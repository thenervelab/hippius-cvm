//! The live storage move against the mock libvirt: the happy path to
//! `done`, every abort (mid-copy job failure, pivot failure, guest stop,
//! operator cancel), an agent restart mid-copy, the reboot gate, the
//! pre-checks and the destination budget.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use super::*;
use crate::lifecycle::launch_digest::MockLaunchDigest;
use crate::lifecycle::libvirt_driver::MockLibvirtDriver;
use crate::lifecycle::{DomainState, HostResources, LibvirtDriver};
use crate::orders::LaunchOrder;

struct GoodFs;

impl crate::storage::pools::PoolFs for GoodFs {
    fn canonical(&self, path: &Path) -> Option<PathBuf> {
        Some(path.to_path_buf())
    }
    fn stat(&self, path: &Path) -> Option<crate::storage::pools::DirStat> {
        use std::hash::{Hash, Hasher};
        let mut h = std::collections::hash_map::DefaultHasher::new();
        path.hash(&mut h);
        Some(crate::storage::pools::DirStat {
            dev: h.finish() | 2,
            uid: 0,
            mode: 0o040755,
            is_dir: true,
        })
    }
    fn mount_of(&self, path: &Path) -> Option<(PathBuf, String)> {
        Some((path.to_path_buf(), "xfs".into()))
    }
    fn odirect_ok(&self, _path: &Path) -> bool {
        true
    }
    fn total_bytes(&self, _path: &Path) -> Option<u64> {
        Some(10_000 * (1 << 30))
    }
}

/// A host: `default` at `<dir>/data`, `nvme0` at `<dir>/pools/nvme0`
/// (budget `nvme0_gb`), state at `<dir>/state`.
struct Host {
    dir: tempfile::TempDir,
    driver: Arc<MockLibvirtDriver>,
}

impl Host {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        for sub in ["data", "state", "pools/nvme0"] {
            std::fs::create_dir_all(dir.path().join(sub)).unwrap();
        }
        crate::snp_config::install_for_tests(crate::snp_config::SnpCpuConfig {
            cbitpos: 51,
            reduced_phys_bits: 1,
        });
        Self {
            dir,
            driver: Arc::new(MockLibvirtDriver::new()),
        }
    }

    fn data(&self) -> PathBuf {
        self.dir.path().join("data")
    }

    fn nvme0(&self) -> PathBuf {
        self.dir.path().join("pools/nvme0")
    }

    fn state(&self) -> PathBuf {
        self.dir.path().join("state")
    }

    /// A lifecycle over this host (a fresh one = an agent restart).
    fn lifecycle(&self, nvme0_gb: u64) -> Arc<CvmLifecycle> {
        use crate::config::{
            PoolClassConfig, StorageDesiredStateConfig, StoragePoolConfig, StorageSection,
        };
        let mountinfo = self.dir.path().join("mountinfo");
        std::fs::write(
            &mountinfo,
            format!("36 1 8:17 / {} rw - xfs nvme rw\n", self.nvme0().display()),
        )
        .unwrap();
        let src = crate::storage::registry::FsIdentitySource {
            mountinfo,
            udev_data: self.dir.path().join("no-udev"),
            sys_class_block: self.dir.path().join("no-class-block"),
            by_uuid: self.dir.path().join("no-by-uuid"),
        };
        let pool = |id: &str, path: PathBuf, budget_gb: u64| StoragePoolConfig {
            id: id.into(),
            path,
            class: PoolClassConfig::Nvme,
            budget_gb,
            os_disks: true,
            state: StorageDesiredStateConfig::Active,
        };
        let pools = Arc::new(crate::storage::StoragePools::from_config(
            &StorageSection {
                data_disk_root: self.data(),
                state_disk_root: self.state(),
                pools: vec![
                    pool("default", self.data(), 0),
                    pool("nvme0", self.nvme0(), nvme0_gb),
                ],
                dedicated_disks: Vec::new(),
            },
            0,
        ));
        let bindings = crate::storage::registry::enforce_with(&self.state(), &pools, &src).unwrap();
        let state = Arc::new(crate::storage::state::StorageState::new(
            crate::storage::state::EffectiveStorage {
                pools,
                dedicated: Vec::new(),
                revision: 0,
                bindings,
            },
        ));
        let driver: Arc<dyn LibvirtDriver> = self.driver.clone();
        Arc::new(
            CvmLifecycle::new_with_poll(
                driver,
                Arc::new(MockLaunchDigest::fixed([0u8; 48])),
                HostResources {
                    total_cpus: 16,
                    total_memory_mb: 65536,
                    total_disk_gb: 0,
                },
                Duration::from_millis(1),
                5,
            )
            .skip_state_disk_provision_for_tests()
            .with_storage_roots(self.data(), self.state())
            .with_storage_state(state)
            .with_pool_host(Arc::new(crate::storage::PoolHost {
                pool_fs: Box::new(GoodFs),
                fs_identity: src,
            }))
            .with_move_poll(Duration::from_millis(5)),
        )
    }

    /// A running golden VM on `default`, its overlay `len` bytes.
    async fn running_vm(&self, lc: &CvmLifecycle, vm: &str, len: u64) -> VmId {
        let vm_id = VmId::new(vm).unwrap();
        lc.launch(golden_order(&vm_id)).await.unwrap();
        let overlay = golden::overlay_disk_path(&self.data(), &vm_id);
        std::fs::create_dir_all(overlay.parent().unwrap()).unwrap();
        std::fs::File::create(&overlay)
            .unwrap()
            .set_len(len)
            .unwrap();
        vm_id
    }
}

fn medium_ticket() -> Vec<u8> {
    use ciborium::value::Value;
    use coset::{iana, CborSerializable, CoseSign1Builder, HeaderBuilder};
    let payload = Value::Map(vec![
        (Value::Text("v".into()), Value::Integer(2.into())),
        (Value::Text("flavor".into()), Value::Text("medium".into())),
    ]);
    let mut payload_buf = Vec::new();
    ciborium::ser::into_writer(&payload, &mut payload_buf).unwrap();
    CoseSign1Builder::new()
        .protected(
            HeaderBuilder::new()
                .algorithm(iana::Algorithm::EdDSA)
                .build(),
        )
        .payload(payload_buf)
        .create_signature(b"", |_| vec![0u8; 64])
        .build()
        .to_vec()
        .unwrap()
}

fn golden_order(vm_id: &VmId) -> LaunchOrder {
    LaunchOrder {
        vm_id: vm_id.clone(),
        ovmf_path: "/var/lib/hippius-miner/ovmf.fd".into(),
        kernel_path: "/var/lib/hippius-miner/vmlinuz".into(),
        initrd_path: "/var/lib/hippius-miner/initrd".into(),
        cmdline: format!("ro dm-verity.root={} hippius.disk_gb=10", "0".repeat(64)),
        luks_disk_path: "/var/lib/hippius-miner/ignored.img".into(),
        luks_disk_size_gb: 10,
        data_disk_size_gb: 10,
        rootfs_data_path: "/var/lib/hippius-miner/rootfs.img".into(),
        rootfs_hash_path: "/var/lib/hippius-miner/rootfs.verity".into(),
        cpu_count: 2,
        memory_mb: 2048,
        cose_ticket: serde_bytes::ByteBuf::from(medium_ticket()),
        require_existing_disks: false,
        guardian_ep: None,
        net: None,
        on_guest_poweroff: None,
        os_pool: None,
        extra_disks: Vec::new(),
    }
}

const MOVE_ID: &str = "0123456789abcdef0123456789abcdef";

fn order(vm_id: &VmId, action: MoveAction) -> MoveVmStorageOrder {
    let start = action == MoveAction::Start;
    MoveVmStorageOrder {
        vm_id: vm_id.clone(),
        move_id: MOVE_ID.into(),
        action,
        target_pool: start.then(|| "nvme0".into()),
        expected_source_pool: start.then(|| "default".into()),
        bandwidth_mib_s: start.then_some(200),
        not_after_unix: now_unix() + 3600,
    }
}

fn domain(vm_id: &VmId) -> DomainId {
    domain_of(vm_id).unwrap()
}

/// Wait (up to 5 s) for the move to reach `phase`.
async fn wait_for(lc: &CvmLifecycle, vm_id: &VmId, phase: MovePhase) -> MoveStatus {
    for _ in 0..1000 {
        let status = lc.move_status(vm_id, MOVE_ID).await.unwrap();
        if status.phase == phase {
            return status;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    panic!(
        "never reached {phase:?}: {:?}",
        lc.move_status(vm_id, MOVE_ID).await
    );
}

fn code(err: MinerAgentError) -> &'static str {
    match err {
        MinerAgentError::StorageMove(code) => code,
        other => panic!("not a move refusal: {other:?}"),
    }
}

#[tokio::test]
async fn a_move_copies_pivots_redefines_and_releases_the_source() {
    let host = Host::new();
    let lc = host.lifecycle(100);
    let vm = host.running_vm(&lc, "move-me", 4 << 20).await;
    let src = golden::overlay_disk_path(&host.data(), &vm);
    let dst = golden::overlay_disk_path(&host.nvme0(), &vm);

    let status = lc
        .storage_move(&order(&vm, MoveAction::Start))
        .await
        .unwrap();
    assert_eq!(status.phase, MovePhase::Copying);
    assert_eq!(
        std::fs::metadata(&dst).unwrap().len(),
        4 << 20,
        "dst pre-created"
    );
    // A launch of it now waits for the move.
    assert_eq!(
        code(lc.check_no_move(&vm).unwrap_err()),
        "vm-storage-move-in-progress"
    );
    // Idempotent on move_id.
    assert_eq!(
        lc.storage_move(&order(&vm, MoveAction::Start))
            .await
            .unwrap()
            .phase,
        MovePhase::Copying
    );

    host.driver.set_block_job(&domain(&vm), 1, 1, true);
    let status = wait_for(&lc, &vm, MovePhase::Redefined).await;
    assert_eq!(status.bytes_done, status.bytes_total);
    // Live, persistent, handle, pool record: all on dst.
    let live = host.driver.domain_xml(&domain(&vm)).await.unwrap();
    assert_eq!(adopt::writable_disk_path(&live), Some(dst.clone()));
    let inactive = host.driver.domain_xml_inactive(&domain(&vm)).await.unwrap();
    assert_eq!(adopt::writable_disk_path(&inactive), Some(dst.clone()));
    assert_eq!(lc.luks_disk_path_for(&vm), Some(dst.clone()));
    let record = vm_pool::read(&host.state(), &vm).unwrap().unwrap();
    assert_eq!(
        (record.pool_id.as_str(), record.root),
        ("nvme0", host.nvme0())
    );
    lc.check_no_move(&vm).unwrap();
    // The source is kept until released.
    assert!(src.exists());
    assert_eq!(
        code(
            lc.storage_move(&order(&vm, MoveAction::Cancel))
                .await
                .unwrap_err()
        ),
        "move-past-pivot"
    );
    let status = lc
        .storage_move(&order(&vm, MoveAction::Release))
        .await
        .unwrap();
    assert_eq!(status.phase, MovePhase::Done);
    assert!(!src.exists());
    assert!(dst.exists());
}

#[tokio::test]
async fn a_release_never_deletes_a_source_the_vm_is_back_on() {
    let host = Host::new();
    let lc = host.lifecycle(100);
    let vm = host.running_vm(&lc, "move-back", 4 << 20).await;
    let src = golden::overlay_disk_path(&host.data(), &vm);
    let dst = golden::overlay_disk_path(&host.nvme0(), &vm);
    lc.storage_move(&order(&vm, MoveAction::Start))
        .await
        .unwrap();
    assert!(lc.is_journaled_move(&vm, &order(&vm, MoveAction::Start).move_id));
    assert!(!lc.is_journaled_move(&vm, &"cd".repeat(16)));
    host.driver.set_block_job(&domain(&vm), 1, 1, true);
    wait_for(&lc, &vm, MovePhase::Redefined).await;

    // The VM's definition names the source path again (it left the host
    // and came back onto the same pool meanwhile).
    let inactive = host.driver.domain_xml_inactive(&domain(&vm)).await.unwrap();
    let back = super::super::libvirt_driver::replace_vda_source(&inactive, &src).unwrap();
    host.driver.define_domain(&back).await.unwrap();
    let err = lc
        .storage_move(&order(&vm, MoveAction::Release))
        .await
        .unwrap_err();
    assert_eq!(code(err), "move-release-in-use");
    assert!(src.exists(), "the disk in use is kept");

    host.driver.define_domain(&inactive).await.unwrap();
    // The agent's handle naming it is enough too.
    lc.lock_handles()
        .unwrap()
        .get_mut(&vm)
        .unwrap()
        .luks_disk_path = src.clone();
    let err = lc
        .storage_move(&order(&vm, MoveAction::Release))
        .await
        .unwrap_err();
    assert_eq!(code(err), "move-release-in-use");
    lc.lock_handles()
        .unwrap()
        .get_mut(&vm)
        .unwrap()
        .luks_disk_path = dst.clone();

    let status = lc
        .storage_move(&order(&vm, MoveAction::Release))
        .await
        .unwrap();
    assert_eq!(status.phase, MovePhase::Done);
    assert!(!src.exists());
}

#[tokio::test]
async fn a_start_past_its_validity_never_begins_a_copy() {
    let host = Host::new();
    let lc = host.lifecycle(100);
    let vm = host.running_vm(&lc, "expired-start", 4 << 20).await;
    let mut late = order(&vm, MoveAction::Start);
    late.not_after_unix = now_unix() - 1;
    assert_eq!(
        code(lc.storage_move(&late).await.unwrap_err()),
        "move-order-expired"
    );
    assert!(read_journal(&host.state(), &vm).unwrap().is_none());
    assert!(!golden::overlay_disk_path(&host.nvme0(), &vm).exists());
}

#[tokio::test]
async fn a_copy_that_fails_mid_way_is_aborted_and_the_vm_stays_on_its_source() {
    let host = Host::new();
    let lc = host.lifecycle(100);
    let vm = host.running_vm(&lc, "move-fails", 4 << 20).await;
    let src = golden::overlay_disk_path(&host.data(), &vm);
    let dst = golden::overlay_disk_path(&host.nvme0(), &vm);
    lc.storage_move(&order(&vm, MoveAction::Start))
        .await
        .unwrap();
    host.driver.set_block_job(&domain(&vm), 1, 2, false);
    // The job dies half way (libvirtd restart, an I/O error).
    host.driver.kill_block_job(&domain(&vm));

    let status = wait_for(&lc, &vm, MovePhase::Aborted).await;
    assert_eq!(status.code.as_deref(), Some("move-job-failed"));
    assert!(!dst.exists(), "the copy is deleted");
    assert!(src.exists());
    let live = host.driver.domain_xml(&domain(&vm)).await.unwrap();
    assert_eq!(adopt::writable_disk_path(&live), Some(src.clone()));
    let inactive = host.driver.domain_xml_inactive(&domain(&vm)).await.unwrap();
    assert_eq!(adopt::writable_disk_path(&inactive), Some(src.clone()));
    assert_eq!(lc.luks_disk_path_for(&vm), Some(src));
    lc.check_no_move(&vm).unwrap();
}

#[tokio::test]
async fn a_failed_pivot_aborts_and_deletes_the_copy() {
    let host = Host::new();
    let lc = host.lifecycle(100);
    let vm = host.running_vm(&lc, "pivot-fails", 4 << 20).await;
    let dst = golden::overlay_disk_path(&host.nvme0(), &vm);
    lc.storage_move(&order(&vm, MoveAction::Start))
        .await
        .unwrap();
    host.driver.fail_next_pivot();
    host.driver.set_block_job(&domain(&vm), 1, 1, true);
    let status = wait_for(&lc, &vm, MovePhase::Aborted).await;
    assert_eq!(status.code.as_deref(), Some("move-pivot-failed"));
    assert!(!dst.exists());
    assert!(!host.driver.has_block_job(&domain(&vm)));
}

#[tokio::test]
async fn a_pivot_that_cannot_back_out_stays_pivoting_and_holds_on_a_stop() {
    let host = Host::new();
    let lc = Arc::new(
        Arc::try_unwrap(host.lifecycle(100))
            .ok()
            .unwrap()
            .with_move_poll(Duration::from_secs(3600)),
    );
    let vm = host.running_vm(&lc, "pivot-stuck", 4 << 20).await;
    let dst = golden::overlay_disk_path(&host.nvme0(), &vm);
    lc.storage_move(&order(&vm, MoveAction::Start))
        .await
        .unwrap();
    host.driver.set_block_job(&domain(&vm), 1, 1, true);
    // The pivot is refused and so is the abort (libvirt still pivoting).
    host.driver.fail_next_pivot();
    host.driver.fail_next_abort();
    let mut journal = read_journal(&host.state(), &vm).unwrap().unwrap();
    let _ = lc.step(&mut journal).await;
    let journal = read_journal(&host.state(), &vm).unwrap().unwrap();
    assert_eq!(journal.phase, MovePhase::Pivoting, "never back to copying");
    // The guest stops now: it is held, the copy is kept.
    host.driver
        .destroy_domain(&domain(&vm), false)
        .await
        .unwrap();
    assert_eq!(
        code(lc.settle_move_before_restart(&vm).await.unwrap_err()),
        "move-pivot-unknown"
    );
    assert!(dst.exists(), "a copy that may hold the last writes is kept");
}

#[tokio::test]
async fn a_destroy_holds_every_move_step_until_it_is_over() {
    let host = Host::new();
    let lc = host.lifecycle(100);
    let vm = host.running_vm(&lc, "destroy-holds", 4 << 20).await;
    // Without a move journal, a destroy takes no move lock.
    let other = host.running_vm(&lc, "destroy-free", 4 << 20).await;
    let guard = lc.moves.ops.lock().await;
    tokio::time::timeout(Duration::from_secs(5), lc.destroy(&other, None))
        .await
        .expect("not held by the move lock")
        .unwrap();
    write_journal(&host.state(), &journal_at(&host, &vm, MovePhase::Done)).unwrap();
    let destroy = {
        let lc = Arc::clone(&lc);
        let vm = vm.clone();
        tokio::spawn(async move { lc.destroy(&vm, None).await })
    };
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(
        !destroy.is_finished(),
        "the destroy waits for the move lock"
    );
    drop(guard);
    destroy.await.unwrap().unwrap();
}

/// A move redefined, then the VM back on its source path: `(lc, vm, src,
/// dst)` with the VM stopped (no domain, no handle) and its pool record
/// naming the source root again.
async fn moved_then_back_on_src(host: &Host, name: &str) -> (Arc<CvmLifecycle>, VmId, PathBuf) {
    let lc = host.lifecycle(100);
    let vm = host.running_vm(&lc, name, 4 << 20).await;
    let src = golden::overlay_disk_path(&host.data(), &vm);
    lc.storage_move(&order(&vm, MoveAction::Start))
        .await
        .unwrap();
    host.driver.set_block_job(&domain(&vm), 1, 1, true);
    wait_for(&lc, &vm, MovePhase::Redefined).await;
    lc.stop(&vm, false).await.unwrap();
    (lc, vm, src)
}

#[tokio::test]
async fn a_release_never_deletes_the_disk_the_pool_record_names() {
    let host = Host::new();
    let (lc, vm, src) = moved_then_back_on_src(&host, "back-on-src").await;
    // A §25 arrival or restore put it back on `default` (the record names
    // the source root) without touching the journal; it is stopped.
    vm_pool::write(
        &host.state(),
        &vm,
        &vm_pool::VmPoolRecord {
            pool_id: "default".into(),
            root: host.data(),
            ran: true,
        },
    )
    .unwrap();
    assert!(lc.lock_handles().unwrap().get(&vm).is_none());
    let err = lc
        .storage_move(&order(&vm, MoveAction::Release))
        .await
        .unwrap_err();
    assert_eq!(code(err), "move-release-in-use");
    assert!(src.exists(), "the VM's only disk is kept");
    // An unreadable record is no better: refused.
    std::fs::write(vm_pool_path(&host, &vm), b"{not json").unwrap();
    let err = lc
        .storage_move(&order(&vm, MoveAction::Release))
        .await
        .unwrap_err();
    assert_eq!(code(err), "move-pool-record-unreadable");
    assert!(src.exists());
}

#[tokio::test]
async fn a_release_refuses_when_the_running_definition_has_no_readable_vda() {
    let host = Host::new();
    let lc = host.lifecycle(100);
    let vm = host.running_vm(&lc, "no-vda", 4 << 20).await;
    let src = golden::overlay_disk_path(&host.data(), &vm);
    lc.storage_move(&order(&vm, MoveAction::Start))
        .await
        .unwrap();
    host.driver.set_block_job(&domain(&vm), 1, 1, true);
    wait_for(&lc, &vm, MovePhase::Redefined).await;
    // The VM runs, but its live definition names no vda libvirt can read.
    host.driver
        .set_live_xml(&domain(&vm), "<domain><devices></devices></domain>");
    let err = lc
        .storage_move(&order(&vm, MoveAction::Release))
        .await
        .unwrap_err();
    assert_eq!(code(err), "move-libvirt-unknown");
    assert!(src.exists(), "unknown is never 'not in use'");
}

#[tokio::test]
async fn a_launch_onto_a_source_waits_for_the_move_lock() {
    let host = Host::new();
    let lc = host.lifecycle(100);
    let vm = VmId::new("lock-arrival").unwrap();
    write_journal(&host.state(), &journal_at(&host, &vm, MovePhase::Redefined)).unwrap();
    let guard = lc.moves.ops.lock().await;
    let close = {
        let lc = Arc::clone(&lc);
        let vm = vm.clone();
        let root = host.data();
        tokio::spawn(async move { lc.close_superseded_move(&vm, &root).await })
    };
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(
        !close.is_finished(),
        "serialized with release under the move lock"
    );
    drop(guard);
    close.await.unwrap().unwrap();
    assert_eq!(
        read_journal(&host.state(), &vm)
            .unwrap()
            .unwrap()
            .code
            .as_deref(),
        Some("move-superseded")
    );
}

#[tokio::test]
async fn a_relaunch_onto_the_source_closes_the_move() {
    let host = Host::new();
    let (lc, vm, src) = moved_then_back_on_src(&host, "relaunch-src").await;
    vm_pool::write(
        &host.state(),
        &vm,
        &vm_pool::VmPoolRecord {
            pool_id: "default".into(),
            root: host.data(),
            ran: true,
        },
    )
    .unwrap();
    let state_disk = lc.state_disk_path(&vm);
    std::fs::create_dir_all(state_disk.parent().unwrap()).unwrap();
    std::fs::write(&state_disk, b"").unwrap();
    lc.launch(golden_order(&vm)).await.unwrap();
    let journal = read_journal(&host.state(), &vm).unwrap().unwrap();
    assert_eq!(
        (journal.phase, journal.code.as_deref()),
        (MovePhase::Done, Some("move-superseded"))
    );
    lc.stop(&vm, false).await.unwrap();
    // A late release finds the move over: nothing deleted.
    let status = lc
        .storage_move(&order(&vm, MoveAction::Release))
        .await
        .unwrap();
    assert_eq!(status.phase, MovePhase::Done);
    assert!(src.exists());
}

#[tokio::test]
async fn an_arrival_onto_the_source_closes_the_move_and_waits_for_a_copy() {
    let host = Host::new();
    let (lc, vm, src) = moved_then_back_on_src(&host, "arrive-src").await;
    vm_pool::remove(&host.state(), &vm).unwrap();
    let root = lc.place_arriving(&vm, None, 10, false).unwrap();
    assert_eq!(root, host.data());
    lc.close_superseded_move(&vm, &root).await.unwrap();
    let journal = read_journal(&host.state(), &vm).unwrap().unwrap();
    assert_eq!(journal.code.as_deref(), Some("move-superseded"));
    lc.storage_move(&order(&vm, MoveAction::Release))
        .await
        .unwrap();
    assert!(src.exists());
    // Onto anything else, a redefined move is left alone.
    let other = VmId::new("arrive-other").unwrap();
    write_journal(
        &host.state(),
        &journal_at(&host, &other, MovePhase::Redefined),
    )
    .unwrap();
    lc.close_superseded_move(&other, &host.nvme0())
        .await
        .unwrap();
    assert_eq!(
        read_journal(&host.state(), &other).unwrap().unwrap().phase,
        MovePhase::Redefined
    );
    // A copy in flight refuses any arrival.
    write_journal(
        &host.state(),
        &journal_at(&host, &other, MovePhase::Copying),
    )
    .unwrap();
    assert_eq!(
        code(lc.place_arriving(&other, None, 10, false).unwrap_err()),
        "vm-storage-move-in-progress"
    );
}

#[tokio::test]
async fn an_abort_never_deletes_a_copy_a_definition_names() {
    let host = Host::new();
    let lc = Arc::new(
        Arc::try_unwrap(host.lifecycle(100))
            .ok()
            .unwrap()
            .with_move_poll(Duration::from_secs(3600)),
    );
    let vm = host.running_vm(&lc, "abort-named", 4 << 20).await;
    let dst = golden::overlay_disk_path(&host.nvme0(), &vm);
    lc.storage_move(&order(&vm, MoveAction::Start))
        .await
        .unwrap();
    // The persistent definition names dst (whatever got it there), then
    // the guest stops while the journal still says `copying`.
    let inactive = host.driver.domain_xml_inactive(&domain(&vm)).await.unwrap();
    let on_dst = crate::lifecycle::libvirt_driver::replace_vda_source(&inactive, &dst).unwrap();
    host.driver.define_domain(&on_dst).await.unwrap();
    host.driver
        .destroy_domain(&domain(&vm), false)
        .await
        .unwrap();
    // libvirt pivoted after all: the move goes on, the VM restarts on dst.
    lc.settle_move_before_restart(&vm).await.unwrap();
    let journal = read_journal(&host.state(), &vm).unwrap().unwrap();
    assert_eq!(journal.phase, MovePhase::Redefined);
    assert!(dst.exists());
}

#[tokio::test]
async fn an_abort_holds_a_copy_only_the_agent_records_name() {
    let host = Host::new();
    let lc = Arc::new(
        Arc::try_unwrap(host.lifecycle(100))
            .ok()
            .unwrap()
            .with_move_poll(Duration::from_secs(3600)),
    );
    let vm = host.running_vm(&lc, "abort-record", 4 << 20).await;
    let dst = golden::overlay_disk_path(&host.nvme0(), &vm);
    lc.storage_move(&order(&vm, MoveAction::Start))
        .await
        .unwrap();
    // The pool record names the destination, no definition does.
    vm_pool::write(
        &host.state(),
        &vm,
        &vm_pool::VmPoolRecord {
            pool_id: "nvme0".into(),
            root: host.nvme0(),
            ran: true,
        },
    )
    .unwrap();
    host.driver
        .destroy_domain(&domain(&vm), false)
        .await
        .unwrap();
    assert_eq!(
        code(lc.settle_move_before_restart(&vm).await.unwrap_err()),
        "move-pivot-unknown"
    );
    assert!(read_journal(&host.state(), &vm)
        .unwrap()
        .unwrap()
        .pivot_unknown());
    assert!(dst.exists(), "held, both copies kept");
}

#[tokio::test]
async fn a_pivot_that_times_out_is_read_off_libvirt_never_backed_out() {
    // Landed, the guest running: the move completes.
    let host = Host::new();
    let lc = host.lifecycle(100);
    let vm = host.running_vm(&lc, "pivot-timeout", 4 << 20).await;
    let dst = golden::overlay_disk_path(&host.nvme0(), &vm);
    host.driver.pivot_lands_then_times_out();
    lc.storage_move(&order(&vm, MoveAction::Start))
        .await
        .unwrap();
    host.driver.set_block_job(&domain(&vm), 1, 1, true);
    wait_for(&lc, &vm, MovePhase::Redefined).await;
    assert!(dst.exists());

    // Landed, then the guest stopped before the next look: held, both
    // copies kept.
    let host = Host::new();
    let lc = Arc::new(
        Arc::try_unwrap(host.lifecycle(100))
            .ok()
            .unwrap()
            .with_move_poll(Duration::from_secs(3600)),
    );
    let vm = host.running_vm(&lc, "pivot-timeout-stop", 4 << 20).await;
    let dst = golden::overlay_disk_path(&host.nvme0(), &vm);
    lc.storage_move(&order(&vm, MoveAction::Start))
        .await
        .unwrap();
    host.driver.set_block_job(&domain(&vm), 1, 1, true);
    host.driver.pivot_lands_then_times_out();
    let mut journal = read_journal(&host.state(), &vm).unwrap().unwrap();
    assert!(lc.step(&mut journal).await.is_err());
    assert_eq!(
        read_journal(&host.state(), &vm).unwrap().unwrap().phase,
        MovePhase::Pivoting
    );
    host.driver
        .destroy_domain(&domain(&vm), false)
        .await
        .unwrap();
    assert_eq!(
        code(lc.settle_move_before_restart(&vm).await.unwrap_err()),
        "move-pivot-unknown"
    );
    assert!(
        dst.exists(),
        "the copy that may hold the last writes survives"
    );
}

#[tokio::test]
async fn a_start_that_timed_out_aborts_its_late_job_before_the_copy_goes() {
    let host = Host::new();
    let lc = host.lifecycle(100);
    let vm = host.running_vm(&lc, "late-job", 4 << 20).await;
    let dst = golden::overlay_disk_path(&host.nvme0(), &vm);
    host.driver.blockcopy_times_out_job_appears_after(1);
    let err = lc
        .storage_move(&order(&vm, MoveAction::Start))
        .await
        .unwrap_err();
    assert_eq!(code(err), "move-job-failed");
    let status = wait_for(&lc, &vm, MovePhase::Aborted).await;
    assert_eq!(status.code.as_deref(), Some("move-aborted-agent-restart"));
    assert!(!host.driver.late_job_pending(), "looked for the late job");
    assert!(
        !host.driver.has_block_job(&domain(&vm)),
        "the late job is aborted"
    );
    assert!(!dst.exists());
}

#[tokio::test]
async fn a_destroy_goes_through_an_unreadable_journal_and_drops_a_leftover_one() {
    let host = Host::new();
    let lc = host.lifecycle(100);
    let vm = host.running_vm(&lc, "corrupt-journal", 4 << 20).await;
    std::fs::create_dir_all(moves_dir(&host.state())).unwrap();
    std::fs::write(journal_path(&host.state(), &vm), b"{garbage").unwrap();
    lc.destroy(&vm, None).await.unwrap();
    assert!(
        !journal_path(&host.state(), &vm).exists(),
        "dropped with the VM"
    );
    // Nothing left to reclaim: a retried destroy still drops a journal.
    let gone = VmId::new("never-here").unwrap();
    write_journal(
        &host.state(),
        &journal_at(&host, &gone, MovePhase::Pivoting),
    )
    .unwrap();
    lc.destroy(&gone, None).await.unwrap();
    assert!(read_journal(&host.state(), &gone).unwrap().is_none());
}

#[test]
fn both_copies_count_between_the_pivot_and_the_redefine() {
    let host = Host::new();
    let vm = VmId::new("held").unwrap();
    for phase in [MovePhase::Pivoting, MovePhase::Pivoted] {
        let roots: Vec<PathBuf> = held_gb(&journal_at(&host, &vm, phase))
            .into_iter()
            .map(|(r, _)| r)
            .collect();
        assert_eq!(roots, vec![host.nvme0(), host.data()], "{phase:?}");
    }
    let mut unknown = journal_at(&host, &vm, MovePhase::Failed);
    unknown.code = Some("move-pivot-unknown".into());
    assert_eq!(held_gb(&unknown).len(), 2);
}

#[tokio::test]
async fn a_departure_releases_a_redefined_source_and_waits_for_a_copy() {
    let host = Host::new();
    let lc = host.lifecycle(100);
    let vm = VmId::new("leaving").unwrap();
    let journal = journal_at(&host, &vm, MovePhase::Copying);
    write_journal(&host.state(), &journal).unwrap();
    assert_eq!(
        code(lc.release_before_departure(&vm).await.unwrap_err()),
        "vm-storage-move-in-progress"
    );
    std::fs::create_dir_all(journal.src.parent().unwrap()).unwrap();
    std::fs::write(&journal.src, b"stale").unwrap();
    write_journal(&host.state(), &journal_at(&host, &vm, MovePhase::Redefined)).unwrap();
    lc.release_before_departure(&vm).await.unwrap();
    assert!(!journal.src.exists(), "the stale source is released");
    let after = read_journal(&host.state(), &vm).unwrap().unwrap();
    assert_eq!(after.phase, MovePhase::Done);
    // No move at all: nothing to do.
    lc.release_before_departure(&VmId::new("no-move").unwrap())
        .await
        .unwrap();
}

#[tokio::test]
async fn an_abort_that_finds_the_guest_stopped_mid_pivot_holds_it() {
    let host = Host::new();
    let lc = host.lifecycle(100);
    let vm = host.running_vm(&lc, "abort-mid-pivot", 4 << 20).await;
    let mut journal = journal_at(&host, &vm, MovePhase::Pivoting);
    std::fs::create_dir_all(journal.dst.parent().unwrap()).unwrap();
    std::fs::write(&journal.dst, b"maybe the last writes").unwrap();
    write_journal(&host.state(), &journal).unwrap();
    host.driver
        .destroy_domain(&domain(&vm), false)
        .await
        .unwrap();
    lc.abort_move(&mut journal, "move-pivot-failed")
        .await
        .unwrap();
    assert!(journal.pivot_unknown(), "{journal:?}");
    assert!(journal.dst.exists(), "never deleted on a guess");
}

#[tokio::test]
async fn an_agent_restart_mid_copy_resumes_the_move() {
    let host = Host::new();
    // The first agent never polls again (it "died").
    let first = Arc::new(
        Arc::try_unwrap(host.lifecycle(100))
            .ok()
            .unwrap()
            .with_move_poll(Duration::from_secs(3600)),
    );
    let vm = host.running_vm(&first, "move-restart", 4 << 20).await;
    let dst = golden::overlay_disk_path(&host.nvme0(), &vm);
    first
        .storage_move(&order(&vm, MoveAction::Start))
        .await
        .unwrap();

    // A new agent: re-adopts the running VM, resumes the move.
    let second = host.lifecycle(100);
    assert_eq!(second.readopt_running().await.unwrap(), 1);
    assert_eq!(second.resume_moves().await.unwrap(), 1);
    assert_eq!(
        second.move_status(&vm, MOVE_ID).await.unwrap().phase,
        MovePhase::Copying
    );
    host.driver.set_block_job(&domain(&vm), 1, 1, true);
    wait_for(&second, &vm, MovePhase::Redefined).await;
    assert_eq!(second.luks_disk_path_for(&vm), Some(dst));
}

#[tokio::test]
async fn an_agent_restart_after_libvirt_lost_the_job_aborts_it() {
    let host = Host::new();
    let first = Arc::new(
        Arc::try_unwrap(host.lifecycle(100))
            .ok()
            .unwrap()
            .with_move_poll(Duration::from_secs(3600)),
    );
    let vm = host.running_vm(&first, "move-lost", 4 << 20).await;
    let dst = golden::overlay_disk_path(&host.nvme0(), &vm);
    first
        .storage_move(&order(&vm, MoveAction::Start))
        .await
        .unwrap();
    host.driver.kill_block_job(&domain(&vm));

    let second = host.lifecycle(100);
    second.readopt_running().await.unwrap();
    second.resume_moves().await.unwrap();
    let status = wait_for(&second, &vm, MovePhase::Aborted).await;
    assert_eq!(status.code.as_deref(), Some("move-job-failed"));
    assert!(!dst.exists());
}

#[tokio::test]
async fn a_guest_stop_mid_copy_restarts_it_on_its_source() {
    let host = Host::new();
    let lc = Arc::new(
        Arc::try_unwrap(host.lifecycle(100))
            .ok()
            .unwrap()
            .with_move_poll(Duration::from_secs(3600)),
    );
    let vm = host.running_vm(&lc, "move-stop", 4 << 20).await;
    let src = golden::overlay_disk_path(&host.data(), &vm);
    let dst = golden::overlay_disk_path(&host.nvme0(), &vm);
    lc.storage_move(&order(&vm, MoveAction::Start))
        .await
        .unwrap();
    // QEMU exits (guest reboot on SNP): the mirror dies with it.
    host.driver
        .destroy_domain(&domain(&vm), false)
        .await
        .unwrap();
    // The reboot watcher asks before it restarts the domain.
    lc.settle_move_before_restart(&vm).await.unwrap();
    let status = lc.move_status(&vm, MOVE_ID).await.unwrap();
    assert_eq!(
        (status.phase, status.code.as_deref()),
        (MovePhase::Aborted, Some("move-aborted-guest-stop"))
    );
    assert!(!dst.exists());
    let inactive = host.driver.domain_xml_inactive(&domain(&vm)).await.unwrap();
    assert_eq!(adopt::writable_disk_path(&inactive), Some(src));
}

#[tokio::test]
async fn a_restart_after_the_pivot_boots_the_destination_never_the_stale_source() {
    let host = Host::new();
    let lc = host.lifecycle(100);
    let vm = host.running_vm(&lc, "move-pivoted", 4 << 20).await;
    let src = golden::overlay_disk_path(&host.data(), &vm);
    let dst = golden::overlay_disk_path(&host.nvme0(), &vm);
    std::fs::create_dir_all(dst.parent().unwrap()).unwrap();
    std::fs::File::create(&dst)
        .unwrap()
        .set_len(4 << 20)
        .unwrap();
    // Pivoted, the agent died before the redefine; then the guest stopped.
    let journal = MoveJournal {
        move_id: MOVE_ID.into(),
        vm_id: vm.as_str().into(),
        src_pool: "default".into(),
        dst_pool: "nvme0".into(),
        src: src.clone(),
        dst: dst.clone(),
        dst_root: host.nvme0(),
        bytes_total: 4 << 20,
        bandwidth_mib_s: 200,
        phase: MovePhase::Pivoted,
        code: None,
        started_at: 1,
        updated_at: 1,
    };
    write_journal(&host.state(), &journal).unwrap();
    host.driver
        .destroy_domain(&domain(&vm), false)
        .await
        .unwrap();

    lc.settle_move_before_restart(&vm).await.unwrap();
    let inactive = host.driver.domain_xml_inactive(&domain(&vm)).await.unwrap();
    assert_eq!(adopt::writable_disk_path(&inactive), Some(dst));
    assert_eq!(
        lc.move_status(&vm, MOVE_ID).await.unwrap().phase,
        MovePhase::Redefined
    );
    assert!(src.exists(), "kept until released");
}

#[tokio::test]
async fn a_stop_mid_pivot_is_never_restarted_on_a_guess() {
    let host = Host::new();
    let lc = host.lifecycle(100);
    let vm = host.running_vm(&lc, "move-midpivot", 4 << 20).await;
    let src = golden::overlay_disk_path(&host.data(), &vm);
    let dst = golden::overlay_disk_path(&host.nvme0(), &vm);
    std::fs::create_dir_all(dst.parent().unwrap()).unwrap();
    std::fs::File::create(&dst)
        .unwrap()
        .set_len(4 << 20)
        .unwrap();
    let journal = MoveJournal {
        move_id: MOVE_ID.into(),
        vm_id: vm.as_str().into(),
        src_pool: "default".into(),
        dst_pool: "nvme0".into(),
        src: src.clone(),
        dst: dst.clone(),
        dst_root: host.nvme0(),
        bytes_total: 4 << 20,
        bandwidth_mib_s: 200,
        phase: MovePhase::Pivoting,
        code: None,
        started_at: 1,
        updated_at: 1,
    };
    write_journal(&host.state(), &journal).unwrap();
    host.driver
        .destroy_domain(&domain(&vm), false)
        .await
        .unwrap();

    assert_eq!(
        code(lc.settle_move_before_restart(&vm).await.unwrap_err()),
        "move-pivot-unknown"
    );
    assert!(src.exists() && dst.exists(), "both copies kept");
}

#[tokio::test]
async fn an_operator_cancel_mid_copy_aborts() {
    let host = Host::new();
    let lc = host.lifecycle(100);
    let vm = host.running_vm(&lc, "move-cancel", 4 << 20).await;
    let dst = golden::overlay_disk_path(&host.nvme0(), &vm);
    lc.storage_move(&order(&vm, MoveAction::Start))
        .await
        .unwrap();
    let status = lc
        .storage_move(&order(&vm, MoveAction::Cancel))
        .await
        .unwrap();
    assert_eq!(
        (status.phase, status.code.as_deref()),
        (MovePhase::Aborted, Some("move-aborted-operator"))
    );
    assert!(!dst.exists());
    assert!(!host.driver.has_block_job(&domain(&vm)));
}

#[tokio::test]
async fn the_destination_must_hold_the_disk_within_its_budget() {
    let host = Host::new();
    // nvme0's budget: 1 GiB; the disk: 2 GiB (sparse).
    let lc = host.lifecycle(1);
    let vm = host.running_vm(&lc, "move-big", 2 << 30).await;
    assert_eq!(
        code(
            lc.storage_move(&order(&vm, MoveAction::Start))
                .await
                .unwrap_err()
        ),
        "move-pool-insufficient-space"
    );
    assert!(!golden::overlay_disk_path(&host.nvme0(), &vm).exists());
    assert!(read_journal(&host.state(), &vm).unwrap().is_none());
}

#[tokio::test]
async fn pre_checks_refuse_before_anything_is_created() {
    let host = Host::new();
    let lc = host.lifecycle(100);
    let vm = host.running_vm(&lc, "move-checks", 4 << 20).await;
    let with = |f: &dyn Fn(&mut MoveVmStorageOrder)| {
        let mut o = order(&vm, MoveAction::Start);
        f(&mut o);
        o
    };
    for (o, why) in [
        (
            with(&|o| o.target_pool = Some("ghost".into())),
            "move-pool-unknown",
        ),
        (
            with(&|o| o.target_pool = Some("default".into())),
            "move-same-pool",
        ),
        (
            with(&|o| o.expected_source_pool = Some("nvme0".into())),
            "move-source-mismatch",
        ),
        (
            with(&|o| o.vm_id = VmId::new("not-here").unwrap()),
            "move-vm-not-found",
        ),
    ] {
        assert_eq!(code(lc.storage_move(&o).await.unwrap_err()), why);
    }
    assert!(!golden::overlay_disk_path(&host.nvme0(), &vm).exists());
    // One move per host.
    let other = host.running_vm(&lc, "move-other", 4 << 20).await;
    lc.storage_move(&order(&vm, MoveAction::Start))
        .await
        .unwrap();
    let mut second = order(&other, MoveAction::Start);
    second.move_id = "f".repeat(32);
    assert_eq!(
        code(lc.storage_move(&second).await.unwrap_err()),
        "move-busy"
    );
    // A status of another move id: not found.
    let mut status = order(&vm, MoveAction::Status);
    status.move_id = "e".repeat(32);
    assert_eq!(
        code(lc.storage_move(&status).await.unwrap_err()),
        "move-not-found"
    );
}

#[tokio::test]
async fn a_destroy_mid_copy_stops_the_job_and_reclaims_both_copies() {
    let host = Host::new();
    let lc = Arc::new(
        Arc::try_unwrap(host.lifecycle(100))
            .ok()
            .unwrap()
            .with_move_poll(Duration::from_secs(3600)),
    );
    let vm = host.running_vm(&lc, "move-destroyed", 4 << 20).await;
    let src = golden::overlay_disk_path(&host.data(), &vm);
    let dst = golden::overlay_disk_path(&host.nvme0(), &vm);
    lc.storage_move(&order(&vm, MoveAction::Start))
        .await
        .unwrap();
    lc.destroy(&vm, None).await.unwrap();
    assert!(!host.driver.has_block_job(&domain(&vm)));
    assert!(!src.exists() && !dst.exists());
    assert!(read_journal(&host.state(), &vm).unwrap().is_none());
}

#[test]
fn the_dest_disk_xml_names_the_file_and_refuses_markup() {
    let xml = dest_disk_xml(Path::new("/p/overlay/vm.img")).unwrap();
    assert!(xml.contains("<source file='/p/overlay/vm.img'/>"));
    assert!(xml.contains("type='raw' cache='none'"));
    assert!(dest_disk_xml(Path::new("/p/o'v")).is_err());
}

#[test]
fn only_moves_before_the_redefine_block_their_vm() {
    use MovePhase::*;
    for p in [Prepared, Copying, Pivoting, Pivoted] {
        assert!(p.blocks_vm() && p.is_active(), "{p:?}");
    }
    assert!(!Redefined.blocks_vm() && Redefined.is_active());
    for p in [Done, Aborted, Failed] {
        assert!(!p.blocks_vm() && !p.is_active(), "{p:?}");
    }
}

#[tokio::test]
async fn the_mock_reports_no_job_on_a_domain_that_was_never_copied() {
    let host = Host::new();
    let lc = host.lifecycle(100);
    let vm = host.running_vm(&lc, "never-copied", 4 << 20).await;
    assert_eq!(
        host.driver
            .blockjob_info(&domain(&vm), "vda")
            .await
            .unwrap(),
        None
    );
    assert_eq!(
        host.driver.query_domain_state(&domain(&vm)).await.unwrap(),
        DomainState::Running
    );
}

/// A pivot libvirt confirmed is authoritative: a libvirt that then fails
/// to dump the XML never makes the agent read "not on dst" and delete
/// the file the VM runs on.
#[tokio::test]
async fn a_flaky_libvirt_around_the_pivot_never_deletes_the_copy_in_use() {
    let host = Host::new();
    let lc = host.lifecycle(100);
    let vm = host.running_vm(&lc, "move-flaky", 4 << 20).await;
    let dst = golden::overlay_disk_path(&host.nvme0(), &vm);
    lc.storage_move(&order(&vm, MoveAction::Start))
        .await
        .unwrap();
    host.driver.fail_domain_xml(4);
    host.driver.set_block_job(&domain(&vm), 1, 1, true);
    wait_for(&lc, &vm, MovePhase::Redefined).await;
    assert!(dst.exists());

    // A refused pivot while libvirt can't be read: the move waits, then
    // pivots once libvirt answers again.
    let host = Host::new();
    let lc = host.lifecycle(100);
    let vm = host.running_vm(&lc, "move-flaky2", 4 << 20).await;
    let dst = golden::overlay_disk_path(&host.nvme0(), &vm);
    lc.storage_move(&order(&vm, MoveAction::Start))
        .await
        .unwrap();
    host.driver.fail_next_pivot();
    host.driver.fail_domain_xml(6);
    host.driver.set_block_job(&domain(&vm), 1, 1, true);
    wait_for(&lc, &vm, MovePhase::Redefined).await;
    assert!(dst.exists());
}

/// A stop mid-pivot holds the VM: no launch, no new move, until an
/// operator decides (both copies kept).
#[tokio::test]
async fn an_unknown_pivot_holds_the_vm() {
    let host = Host::new();
    let lc = host.lifecycle(100);
    let vm = host.running_vm(&lc, "move-unknown", 4 << 20).await;
    let src = golden::overlay_disk_path(&host.data(), &vm);
    let dst = golden::overlay_disk_path(&host.nvme0(), &vm);
    std::fs::create_dir_all(dst.parent().unwrap()).unwrap();
    std::fs::File::create(&dst)
        .unwrap()
        .set_len(4 << 20)
        .unwrap();
    write_journal(&host.state(), &journal_at(&host, &vm, MovePhase::Pivoting)).unwrap();
    host.driver
        .destroy_domain(&domain(&vm), false)
        .await
        .unwrap();
    assert!(lc.settle_move_before_restart(&vm).await.is_err());
    assert_eq!(
        code(lc.check_no_move(&vm).unwrap_err()),
        "vm-storage-move-in-progress"
    );
    let other = host.running_vm(&lc, "move-after", 4 << 20).await;
    let mut start = order(&other, MoveAction::Start);
    start.move_id = "f".repeat(32);
    assert_eq!(
        code(lc.storage_move(&start).await.unwrap_err()),
        "move-busy"
    );
    assert!(src.exists() && dst.exists());
}

/// Pivoted, then the domain was undefined (a stop): the redefine writes
/// the records only, and the next launch renders vda from them (dst).
#[tokio::test]
async fn a_pivoted_move_of_an_undefined_domain_completes_on_its_records() {
    let host = Host::new();
    let lc = host.lifecycle(100);
    let vm = host.running_vm(&lc, "move-undefined", 4 << 20).await;
    let dst = golden::overlay_disk_path(&host.nvme0(), &vm);
    std::fs::create_dir_all(dst.parent().unwrap()).unwrap();
    std::fs::File::create(&dst)
        .unwrap()
        .set_len(4 << 20)
        .unwrap();
    write_journal(&host.state(), &journal_at(&host, &vm, MovePhase::Pivoted)).unwrap();
    host.driver
        .destroy_domain(&domain(&vm), false)
        .await
        .unwrap();
    host.driver.undefine_domain(&domain(&vm)).await.unwrap();

    lc.settle_move_before_restart(&vm).await.unwrap();
    assert_eq!(
        lc.move_status(&vm, MOVE_ID).await.unwrap().phase,
        MovePhase::Redefined
    );
    let record = vm_pool::read(&host.state(), &vm).unwrap().unwrap();
    assert_eq!(record.root, host.nvme0());
}

#[tokio::test]
async fn a_destroy_keeps_the_journal_until_it_succeeds() {
    let host = Host::new();
    let lc = Arc::new(
        Arc::try_unwrap(host.lifecycle(100))
            .ok()
            .unwrap()
            .with_move_poll(Duration::from_secs(3600)),
    );
    let vm = host.running_vm(&lc, "move-destroy-fails", 4 << 20).await;
    lc.storage_move(&order(&vm, MoveAction::Start))
        .await
        .unwrap();
    lc.abort_move_for_destroy(&vm).await.unwrap();
    assert!(!host.driver.has_block_job(&domain(&vm)));
    assert!(read_journal(&host.state(), &vm).unwrap().is_some());
}

#[tokio::test]
async fn the_second_copy_counts_against_its_pool_while_moving() {
    let host = Host::new();
    let lc = Arc::new(
        Arc::try_unwrap(host.lifecycle(100))
            .ok()
            .unwrap()
            .with_move_poll(Duration::from_secs(3600)),
    );
    let vm = host.running_vm(&lc, "move-held", 3 << 30).await;
    assert_eq!(lc.move_held_gb(&host.nvme0()), 0);
    lc.storage_move(&order(&vm, MoveAction::Start))
        .await
        .unwrap();
    assert_eq!(lc.move_held_gb(&host.nvme0()), 3);
    assert_eq!(lc.move_held_gb(&host.data()), 0);
    // nvme0's budget (100 GiB) now has 97 left.
    let pools = lc.storage_pools();
    let nvme0 = pools.get("nvme0").unwrap();
    lc.check_pool_disk_budget(nvme0, 97).unwrap();
    assert!(lc.check_pool_disk_budget(nvme0, 98).is_err());
}

fn vm_pool_path(host: &Host, vm: &VmId) -> PathBuf {
    vm_pool::record_path(&host.state(), vm)
}

fn journal_at(host: &Host, vm: &VmId, phase: MovePhase) -> MoveJournal {
    MoveJournal {
        move_id: MOVE_ID.into(),
        vm_id: vm.as_str().into(),
        src_pool: "default".into(),
        dst_pool: "nvme0".into(),
        src: golden::overlay_disk_path(&host.data(), vm),
        dst: golden::overlay_disk_path(&host.nvme0(), vm),
        dst_root: host.nvme0(),
        bytes_total: 4 << 20,
        bandwidth_mib_s: 200,
        phase,
        code: None,
        started_at: 1,
        updated_at: 1,
    }
}
