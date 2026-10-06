//! `CvmLifecycle` state-machine tests.
//!
//! The whole machine runs against [`MockLibvirtDriver`] +
//! [`MockLaunchDigest`], so no libvirt and no SEV hardware is needed
//! — every transition, the idempotency rule, resource accounting and
//! the fail-closed ordering are exercised on any host.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use ciborium::value::Value;
use coset::{CborSerializable, CoseSign1Builder, HeaderBuilder};
use hippius_miner_agent::lifecycle::DomainState;
use hippius_miner_agent::lifecycle::{
    CidVerdict, TicketPushState, CID_VERIFY_BASE_BACKOFF, CID_VERIFY_MAX_BACKOFF,
};
use hippius_miner_agent::lifecycle::{
    DomainId, LibvirtDriver, MockLaunchDigest, MockLibvirtDriver,
};
use hippius_miner_agent::snp_config::{install_for_tests, SnpCpuConfig};
use hippius_miner_agent::vsock::CidOwner;
use hippius_miner_agent::vsock::VmProgressSink;
use hippius_miner_agent::{
    CvmLifecycle, CvmPhase, DomainLiveness, HostResources, LaunchOrder, MinerAgentError, Result,
    VmId,
};
use hippius_types::vm_progress::VmProgressMilestone;
use std::sync::Mutex;
use tokio::sync::{Notify, Semaphore};

/// A recording [`VmProgressSink`] — captures the `(vm_id, milestone)` the
/// lifecycle reports, without any Edge transport, so a test can assert the
/// `booting` emit fires on a successful domain start. Mirrors the
/// `SpySink` in the kbs-proxy's `kek-released` emit tests.
struct SpySink {
    seen: Mutex<Vec<(String, VmProgressMilestone)>>,
}

impl SpySink {
    fn new() -> Self {
        Self {
            seen: Mutex::new(Vec::new()),
        }
    }
    fn seen(&self) -> Vec<(String, VmProgressMilestone)> {
        self.seen.lock().unwrap().clone()
    }
}

#[async_trait]
impl VmProgressSink for SpySink {
    async fn report(&self, vm_id: &str, milestone: VmProgressMilestone) {
        self.seen
            .lock()
            .unwrap()
            .push((vm_id.to_string(), milestone));
    }
}

/// Give a detached fire-and-forget emit task a moment to run.
async fn settle() {
    tokio::time::sleep(Duration::from_millis(50)).await;
}

/// Issue #116 — `QemuConfig::validate` now calls `snp_config::global()`
/// which probes the host CPU via `CPUID 0x8000001f`. CI runners (and
/// most dev hosts) aren't AMD EPYC, so validate would `Err(SnpProbe)`
/// and every lifecycle test would assert against the wrong error
/// variant. Pre-seed the process-global cache with the Genoa/Turin
/// shape (`51 / 1`); idempotent — `OnceLock::set` short-circuits on
/// repeat calls.
fn seed_snp_probe() {
    install_for_tests(SnpCpuConfig {
        cbitpos: 51,
        reduced_phys_bits: 1,
    });
}

/// Build a minimal valid CoseSign1 OrderTicket carrying `flavor:
/// "medium"`. `CvmLifecycle::launch` (since #317) PEEKS the COSE
/// payload via `ticket_peek::enforce_flavor_matches_cpu_count` BEFORE
/// any libvirt call, and refuses with `LaunchInput("ticket-peek/cose-
/// decode")` when the buffer is empty. The peek does NOT verify the
/// L1 Ed25519 signature, so the sig bytes are bogus; only the COSE
/// frame + CBOR-map shape matter. `flavor = "medium"` pairs with the
/// default `cpu_count: 2` in `order()` below (Flavor::Medium.vcpus()
/// = 2) — the pair gate refuses on mismatch.
fn ticket_medium() -> Vec<u8> {
    let payload = Value::Map(vec![
        (Value::Text("v".into()), Value::Integer(2.into())),
        (Value::Text("flavor".into()), Value::Text("medium".into())),
    ]);
    let mut payload_buf = Vec::new();
    ciborium::ser::into_writer(&payload, &mut payload_buf).unwrap();
    let protected = HeaderBuilder::new()
        .algorithm(coset::iana::Algorithm::EdDSA)
        .build();
    CoseSign1Builder::new()
        .protected(protected)
        .payload(payload_buf)
        .create_signature(b"", |_| vec![0u8; 64])
        .build()
        .to_vec()
        .unwrap()
}

/// A launch order with valid, traversal-free paths under the miner
/// root. The paths need not exist — the mock driver never reads them.
fn order(vm_id: &str) -> LaunchOrder {
    // Seed the SNP-probe cache before any test that exercises the
    // launch path — `QemuConfig::validate` (called from
    // `CvmLifecycle::launch`) now reads `snp_config::global()`. Tests
    // that bypass `order()` and construct a `LaunchOrder` literal
    // must call `seed_snp_probe()` themselves, but no test in this
    // file does that today.
    seed_snp_probe();
    LaunchOrder {
        vm_id: VmId::new(vm_id).unwrap(),
        ovmf_path: PathBuf::from("/var/lib/hippius-miner/ovmf.fd"),
        kernel_path: PathBuf::from("/var/lib/hippius-miner/vmlinuz"),
        initrd_path: PathBuf::from("/var/lib/hippius-miner/initrd"),
        cmdline: "quiet panic=0".to_string(),
        luks_disk_path: PathBuf::from(format!("/var/lib/hippius-miner/{vm_id}.img")),
        luks_disk_size_gb: 10,
        data_disk_size_gb: 0,
        rootfs_data_path: PathBuf::from("/var/lib/hippius-miner/rootfs.img"),
        rootfs_hash_path: PathBuf::from("/var/lib/hippius-miner/rootfs.verity"),
        cpu_count: 2,
        memory_mb: 2048,
        cose_ticket: serde_bytes::ByteBuf::from(ticket_medium()),
        require_existing_disks: false,
        guardian_ep: None,
    }
}

/// A lifecycle with a generous host budget and a 1 ms poll interval
/// so the timeout paths finish fast.
fn lifecycle(driver: Arc<MockLibvirtDriver>, digest: Arc<MockLaunchDigest>) -> CvmLifecycle {
    seed_snp_probe();
    CvmLifecycle::new_with_poll(
        driver,
        digest,
        HostResources {
            total_cpus: 16,
            total_memory_mb: 65536,
            total_disk_gb: 0,
        },
        Duration::from_millis(1),
        5,
    )
    // Phase 2B — these tests model libvirt + digest behavior and
    // don't exercise state-disk provisioning. Real state-disk
    // coverage lives in `lifecycle::state_disk::tests`.
    .skip_state_disk_provision_for_tests()
}

fn ok_digest() -> Arc<MockLaunchDigest> {
    Arc::new(MockLaunchDigest::fixed([0u8; 48]))
}

/// A lifecycle with an explicit DATA-disk budget — for the preflight
/// fail-fast (`check_disk_budget`).
fn lifecycle_with_disk_budget(total_disk_gb: u64) -> CvmLifecycle {
    seed_snp_probe();
    CvmLifecycle::new(
        Arc::new(MockLibvirtDriver::new()),
        ok_digest(),
        HostResources {
            total_cpus: 16,
            total_memory_mb: 65536,
            total_disk_gb,
        },
    )
    .skip_state_disk_provision_for_tests()
}

#[test]
fn check_disk_budget_fail_fasts_over_the_declared_budget() {
    // The preflight fail-fast that lets vali re-place BEFORE the
    // launch-time KBS register (a dispatch-time rejection lands after
    // register and can't be cleanly re-placed).
    let lc = lifecycle_with_disk_budget(64);
    // 128 GiB against a 64 GiB budget → rejected at preflight.
    assert!(matches!(
        lc.check_disk_budget(128),
        Err(MinerAgentError::InsufficientDisk)
    ));
    // Exactly at budget is admitted.
    assert!(lc.check_disk_budget(64).is_ok());
}

#[test]
fn check_disk_budget_zero_disables_the_fail_fast() {
    // 0 budget = disabled (back-compat) — a huge request passes; the
    // launch-time statvfs backstop still catches a genuinely full mount.
    let lc = lifecycle_with_disk_budget(0);
    assert!(lc.check_disk_budget(1_000_000).is_ok());
}

/// A lifecycle whose data-disk root is `root` — for the measured
/// free-space preflight (`check_disk_space`).
fn lifecycle_on_root(root: &std::path::Path) -> CvmLifecycle {
    lifecycle_with_disk_budget(0).with_state_disk_root(root.to_path_buf())
}

/// A sparse file under `<root>/data/` that promises all but
/// `leave_gib` GiB of the filesystem's current free space.
fn promise_all_but(root: &std::path::Path, name: &str, leave_gib: u64) {
    let free = nix::sys::statvfs::statvfs(root).unwrap();
    #[allow(clippy::useless_conversion)]
    let free = u64::from(free.blocks_available()) * u64::from(free.fragment_size());
    let data = root.join("data");
    std::fs::create_dir_all(&data).unwrap();
    let f = std::fs::File::create(data.join(name)).unwrap();
    f.set_len(free.saturating_sub(leave_gib << 30)).unwrap();
}

#[test]
fn check_disk_space_refuses_what_the_filesystem_cannot_hold() {
    let tmp = tempfile::tempdir().unwrap();
    let lc = lifecycle_on_root(tmp.path());
    let vm = VmId::new("tenant-space").unwrap();
    assert!(lc.check_disk_space(&vm, 1).is_ok());
    assert!(matches!(
        lc.check_disk_space(&vm, u32::MAX),
        Err(MinerAgentError::InsufficientDisk)
    ));
    // 0 GiB never refuses.
    assert!(lc.check_disk_space(&vm, 0).is_ok());
}

/// Serialises the tests below whose margin a concurrent GiB-scale host
/// reservation would eat (the host ledger is process-wide).
static TIGHT: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn tight() -> std::sync::MutexGuard<'static, ()> {
    TIGHT
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[test]
fn check_disk_space_counts_the_unwritten_tail_of_existing_disks() {
    // An existing sparse disk that has promised all but ~4 GiB: a bare
    // statvfs would still admit 8 GiB, the net-of-tail gate must not.
    let _tight = tight();
    let tmp = tempfile::tempdir().unwrap();
    let lc = lifecycle_on_root(tmp.path());
    promise_all_but(tmp.path(), "tenant-other.img", 4);
    let vm = VmId::new("tenant-new").unwrap();
    assert!(matches!(
        lc.check_disk_space(&vm, 8),
        Err(MinerAgentError::InsufficientDisk)
    ));
    assert!(lc.check_disk_space(&vm, 2).is_ok());
}

#[test]
fn check_disk_space_counts_what_in_flight_writers_hold_reserved() {
    // A backup / restore / §25 download holding 3 GiB of the 4 GiB left:
    // the preflight must not promise a launch those bytes.
    let _tight = tight();
    let tmp = tempfile::tempdir().unwrap();
    let lc = lifecycle_on_root(tmp.path());
    promise_all_but(tmp.path(), "tenant-other.img", 4);
    let vm = VmId::new("tenant-new").unwrap();
    let ledger = lc.disk_space_ledger();
    let held = ledger.reserve(tmp.path(), 3 << 30, 0).expect("fits");
    assert!(matches!(
        lc.check_disk_space(&vm, 2),
        Err(MinerAgentError::InsufficientDisk)
    ));
    drop(held);
    assert!(lc.check_disk_space(&vm, 2).is_ok());
}

#[test]
fn check_disk_space_never_refuses_a_vm_whose_disk_already_exists() {
    // A relaunch reuses its disk: it needs no new space.
    let tmp = tempfile::tempdir().unwrap();
    let lc = lifecycle_on_root(tmp.path());
    let vm = VmId::new("tenant-back").unwrap();
    promise_all_but(tmp.path(), "tenant-back.img", 0);
    assert!(lc.check_disk_space(&vm, 64).is_ok());
    // …and the golden overlay counts as that disk too.
    let vm2 = VmId::new("tenant-golden").unwrap();
    std::fs::create_dir_all(tmp.path().join("overlay")).unwrap();
    std::fs::write(tmp.path().join("overlay/tenant-golden.img"), b"").unwrap();
    assert!(lc.check_disk_space(&vm2, 64).is_ok());
}

#[tokio::test]
async fn launch_reaches_running() {
    let driver = Arc::new(MockLibvirtDriver::new());
    let lc = lifecycle(driver.clone(), ok_digest());
    let vm = lc.launch(order("cvm-1")).await.unwrap();
    assert_eq!(lc.query(&vm).await.unwrap(), CvmPhase::Running);
    assert_eq!(driver.defined_count().unwrap(), 1);
}

/// A GOLDEN-mode launch order (golden-bake PR4): the measured cmdline
/// carries `dm-verity.root=` and NO `hippius.luks_header_sha256=`, and a
/// non-zero `data_disk_size_gb` (the overlay-upper size anchor). The
/// `luks_disk_path` on the order is IGNORED in golden mode — the miner
/// derives the blank overlay vda itself — but we set a sentinel to prove
/// it is not the disk that boots.
fn golden_order(vm_id: &str) -> LaunchOrder {
    let mut o = order(vm_id);
    o.cmdline = format!(
        "ro quiet dm-verity.root={} hippius.disk_gb=10 boot=hippius-golden",
        "0".repeat(64)
    );
    o.luks_disk_path = PathBuf::from("/var/lib/hippius-miner/IGNORED-in-golden.qcow2");
    o.data_disk_size_gb = 10;
    o
}

#[tokio::test]
async fn golden_launch_reaches_running_with_a_derived_overlay_vda() {
    // Point the storage root at a tempdir NOT under MINER_ROOT: the golden
    // overlay vda is derived there, so a launch that reaches Running PROVES
    // the golden `validate()` branch admits the internally-derived path
    // (validate_input_path) rather than the MINER_ROOT-prefixed
    // validate_luks_path that guards an order-supplied legacy vda.
    let tmp = tempfile::tempdir().unwrap();
    seed_snp_probe();
    let driver = Arc::new(MockLibvirtDriver::new());
    let lc = CvmLifecycle::new_with_poll(
        driver.clone(),
        ok_digest(),
        HostResources {
            total_cpus: 16,
            total_memory_mb: 65536,
            total_disk_gb: 0,
        },
        Duration::from_millis(1),
        5,
    )
    .with_state_disk_root(tmp.path().to_path_buf())
    .skip_state_disk_provision_for_tests();
    let vm = lc.launch(golden_order("cvm-golden-1")).await.unwrap();
    assert_eq!(lc.query(&vm).await.unwrap(), CvmPhase::Running);
    assert_eq!(driver.defined_count().unwrap(), 1);
}

#[tokio::test]
async fn golden_launch_without_a_disk_gb_is_refused() {
    // The golden overlay upper IS the root — a zero disk_gb is a producer
    // bug and must fail closed BEFORE any domain is defined.
    let driver = Arc::new(MockLibvirtDriver::new());
    let lc = lifecycle(driver.clone(), ok_digest());
    let mut o = golden_order("cvm-golden-nodisk");
    o.data_disk_size_gb = 0;
    assert!(matches!(
        lc.launch(o).await,
        Err(MinerAgentError::LaunchInput("golden-disk-gb-zero"))
    ));
    assert_eq!(driver.defined_count().unwrap(), 0);
}

#[tokio::test]
async fn launch_emits_booting_at_domain_start() {
    // A successful domain start fires exactly one `booting` milestone for
    // the launching VM through the wired progress sink — the host-observed
    // first phase of `booting → kek-released → running`. The emit is
    // detached + fail-open, so it never affects the launch result.
    let sink = Arc::new(SpySink::new());
    let lc = lifecycle(Arc::new(MockLibvirtDriver::new()), ok_digest())
        .with_progress_sink(Some(sink.clone() as Arc<dyn VmProgressSink>));
    let vm = lc.launch(order("cvm-boot-1")).await.unwrap();
    assert_eq!(lc.query(&vm).await.unwrap(), CvmPhase::Running);
    settle().await;
    let seen = sink.seen();
    assert_eq!(seen.len(), 1, "exactly one booting report per launch");
    assert_eq!(seen[0].0, "cvm-boot-1");
    assert_eq!(seen[0].1, VmProgressMilestone::Booting);
}

#[tokio::test]
async fn launch_without_a_sink_does_not_panic() {
    // Fail-open: the default lifecycle has no progress sink, so a launch
    // simply reports nothing — the emit is a no-op, never launch-fatal.
    let lc = lifecycle(Arc::new(MockLibvirtDriver::new()), ok_digest());
    let vm = lc.launch(order("cvm-nosink-1")).await.unwrap();
    assert_eq!(lc.query(&vm).await.unwrap(), CvmPhase::Running);
}

#[tokio::test]
async fn launch_retries_a_fresh_cid_on_a_guest_cid_collision() {
    // AUDIT-3: an orphan qemu holds the guest-cid the allocator handed
    // out → libvirt `create` fails `Address already in use`. The launch
    // must BURN that CID, pick a fresh one, and retry — not fail.
    use hippius_miner_agent::vsock::MIN_GUEST_CID;
    let driver = Arc::new(MockLibvirtDriver::new());
    driver.set_cid_conflicts(2); // two orphan collisions, then success
    let lc = lifecycle(driver.clone(), ok_digest());
    let vm = lc.launch(order("cvm-1")).await.unwrap();
    assert_eq!(lc.query(&vm).await.unwrap(), CvmPhase::Running);
    // Burned MIN and MIN+1, landed on MIN+2.
    assert_eq!(
        lc.cid_allocator().cid_for_vm(&vm).unwrap(),
        Some(MIN_GUEST_CID + 2)
    );
    // Each collision undefined the stale (bad-CID) definition before the
    // retry redefined with the fresh CID.
    assert_eq!(driver.undefine_count(), 2);
}

#[tokio::test]
async fn launch_fails_when_cid_collisions_exceed_the_retry_bound() {
    // More collisions than the retry bound (8) → the launch fails closed
    // rather than looping forever.
    let driver = Arc::new(MockLibvirtDriver::new());
    driver.set_cid_conflicts(9);
    let lc = lifecycle(driver.clone(), ok_digest());
    assert!(matches!(
        lc.launch(order("cvm-1")).await,
        Err(MinerAgentError::VsockCid("cid-in-use"))
    ));
}

#[tokio::test]
async fn double_launch_of_a_live_vm_is_refused() {
    let lc = lifecycle(Arc::new(MockLibvirtDriver::new()), ok_digest());
    lc.launch(order("cvm-1")).await.unwrap();
    // The relaunch now runs the idempotent-admission liveness probe;
    // the domain is genuinely Running, so it is STILL refused — we must
    // never reclaim a slot whose tenant VM is live.
    assert!(matches!(
        lc.launch(order("cvm-1")).await,
        Err(MinerAgentError::AlreadyLaunched)
    ));
}

#[tokio::test]
async fn relaunch_reclaims_a_stale_handle_after_out_of_band_shutoff() {
    // cvm-1 launched (handle present, domain Running); then an
    // out-of-band `virsh destroy` shut the domain off WITHOUT the agent
    // tearing down the handle — the live "already-launched" bug that
    // previously forced an `hippius-miner-agent` restart to clear. A
    // relaunch MUST reclaim the stale slot and proceed, not be refused
    // `AlreadyLaunched`.
    let driver = Arc::new(MockLibvirtDriver::new());
    let lc = lifecycle(driver.clone(), ok_digest());
    let vm = lc.launch(order("cvm-1")).await.unwrap();
    assert_eq!(lc.query(&vm).await.unwrap(), CvmPhase::Running);

    // Out-of-band: the domain goes ShutOff; the handle is NOT removed.
    driver.force_all_to_state(DomainState::ShutOff).unwrap();

    // Relaunch the same vm_id — reclaimed (prior domain undefined, slot
    // replaced) and reaches Running again, with no duplicate handle.
    let vm2 = lc.launch(order("cvm-1")).await.unwrap();
    assert_eq!(lc.query(&vm2).await.unwrap(), CvmPhase::Running);
    assert_eq!(lc.list().await.unwrap().len(), 1);
    // The reclaim went through the failed-launch teardown (destroy +
    // undefine of the stale domain).
    assert!(driver.undefine_count() >= 1);
}

#[tokio::test]
async fn stop_drops_the_handle() {
    let lc = lifecycle(Arc::new(MockLibvirtDriver::new()), ok_digest());
    let vm = lc.launch(order("cvm-1")).await.unwrap();
    lc.stop(&vm, true).await.unwrap();
    assert!(matches!(
        lc.query(&vm).await,
        Err(MinerAgentError::VmNotFound)
    ));
    assert!(lc.list().await.unwrap().is_empty());
}

#[tokio::test]
async fn force_stop_also_drops_the_handle() {
    let lc = lifecycle(Arc::new(MockLibvirtDriver::new()), ok_digest());
    let vm = lc.launch(order("cvm-1")).await.unwrap();
    lc.stop(&vm, false).await.unwrap();
    assert!(lc.list().await.unwrap().is_empty());
}

#[tokio::test]
async fn digest_failure_aborts_before_any_virsh_call() {
    let driver = Arc::new(MockLibvirtDriver::new());
    let lc = lifecycle(driver.clone(), Arc::new(MockLaunchDigest::failing()));
    assert!(matches!(
        lc.launch(order("cvm-1")).await,
        Err(MinerAgentError::LaunchDigest(_))
    ));
    // Fail-closed BEFORE virsh: no domain was ever defined, and no
    // `destroy` was issued (a rollback destroy here could hit a stale
    // domain sharing the deterministic name).
    assert_eq!(driver.defined_count().unwrap(), 0);
    assert_eq!(driver.destroy_count(), 0);
    // The reservation was rolled back — the VmId is free to retry.
    assert!(lc.list().await.unwrap().is_empty());
}

#[tokio::test]
async fn launch_after_a_failed_launch_is_allowed() {
    let driver = Arc::new(MockLibvirtDriver::new());
    let lc = lifecycle(driver, Arc::new(MockLaunchDigest::failing()));
    assert!(lc.launch(order("cvm-1")).await.is_err());
    // A failed launch is not a live CVM — a clean retry is admitted
    // (here it fails again only because the digest mock still fails).
    assert!(matches!(
        lc.launch(order("cvm-1")).await,
        Err(MinerAgentError::LaunchDigest(_))
    ));
}

#[tokio::test]
async fn launch_times_out_when_the_domain_never_runs() {
    let driver = Arc::new(MockLibvirtDriver::with_post_create_state(
        DomainState::Paused,
    ));
    let lc = lifecycle(driver, ok_digest());
    assert!(matches!(
        lc.launch(order("cvm-1")).await,
        Err(MinerAgentError::LaunchFailed("timeout"))
    ));
}

#[tokio::test]
async fn launch_fails_closed_on_a_crashed_domain() {
    let driver = Arc::new(MockLibvirtDriver::with_post_create_state(
        DomainState::Crashed,
    ));
    let lc = lifecycle(driver, ok_digest());
    assert!(matches!(
        lc.launch(order("cvm-1")).await,
        Err(MinerAgentError::LaunchFailed("domain-error"))
    ));
}

#[tokio::test]
async fn launch_is_refused_when_over_the_host_budget() {
    let lc = CvmLifecycle::new_with_poll(
        Arc::new(MockLibvirtDriver::new()),
        ok_digest(),
        // 1024 MiB budget — `order()` asks for 2048 MiB.
        HostResources {
            total_cpus: 16,
            total_memory_mb: 1024,
            total_disk_gb: 0,
        },
        Duration::from_millis(1),
        5,
    )
    .skip_state_disk_provision_for_tests();
    assert!(matches!(
        lc.launch(order("cvm-1")).await,
        Err(MinerAgentError::InsufficientResources)
    ));
}

#[tokio::test]
async fn a_second_launch_that_overcommits_is_refused() {
    let lc = CvmLifecycle::new_with_poll(
        Arc::new(MockLibvirtDriver::new()),
        ok_digest(),
        // Budget fits exactly one `order()` (2 cpu / 2048 MiB).
        HostResources {
            total_cpus: 2,
            total_memory_mb: 2048,
            total_disk_gb: 0,
        },
        Duration::from_millis(1),
        5,
    )
    .skip_state_disk_provision_for_tests();
    lc.launch(order("cvm-1")).await.unwrap();
    assert!(matches!(
        lc.launch(order("cvm-2")).await,
        Err(MinerAgentError::InsufficientResources)
    ));
}

#[tokio::test]
async fn list_reports_every_running_cvm() {
    let lc = lifecycle(Arc::new(MockLibvirtDriver::new()), ok_digest());
    lc.launch(order("cvm-a")).await.unwrap();
    lc.launch(order("cvm-b")).await.unwrap();
    let listed = lc.list().await.unwrap();
    assert_eq!(listed.len(), 2);
    assert!(listed.iter().all(|(_, phase)| *phase == CvmPhase::Running));
}

#[tokio::test]
async fn shutdown_all_stops_every_cvm() {
    let lc = lifecycle(Arc::new(MockLibvirtDriver::new()), ok_digest());
    lc.launch(order("cvm-a")).await.unwrap();
    lc.launch(order("cvm-b")).await.unwrap();
    lc.shutdown_all().await.unwrap();
    assert!(lc.list().await.unwrap().is_empty());
}

// ── Stale-handle / teardown regression coverage (#) ────────────────
//
// These tests cover a bug observed live during an end-to-end run:
// when `run_domain` returns `Err` (a domain that defines + starts
// but exits before reaching Running — disk perms, kernel panic in
// initramfs, SEV-SNP launch reject), the in-process handle MUST be
// cleared by `teardown_failed_launch` so the next dispatch for the
// same `vm_id` is admitted instead of mis-classified as
// `AlreadyLaunched` (which the orders handler maps to the
// success-shaped `Ok("already-launched")`).

#[tokio::test]
async fn handle_is_cleared_after_run_domain_failure() {
    // `Crashed` post-create state makes `await_running` return
    // `LaunchFailed("domain-error")` — the run_domain-Err path.
    let driver = Arc::new(MockLibvirtDriver::with_post_create_state(
        DomainState::Crashed,
    ));
    let lc = lifecycle(driver, ok_digest());
    assert!(matches!(
        lc.launch(order("cvm-1")).await,
        Err(MinerAgentError::LaunchFailed("domain-error"))
    ));
    // The user-stated invariant: `handles.len() == 0` after the
    // failed launch's teardown completes. Asserted via the
    // `tracked_count` test+ops-debug accessor (no need to expose the
    // inner map).
    assert_eq!(
        lc.tracked_count().unwrap(),
        0,
        "teardown_failed_launch must clear the handle on a run_domain Err"
    );
}

#[tokio::test]
async fn retry_after_run_domain_failure_is_admitted_not_already_launched() {
    // Same setup as above, but exercise the user-visible behaviour
    // (the retry-from-operator path) rather than reaching into the
    // accessor. A second launch for the same vm_id MUST go through
    // the same Err code-path (Crashed) — it MUST NOT be mis-routed
    // to `AlreadyLaunched`, which would be the symptom the bug
    // produced in production.
    let driver = Arc::new(MockLibvirtDriver::with_post_create_state(
        DomainState::Crashed,
    ));
    let lc = lifecycle(driver, ok_digest());
    let first = lc.launch(order("cvm-retry")).await;
    assert!(matches!(
        first,
        Err(MinerAgentError::LaunchFailed("domain-error"))
    ));
    let second = lc.launch(order("cvm-retry")).await;
    assert!(
        !matches!(second, Err(MinerAgentError::AlreadyLaunched)),
        "retry after a failed run_domain MUST NOT be refused as AlreadyLaunched, got {second:?}"
    );
    // Same-failure expected — the mock still crashes on
    // post-create; the assertion above is the load-bearing one.
    assert!(matches!(
        second,
        Err(MinerAgentError::LaunchFailed("domain-error"))
    ));
}

/// Test-only `LibvirtDriver` that lets the test pin `destroy_domain`
/// open until released, so the *actual* race the fix closes — a
/// retry that races between Phase 1 (handle remove) and Phase 2
/// (await destroy) — can be modelled directly.
///
/// The default [`MockLibvirtDriver`] returns from `destroy_domain`
/// without any await point of consequence, so it cannot exercise
/// the timing window. This wrapper adds exactly one async gate
/// inside `destroy_domain`, controlled by the test thread.
///
/// Synchronization primitive choice
/// --------------------------------
/// `proceed` is a [`Semaphore`] (initialised with 0 permits) — NOT
/// a [`Notify`]. `Notify::notify_one` stores at most ONE permit;
/// two `notify_one` calls back-to-back with no waiter present
/// collapse to a single permit, so a test that signals N waiters
/// with N sequential `notify_one` calls would deadlock if those
/// calls landed before the waiters arrived. `Semaphore::add_permits(N)`
/// stores all N permits, and each `acquire()` consumes one — robust
/// regardless of waiter / signaller scheduling order.
///
/// `destroy_entered` stays a [`Notify`] because the test pattern
/// here is the safe one for `Notify`: exactly ONE notifier (the
/// first task that hits destroy_domain) and exactly ONE awaiter
/// (the test thread).
struct PausableDestroyDriver {
    inner: Arc<MockLibvirtDriver>,
    /// Fires once `destroy_domain` has been entered. The test
    /// `.notified().await`s this to know "the failed launch's
    /// teardown is now inside Phase 2 — kick off the retry now."
    destroy_entered: Arc<Notify>,
    /// Each call to `destroy_domain` consumes one permit before
    /// proceeding to the inner mock. The test releases N permits
    /// up front when N concurrent teardowns are expected.
    proceed: Arc<Semaphore>,
}

#[async_trait]
impl LibvirtDriver for PausableDestroyDriver {
    async fn define_domain(&self, xml: &str) -> Result<DomainId> {
        self.inner.define_domain(xml).await
    }
    async fn create_domain(&self, id: &DomainId) -> Result<()> {
        self.inner.create_domain(id).await
    }
    async fn destroy_domain(&self, id: &DomainId, graceful: bool) -> Result<()> {
        self.destroy_entered.notify_one();
        // `acquire` returns a `SemaphorePermit` that releases the
        // permit on drop. We `forget` it so the permit is consumed
        // (not re-released into the pool) — each `destroy_domain`
        // call must consume exactly one permit.
        let permit = self
            .proceed
            .acquire()
            .await
            .expect("semaphore must not be closed in tests");
        permit.forget();
        self.inner.destroy_domain(id, graceful).await
    }
    async fn undefine_domain(&self, id: &DomainId) -> Result<()> {
        // Pass-through. The race this driver models is the
        // destroy-time stall (Phase 2 of `teardown_failed_launch`);
        // undefine runs strictly after, and gating it here would
        // distort the timing without testing anything new.
        self.inner.undefine_domain(id).await
    }
    async fn query_domain_state(&self, id: &DomainId) -> Result<DomainState> {
        self.inner.query_domain_state(id).await
    }
    async fn list_domains(&self) -> Result<Vec<(DomainId, DomainState)>> {
        self.inner.list_domains().await
    }
    async fn domain_xml(&self, id: &DomainId) -> Result<String> {
        self.inner.domain_xml(id).await
    }
}

#[tokio::test]
async fn retry_is_admitted_while_teardown_is_mid_destroy() {
    // Model the live-observed race directly: the failed launch's
    // teardown enters `destroy_domain` (and stalls there); a retry
    // arrives during that window. With the eager Phase-1 handle
    // remove, the retry MUST see an empty slot and proceed — NOT
    // get `AlreadyLaunched`. Without the fix this test would block
    // / fail on `AlreadyLaunched`.
    let inner = Arc::new(MockLibvirtDriver::with_post_create_state(
        DomainState::Crashed,
    ));
    let destroy_entered = Arc::new(Notify::new());
    // Two expected teardown calls — Task A and Task B both go
    // through the Crashed→teardown path. `Semaphore` (not
    // `Notify`) lets us pre-release all expected permits at once
    // without depending on test/task scheduling order.
    let proceed = Arc::new(Semaphore::new(0));
    let driver = Arc::new(PausableDestroyDriver {
        inner,
        destroy_entered: destroy_entered.clone(),
        proceed: proceed.clone(),
    });
    let lc = Arc::new(
        CvmLifecycle::new_with_poll(
            driver,
            ok_digest(),
            HostResources {
                total_cpus: 16,
                total_memory_mb: 65536,
                total_disk_gb: 0,
            },
            Duration::from_millis(1),
            5,
        )
        .skip_state_disk_provision_for_tests(),
    );

    // Task A: first launch — Crashed post-create → run_domain Err →
    // teardown enters destroy_domain → blocks on `proceed`.
    let lc_a = Arc::clone(&lc);
    let task_a = tokio::spawn(async move { lc_a.launch(order("cvm-race")).await });

    // Wait until Task A is parked inside destroy_domain (Phase 2).
    // Phase 1 must have removed the handle by now.
    destroy_entered.notified().await;
    assert_eq!(
        lc.tracked_count().unwrap(),
        0,
        "Phase 1 of teardown must have removed the handle before destroy await"
    );

    // Task B: retry from operator. With the fix, Task B sees the
    // empty slot and proceeds (it will hit the same Crashed-mock
    // failure, but that's a SECOND teardown, not an
    // `AlreadyLaunched`). Spawn it so Task A can still complete.
    let lc_b = Arc::clone(&lc);
    let task_b = tokio::spawn(async move { lc_b.launch(order("cvm-race")).await });

    // Release two permits — one for Task A's teardown, one for
    // Task B's (which goes through the same Crashed → teardown
    // path). Permits accumulate atomically, so it doesn't matter
    // whether Task B has reached `destroy_domain` yet.
    proceed.add_permits(2);

    let result_a = task_a.await.unwrap();
    let result_b = task_b.await.unwrap();
    assert!(
        matches!(result_a, Err(MinerAgentError::LaunchFailed("domain-error"))),
        "task A: {result_a:?}"
    );
    assert!(
        !matches!(result_b, Err(MinerAgentError::AlreadyLaunched)),
        "task B (retry mid-destroy) MUST NOT be refused as AlreadyLaunched, got {result_b:?}"
    );
}

#[tokio::test]
async fn handle_is_cleared_after_libvirt_define_failure() {
    // Edge case from the brief: "if the domain was never defined
    // libvirt-side (e.g. config validation fail before run_domain
    // entry), the handle exists but no domain → handles.remove()
    // stays safe (no-op libvirt if domain does not exist)."
    //
    // We exercise the closest mock-reachable variant — a domain
    // that reaches Crashed (define + create succeed, the post-state
    // is bad). The teardown's destroy_domain returns Ok on the
    // mock; the assertion is the same handle-cleanup invariant.
    let driver = Arc::new(MockLibvirtDriver::with_post_create_state(
        DomainState::Crashed,
    ));
    let lc = lifecycle(driver.clone(), ok_digest());
    let _ = lc.launch(order("cvm-edge")).await;
    assert_eq!(lc.tracked_count().unwrap(), 0);
    // `destroy_domain` was issued at least once — this is the
    // libvirt-side rollback that pairs with the handle-remove.
    assert!(driver.destroy_count() >= 1);
}

#[tokio::test]
async fn query_and_stop_of_an_unknown_vm_fail_closed() {
    let lc = lifecycle(Arc::new(MockLibvirtDriver::new()), ok_digest());
    let ghost = VmId::new("ghost").unwrap();
    assert!(matches!(
        lc.query(&ghost).await,
        Err(MinerAgentError::VmNotFound)
    ));
    assert!(matches!(
        lc.stop(&ghost, true).await,
        Err(MinerAgentError::VmNotFound)
    ));
}

// ── undefine_domain regression coverage ─────────────────────────────
//
// Bug observed live during the post-#190 E2E (2026-05-25):
// `teardown_failed_launch` and `stop` both called `destroy_domain` but
// NEVER `undefine_domain`, so the libvirt domain record stayed behind
// in `shut off` state after every dispatch. The next launch of the
// same `vm_id` failed at `virsh define` with
// `domain '…' already exists with uuid …` — the workaround was a
// manual `virsh undefine` between every dispatch.
//
// These three tests pin the new behaviour: undefine on the clean stop
// path, undefine on the failed-launch teardown path, and idempotent
// `Ok(())` when the domain is already gone.

#[tokio::test]
async fn undefine_of_an_unknown_domain_is_idempotent() {
    // The mock driver mirrors the production semantics — `virsh
    // undefine` of a domain libvirt does not know returns Ok via the
    // closed-vocabulary stderr probe in `VirshDriver::undefine_domain`.
    let driver = MockLibvirtDriver::new();
    let ghost = DomainId::new("hippius-tenant-ghost").unwrap();
    driver.undefine_domain(&ghost).await.unwrap();
    assert_eq!(driver.undefine_count(), 1);
}

#[tokio::test]
async fn clean_stop_undefines_the_domain() {
    // A normal launch → graceful stop must remove the libvirt record,
    // not only the runtime. `destroy_count` and `undefine_count` must
    // both move; without the fix, only destroy did.
    let driver = Arc::new(MockLibvirtDriver::new());
    let lc = lifecycle(driver.clone(), ok_digest());
    let vm = lc.launch(order("cvm-clean")).await.unwrap();
    assert_eq!(driver.destroy_count(), 0);
    assert_eq!(driver.undefine_count(), 0);
    lc.stop(&vm, true).await.unwrap();
    assert!(
        driver.undefine_count() >= 1,
        "stop must issue undefine_domain on a clean teardown, got {}",
        driver.undefine_count()
    );
    // The domain record AND the in-process handle are both gone.
    assert_eq!(driver.defined_count().unwrap(), 0);
    assert_eq!(lc.tracked_count().unwrap(), 0);
}

#[tokio::test]
async fn teardown_failed_launch_undefines_after_destroy() {
    // Crashed post-create state ⇒ `await_running` returns Err ⇒
    // `teardown_failed_launch` runs. It must `destroy_domain` AND
    // `undefine_domain` so the next launch of the same vm_id is not
    // blocked by a stranded `shut off` record.
    let driver = Arc::new(MockLibvirtDriver::with_post_create_state(
        DomainState::Crashed,
    ));
    let lc = lifecycle(driver.clone(), ok_digest());
    assert!(matches!(
        lc.launch(order("cvm-teardown")).await,
        Err(MinerAgentError::LaunchFailed("domain-error"))
    ));
    assert!(
        driver.destroy_count() >= 1,
        "teardown_failed_launch must issue destroy_domain"
    );
    assert!(
        driver.undefine_count() >= 1,
        "teardown_failed_launch must issue undefine_domain after destroy, got {}",
        driver.undefine_count()
    );
    // The libvirt record is gone — the next launch is not blocked by
    // a stranded `domain already exists with uuid …`.
    assert_eq!(driver.defined_count().unwrap(), 0);
}

// ── Startup re-adoption (#669 skip_shutdown_teardown follow-up) ───────

#[tokio::test]
async fn readopt_running_re_tracks_a_survivor() {
    // A CVM launched in a prior agent lifetime survives a restart (its
    // qemu domain kept running). A fresh agent must re-adopt it: same
    // handle, same CID, capacity re-counted — as if it had just launched.
    let driver = Arc::new(MockLibvirtDriver::new());
    let tmp = tempfile::tempdir().unwrap();

    // Lifetime 1: launch → the mock defines a Running domain + the
    // launch persists the adopt snapshot under `tmp`.
    let lc1 = lifecycle(driver.clone(), ok_digest()).with_state_disk_root(tmp.path().to_path_buf());
    let vm = lc1.launch(order("cvm-1")).await.unwrap();
    let cid = lc1.cid_allocator().cid_for_vm(&vm).unwrap();
    assert!(cid.is_some(), "launch should have allocated a CID");

    // "Restart": a fresh lifecycle sharing the SAME driver (so the
    // domain is still Running) + the SAME state-disk root. Its
    // handle-map + CID allocator start EMPTY.
    let lc2 = lifecycle(driver.clone(), ok_digest()).with_state_disk_root(tmp.path().to_path_buf());
    assert!(lc2.list().await.unwrap().is_empty());
    assert_eq!(lc2.cid_allocator().cid_for_vm(&vm).unwrap(), None);

    // Re-adopt.
    let n = lc2.readopt_running().await.unwrap();
    assert_eq!(n, 1, "the running survivor should be re-adopted");
    let tracked = lc2.list().await.unwrap();
    assert_eq!(tracked.len(), 1);
    assert_eq!(tracked[0].0, vm);
    assert_eq!(tracked[0].1, CvmPhase::Running);
    // Same CID re-reserved → the vsock relay routes to the live guest.
    assert_eq!(lc2.cid_allocator().cid_for_vm(&vm).unwrap(), cid);
    // Idempotent — a second sweep changes nothing.
    assert_eq!(lc2.readopt_running().await.unwrap(), 0);
}

#[tokio::test]
async fn readopt_prunes_a_snapshot_whose_domain_is_gone() {
    // If the domain stopped while the agent was down, its snapshot is a
    // ghost: re-adoption must prune it, not track a dead VM.
    let driver = Arc::new(MockLibvirtDriver::new());
    let tmp = tempfile::tempdir().unwrap();
    let lc1 = lifecycle(driver.clone(), ok_digest()).with_state_disk_root(tmp.path().to_path_buf());
    lc1.launch(order("cvm-1")).await.unwrap();

    // Domain goes away out-of-band (not via the agent's stop path, so
    // the snapshot lingers).
    driver
        .destroy_domain(&DomainId::new("hippius-tenant-cvm-1").unwrap(), false)
        .await
        .unwrap();

    let lc2 = lifecycle(driver.clone(), ok_digest()).with_state_disk_root(tmp.path().to_path_buf());
    let n = lc2.readopt_running().await.unwrap();
    assert_eq!(n, 0, "a stopped domain must not be re-adopted");
    assert!(lc2.list().await.unwrap().is_empty());
    // The stale snapshot was pruned → a second sweep still finds nothing.
    assert_eq!(lc2.readopt_running().await.unwrap(), 0);
    // ...and its shut-off definition went with it, so the next launch of
    // the same vm_id defines cleanly instead of colliding on the name.
    assert_eq!(driver.defined_count().unwrap(), 0);
    lc2.launch(order("cvm-1")).await.unwrap();
}

#[tokio::test]
async fn readopt_leaves_a_definition_that_started_since_the_liveness_read() {
    // The stale-definition undefine re-reads the state right before it
    // acts: a domain that is shut off at the liveness read but running by
    // the time of the undefine is left alone.
    let driver = Arc::new(MockLibvirtDriver::new());
    let tmp = tempfile::tempdir().unwrap();
    let lc1 = lifecycle(driver.clone(), ok_digest()).with_state_disk_root(tmp.path().to_path_buf());
    lc1.launch(order("cvm-1")).await.unwrap();
    driver
        .destroy_domain(&DomainId::new("hippius-tenant-cvm-1").unwrap(), false)
        .await
        .unwrap();
    let undefines_before = driver.undefine_count();

    // Liveness read: shut off. Undefine-time re-read: running.
    driver.script_states(vec![DomainState::ShutOff, DomainState::Running]);
    let lc2 = lifecycle(driver.clone(), ok_digest()).with_state_disk_root(tmp.path().to_path_buf());
    assert_eq!(lc2.readopt_running().await.unwrap(), 0);

    assert_eq!(driver.undefine_count(), undefines_before, "never undefined");
    assert_eq!(driver.defined_count().unwrap(), 1);
}

#[tokio::test]
async fn destroy_reclaims_a_golden_overlay_after_re_adoption() {
    // A golden VM's writable disk is the overlay UPPER (not a legacy vda).
    // After an agent restart re-adopts it (#676), §24 destroy must still
    // reclaim that overlay rather than leak it — destroy now unlinks the
    // derived `golden_overlay_path` in addition to the handle's
    // `luks_disk_path`. Regression for the golden-migration-e2e disk leak.
    let driver = Arc::new(MockLibvirtDriver::new());
    let tmp = tempfile::tempdir().unwrap();

    // Lifetime 1: launch a golden VM (handle tracked, domain Running).
    let lc1 = lifecycle(driver.clone(), ok_digest()).with_state_disk_root(tmp.path().to_path_buf());
    let vm = lc1.launch(golden_order("gm-1")).await.unwrap();

    // The golden overlay upper lives at the DERIVED path. The test harness
    // skips real disk provisioning, so materialise it here — the point is to
    // prove `destroy` reclaims THIS file (the leak was a golden overlay left
    // orphaned on a re-adopted VM).
    let overlay = lc1.golden_overlay_path(&vm);
    std::fs::create_dir_all(overlay.parent().unwrap()).unwrap();
    std::fs::write(&overlay, b"luks-ciphertext").unwrap();

    // "Restart": a fresh lifecycle sharing the driver + storage roots →
    // re-adopt the still-running golden VM (the re-adopted-handle scenario).
    let lc2 = lifecycle(driver.clone(), ok_digest()).with_state_disk_root(tmp.path().to_path_buf());
    assert_eq!(
        lc2.readopt_running().await.unwrap(),
        1,
        "the golden survivor is re-adopted"
    );

    // §24 destroy → the overlay is unlinked (no leak).
    lc2.destroy(&vm, None).await.unwrap();
    assert!(
        !overlay.exists(),
        "destroy must reclaim the golden overlay after re-adoption"
    );
}

// ── Re-adoption hardening: capacity, orphans, ambiguous records ──────

/// A `virsh dumpxml`-shaped tenant domain document. Mirrors what libvirt
/// actually emits (memory normalised to `KiB`, `<memoryBacking>` right
/// after `<memory>`, injected `<alias>`), so the tests exercise the form
/// re-adoption really reads.
fn dumpxml(vm: &str, vcpus: u32, memory_kib: u64, cid: u32, vda: &str) -> String {
    format!(
        "<domain type='kvm' id='7'>\n\
         <name>hippius-tenant-{vm}</name>\n\
         <uuid>11111111-2222-4333-8444-555555555555</uuid>\n\
         <memory unit='KiB'>{memory_kib}</memory>\n\
         <currentMemory unit='KiB'>{memory_kib}</currentMemory>\n\
         <memoryBacking><source type='memfd'/></memoryBacking>\n\
         <vcpu placement='static'>{vcpus}</vcpu>\n\
         <devices>\n\
         <disk type='file' device='disk'><driver name='qemu' type='raw'/>\
         <source file='{vda}' index='4'/><target dev='vda' bus='virtio'/>\
         <alias name='virtio-disk0'/></disk>\n\
         <disk type='file' device='disk'><driver name='qemu' type='raw'/>\
         <source file='/var/lib/hippius-miner/state/{vm}.raw' index='1'/>\
         <target dev='vdd' bus='virtio'/></disk>\n\
         <vsock model='virtio'><cid auto='no' address='{cid}'/>\
         <alias name='vsock0'/></vsock>\n\
         </devices>\n\
         </domain>\n"
    )
}

/// Write an `adopt` sidecar by hand — models a record that was written
/// by an older agent, edited, or otherwise disagrees with the live
/// domain. Writing the JSON literally (rather than via `persist`) also
/// pins the on-disk format.
fn write_sidecar(root: &std::path::Path, vm: &str, cpu: u8, mem_mb: u32, cid: u32, disk: &str) {
    let dir = root.join("adopt");
    std::fs::create_dir_all(&dir).unwrap();
    let json = format!(
        r#"{{
            "vm_id": "{vm}",
            "domain_id": "hippius-tenant-{vm}",
            "domain_uuid": "11111111-2222-4333-8444-555555555555",
            "launch_digest_hex": "{}",
            "cpu_count": {cpu},
            "memory_mb": {mem_mb},
            "data_disk_size_gb": 0,
            "luks_disk_path": "{disk}",
            "cid": {cid},
            "cose_ticket_hex": "deadbeef"
        }}"#,
        "00".repeat(48),
    );
    std::fs::write(dir.join(format!("{vm}.json")), json).unwrap();
}

/// Assert the lifecycle has EXACTLY `cpu` vCPUs and `mem` MiB committed
/// against a 16 vCPU / 65536 MiB host — one vCPU / one MiB either side
/// flips the answer, so this pins the number rather than bounding it.
fn assert_committed(lc: &CvmLifecycle, cpu: u8, mem: u32) {
    assert!(
        lc.check_cpu_mem_budget(16 - cpu, 65536 - mem).is_ok(),
        "expected exactly {cpu}c/{mem}MiB committed — the remainder must still fit"
    );
    assert!(
        matches!(
            lc.check_cpu_mem_budget(16 - cpu + 1, 0),
            Err(MinerAgentError::InsufficientResources)
        ),
        "expected exactly {cpu}c committed — one more vCPU must NOT fit"
    );
    assert!(
        matches!(
            lc.check_cpu_mem_budget(0, 65536 - mem + 1),
            Err(MinerAgentError::InsufficientResources)
        ),
        "expected exactly {mem}MiB committed — one more MiB must NOT fit"
    );
}

#[tokio::test]
async fn readopt_recommits_the_exact_cpu_and_memory_budget() {
    // The #668 fit gate sums the handle map. If re-adoption restores the
    // handles but not their resources, the miner silently believes it is
    // empty and oversubscribes itself. Three 2c/2048MiB survivors must
    // come back as EXACTLY 6c/6144MiB committed — the same total the
    // agent held before the restart.
    let driver = Arc::new(MockLibvirtDriver::new());
    let tmp = tempfile::tempdir().unwrap();
    let lc1 = lifecycle(driver.clone(), ok_digest()).with_state_disk_root(tmp.path().to_path_buf());
    for vm in ["cap-1", "cap-2", "cap-3"] {
        lc1.launch(order(vm)).await.unwrap();
    }
    assert_committed(&lc1, 6, 6144);

    // Restart: fresh handle map, same domains, same state root.
    let lc2 = lifecycle(driver.clone(), ok_digest()).with_state_disk_root(tmp.path().to_path_buf());
    assert_committed(&lc2, 0, 0); // nothing tracked yet — the gap
    assert_eq!(lc2.readopt_running().await.unwrap(), 3);
    assert_committed(&lc2, 6, 6144);
}

#[tokio::test]
async fn readopt_does_not_double_count_on_a_second_sweep() {
    // A crash-restart loop, or a future caller that sweeps twice, must
    // not charge a survivor's resources twice — that would starve the
    // host in the OTHER direction and reject launches that fit.
    let driver = Arc::new(MockLibvirtDriver::new());
    let tmp = tempfile::tempdir().unwrap();
    let lc1 = lifecycle(driver.clone(), ok_digest()).with_state_disk_root(tmp.path().to_path_buf());
    lc1.launch(order("dbl-1")).await.unwrap();

    let lc2 = lifecycle(driver.clone(), ok_digest()).with_state_disk_root(tmp.path().to_path_buf());
    assert_eq!(lc2.readopt_running().await.unwrap(), 1);
    assert_committed(&lc2, 2, 2048);
    // Sweep again, and again — still exactly one VM's worth.
    assert_eq!(lc2.readopt_running().await.unwrap(), 0);
    assert_eq!(lc2.readopt_running().await.unwrap(), 0);
    assert_committed(&lc2, 2, 2048);
    assert_eq!(lc2.list().await.unwrap().len(), 1);
}

#[tokio::test]
async fn readopt_restores_the_cid_map_the_billing_relay_gates_on() {
    // `vsock::handle_guest_conn` resolves the inbound CID through
    // `CidAllocator::vm_id_for_cid` and REJECTS an unknown one. That
    // lookup is the billing relay's gate: if re-adoption does not restore
    // it, the survivor's served-delivery receipts are dropped as
    // `unknown-cid` and the tenant stops being billed.
    let driver = Arc::new(MockLibvirtDriver::new());
    let tmp = tempfile::tempdir().unwrap();
    let lc1 = lifecycle(driver.clone(), ok_digest()).with_state_disk_root(tmp.path().to_path_buf());
    let vm = lc1.launch(order("bill-1")).await.unwrap();
    let cid = lc1.cid_allocator().cid_for_vm(&vm).unwrap().unwrap();

    let lc2 = lifecycle(driver.clone(), ok_digest()).with_state_disk_root(tmp.path().to_path_buf());
    assert_eq!(
        lc2.cid_allocator().vm_id_for_cid(cid).unwrap(),
        None,
        "pre-adoption the relay would reject this guest — the gap"
    );
    lc2.readopt_running().await.unwrap();
    assert_eq!(
        lc2.cid_allocator().vm_id_for_cid(cid).unwrap(),
        Some(vm),
        "the relay must resolve the survivor's CID again, or billing stays dead"
    );
}

#[tokio::test]
async fn an_unreachable_libvirt_never_deletes_a_snapshot() {
    // FAIL-SAFE DIRECTION. `virsh domstate` can fail transiently at boot
    // (libvirtd not up yet, socket busy). Treating that as "gone" and
    // pruning destroys the ONLY copy of the vali-signed ticket — nothing
    // on the host can re-mint it, so the VM would be permanently
    // untracked and unable to survive a reboot. Uncertainty must SKIP,
    // never delete.
    let driver = Arc::new(MockLibvirtDriver::new());
    let tmp = tempfile::tempdir().unwrap();
    let lc1 = lifecycle(driver.clone(), ok_digest()).with_state_disk_root(tmp.path().to_path_buf());
    let vm = lc1.launch(order("dark-1")).await.unwrap();
    let sidecar = tmp.path().join("adopt").join("dark-1.json");
    assert!(sidecar.exists());

    // Start with libvirt down: nothing is adopted…
    let dark = CvmLifecycle::new(
        Arc::new(AlwaysUnreachableDriver),
        ok_digest(),
        HostResources {
            total_cpus: 16,
            total_memory_mb: 65536,
            total_disk_gb: 0,
        },
    )
    .with_state_disk_root(tmp.path().to_path_buf());
    assert_eq!(dark.readopt_running().await.unwrap(), 0);
    // …and the snapshot SURVIVES.
    assert!(
        sidecar.exists(),
        "a snapshot must never be pruned on libvirt uncertainty"
    );

    // A later start, with libvirt back, re-adopts it in full.
    let lc2 = lifecycle(driver.clone(), ok_digest()).with_state_disk_root(tmp.path().to_path_buf());
    assert_eq!(lc2.readopt_running().await.unwrap(), 1);
    assert!(lc2.ticket_for_vm(&vm).is_some(), "the ticket survived");
    assert_committed(&lc2, 2, 2048);
}

#[tokio::test]
async fn a_live_domain_with_no_snapshot_is_adopted_from_libvirt() {
    // The sidecar is written best-effort: the write can fail, the
    // directory can be moved aside (observed live, `adopt.bak/`),
    // an older agent may never have written one. Without a libvirt sweep
    // such a VM is invisible forever — uncounted capacity, dead relay.
    let driver = Arc::new(MockLibvirtDriver::new());
    let tmp = tempfile::tempdir().unwrap();
    driver.seed_domain_xml(
        DomainId::new("hippius-tenant-orphan-1").unwrap(),
        DomainState::Running,
        &dumpxml(
            "orphan-1",
            4,
            8 * 1024 * 1024, // 8 GiB in KiB
            21,
            "/var/lib/hippius-miner/overlay/orphan-1.img",
        ),
    );
    let lc = lifecycle(driver.clone(), ok_digest()).with_state_disk_root(tmp.path().to_path_buf());
    assert_eq!(lc.readopt_running().await.unwrap(), 1);

    let vm = VmId::new("orphan-1").unwrap();
    // Charged at what libvirt ACTUALLY runs.
    assert_committed(&lc, 4, 8192);
    // Relay routes for it again.
    assert_eq!(
        lc.cid_allocator().vm_id_for_cid(21).unwrap(),
        Some(vm.clone())
    );
    // §24 reclaim knows the real writable volume.
    assert_eq!(
        lc.luks_disk_path_for(&vm),
        Some(PathBuf::from("/var/lib/hippius-miner/overlay/orphan-1.img"))
    );
}

#[tokio::test]
async fn an_orphan_is_adopted_with_no_ticket_authority() {
    // What adoption may GRANT. libvirt cannot supply the vali-signed
    // `cose_ticket`, and nothing on the miner can forge one — so an
    // orphan is counted but never acted upon: `ticket_for_vm` is the
    // single gate the reboot-watcher uses BOTH to re-push a ticket
    // (`handle_started`) and to decide it may `virsh start` a stopped
    // domain (`handle_stopped`). It must stay `None`.
    let driver = Arc::new(MockLibvirtDriver::new());
    let tmp = tempfile::tempdir().unwrap();
    driver.seed_domain_xml(
        DomainId::new("hippius-tenant-noticket").unwrap(),
        DomainState::Running,
        &dumpxml("noticket", 2, 2 * 1024 * 1024, 22, "/tmp/noticket.img"),
    );
    let lc = lifecycle(driver.clone(), ok_digest()).with_state_disk_root(tmp.path().to_path_buf());
    assert_eq!(lc.readopt_running().await.unwrap(), 1);
    let vm = VmId::new("noticket").unwrap();
    assert!(
        lc.ticket_for_vm(&vm).is_none(),
        "an orphan must never be handed ticket-push / restart authority"
    );
    // It IS accounted for — refusing to count it is the other failure.
    assert_committed(&lc, 2, 2048);
}

#[tokio::test]
async fn an_orphan_whose_xml_cannot_be_read_is_not_adopted() {
    // The other side of the trade-off: we will count a VM we can measure,
    // but we will NOT invent numbers for one we cannot. A fabricated
    // figure in the capacity budget is worse than a logged gap.
    let driver = Arc::new(MockLibvirtDriver::new());
    let tmp = tempfile::tempdir().unwrap();
    // Seeded WITHOUT xml → `domain_xml` errors, like a domain that
    // vanished between the list and the dumpxml.
    driver.seed_domain(
        DomainId::new("hippius-tenant-noxml").unwrap(),
        DomainState::Running,
    );
    let lc = lifecycle(driver.clone(), ok_digest()).with_state_disk_root(tmp.path().to_path_buf());
    assert_eq!(lc.readopt_running().await.unwrap(), 0);
    assert!(lc.list().await.unwrap().is_empty());
    assert_committed(&lc, 0, 0);
}

#[tokio::test]
async fn a_shut_off_domain_is_not_orphan_adopted() {
    // A defined-but-down domain holds no host resources. Charging for it
    // would shrink the miner's usable capacity for nothing.
    let driver = Arc::new(MockLibvirtDriver::new());
    let tmp = tempfile::tempdir().unwrap();
    driver.seed_domain_xml(
        DomainId::new("hippius-tenant-down-1").unwrap(),
        DomainState::ShutOff,
        &dumpxml("down-1", 8, 16 * 1024 * 1024, 25, "/tmp/down-1.img"),
    );
    let lc = lifecycle(driver.clone(), ok_digest()).with_state_disk_root(tmp.path().to_path_buf());
    assert_eq!(lc.readopt_running().await.unwrap(), 0);
    assert_committed(&lc, 0, 0);
}

#[tokio::test]
async fn a_foreign_domain_is_never_adopted() {
    // Only `hippius-tenant-*` is ours. A co-tenant VM on the same
    // libvirtd must not be charged to the tenant budget or handed a CID.
    let driver = Arc::new(MockLibvirtDriver::new());
    let tmp = tempfile::tempdir().unwrap();
    driver.seed_domain_xml(
        DomainId::new("somebody-elses-vm").unwrap(),
        DomainState::Running,
        &dumpxml("x", 8, 16 * 1024 * 1024, 26, "/tmp/x.img"),
    );
    let lc = lifecycle(driver.clone(), ok_digest()).with_state_disk_root(tmp.path().to_path_buf());
    assert_eq!(lc.readopt_running().await.unwrap(), 0);
    assert_committed(&lc, 0, 0);
}

#[tokio::test]
async fn a_sidecar_that_understates_resources_is_corrected_from_libvirt() {
    // AMBIGUOUS RECORD. The sidecar is a plain file under the miner root;
    // the domain XML is what QEMU was started with. A record claiming
    // 1c/512MiB for a domain really running 8c/16384MiB would let the fit
    // gate admit launches the host cannot host. The LARGER of each is
    // charged — under-charging is the harmful direction.
    let driver = Arc::new(MockLibvirtDriver::new());
    let tmp = tempfile::tempdir().unwrap();
    driver.seed_domain_xml(
        DomainId::new("hippius-tenant-skew-1").unwrap(),
        DomainState::Running,
        &dumpxml("skew-1", 8, 16 * 1024 * 1024, 30, "/tmp/skew-1.img"),
    );
    write_sidecar(tmp.path(), "skew-1", 1, 512, 30, "/tmp/skew-1.img");

    let lc = lifecycle(driver.clone(), ok_digest()).with_state_disk_root(tmp.path().to_path_buf());
    assert_eq!(lc.readopt_running().await.unwrap(), 1);
    assert_committed(&lc, 8, 16384);
}

#[tokio::test]
async fn a_sidecar_with_a_stale_cid_reserves_the_live_one() {
    // A stale CID is a BILLING MISATTRIBUTION bug, not a cosmetic one:
    // reserve 5 while the guest really runs on 16, and 16 stays free for
    // the next launch — after which the running guest's relayed receipts
    // resolve to a DIFFERENT tenant's vm_id.
    let driver = Arc::new(MockLibvirtDriver::new());
    let tmp = tempfile::tempdir().unwrap();
    driver.seed_domain_xml(
        DomainId::new("hippius-tenant-cidskew").unwrap(),
        DomainState::Running,
        &dumpxml("cidskew", 2, 2 * 1024 * 1024, 16, "/tmp/cidskew.img"),
    );
    write_sidecar(tmp.path(), "cidskew", 2, 2048, 5, "/tmp/cidskew.img");

    let lc = lifecycle(driver.clone(), ok_digest()).with_state_disk_root(tmp.path().to_path_buf());
    assert_eq!(lc.readopt_running().await.unwrap(), 1);
    let vm = VmId::new("cidskew").unwrap();
    assert_eq!(
        lc.cid_allocator().vm_id_for_cid(16).unwrap(),
        Some(vm.clone()),
        "the LIVE cid must be the one reserved"
    );
    assert_eq!(
        lc.cid_allocator().vm_id_for_cid(5).unwrap(),
        None,
        "the stale cid must NOT be held"
    );
    assert_eq!(lc.cid_allocator().cid_for_vm(&vm).unwrap(), Some(16));
}

#[tokio::test]
async fn a_sidecar_with_a_stale_disk_path_tracks_the_live_volume() {
    // §24 `destroy` unlinks the handle's `luks_disk_path`. A stale path
    // would reclaim a file this domain never wrote and leak the one it
    // did — so the live `vda` source wins.
    let driver = Arc::new(MockLibvirtDriver::new());
    let tmp = tempfile::tempdir().unwrap();
    driver.seed_domain_xml(
        DomainId::new("hippius-tenant-diskskew").unwrap(),
        DomainState::Running,
        &dumpxml(
            "diskskew",
            2,
            2 * 1024 * 1024,
            31,
            "/var/lib/hippius-miner/overlay/diskskew.img",
        ),
    );
    write_sidecar(
        tmp.path(),
        "diskskew",
        2,
        2048,
        31,
        "/var/lib/hippius-miner/overlay/SOMEONE-ELSE.img",
    );

    let lc = lifecycle(driver.clone(), ok_digest()).with_state_disk_root(tmp.path().to_path_buf());
    assert_eq!(lc.readopt_running().await.unwrap(), 1);
    assert_eq!(
        lc.luks_disk_path_for(&VmId::new("diskskew").unwrap()),
        Some(PathBuf::from("/var/lib/hippius-miner/overlay/diskskew.img")),
    );
}

#[tokio::test]
async fn an_orphans_writable_volume_is_charged_to_the_disk_budget() {
    // The disk half of the same accounting: an orphan's overlay occupies
    // real bytes on the backing mount, so it must be charged or a later
    // launch's `check_disk_budget` fail-fast admits a VM that will not fit.
    let driver = Arc::new(MockLibvirtDriver::new());
    let tmp = tempfile::tempdir().unwrap();
    let overlay = tmp.path().join("orphan-disk.img");
    // 1 byte still occupies a whole GiB of budget — sizes round UP.
    std::fs::write(&overlay, b"x").unwrap();
    driver.seed_domain_xml(
        DomainId::new("hippius-tenant-odisk").unwrap(),
        DomainState::Running,
        &dumpxml("odisk", 1, 1024 * 1024, 32, overlay.to_str().unwrap()),
    );
    let lc = CvmLifecycle::new(
        driver.clone(),
        ok_digest(),
        HostResources {
            total_cpus: 16,
            total_memory_mb: 65536,
            total_disk_gb: 1,
        },
    )
    .with_state_disk_root(tmp.path().to_path_buf());
    assert!(
        lc.check_disk_budget(1).is_ok(),
        "the 1 GiB budget is free before adoption"
    );
    assert_eq!(lc.readopt_running().await.unwrap(), 1);
    assert!(
        matches!(
            lc.check_disk_budget(1),
            Err(MinerAgentError::InsufficientDisk)
        ),
        "the orphan's overlay must consume the disk budget"
    );
}

#[tokio::test]
async fn a_snapshot_adopted_vm_is_not_re_adopted_as_an_orphan() {
    // The two passes must compose: a VM covered by its sidecar is
    // adopted ONCE, keeps its ticket, and is not charged twice by the
    // libvirt sweep that follows.
    let driver = Arc::new(MockLibvirtDriver::new());
    let tmp = tempfile::tempdir().unwrap();
    let lc1 = lifecycle(driver.clone(), ok_digest()).with_state_disk_root(tmp.path().to_path_buf());
    let vm = lc1.launch(order("both-1")).await.unwrap();

    let lc2 = lifecycle(driver.clone(), ok_digest()).with_state_disk_root(tmp.path().to_path_buf());
    assert_eq!(
        lc2.readopt_running().await.unwrap(),
        1,
        "adopted once, not once per pass"
    );
    assert_committed(&lc2, 2, 2048);
    assert!(
        lc2.ticket_for_vm(&vm).is_some(),
        "the sidecar's ticket must survive the orphan sweep"
    );
}

// ── PR-7 diskless blackbox host-attestor (Infra profile) ─────────────

/// The mock digest computer yields a fixed all-zero 48-byte digest, so
/// the matching Infra measurement pin is 96 hex zeros.
fn infra_pin_ok() -> String {
    "00".repeat(48)
}

fn infra_order(pin_hex: &str) -> hippius_miner_agent::InfraLaunchOrder {
    seed_snp_probe();
    hippius_miner_agent::InfraLaunchOrder {
        ovmf_path: PathBuf::from("/var/lib/hippius-miner/ovmf.fd"),
        kernel_path: PathBuf::from("/var/lib/hippius-miner/attestor-vmlinuz"),
        initrd_path: PathBuf::from("/var/lib/hippius-miner/attestor-initrd"),
        cmdline: "quiet panic=0 console=ttyS0".to_string(),
        expected_measurement_hex: pin_hex.to_string(),
    }
}

/// A lifecycle with an explicit tenant cpu budget (for the capacity
/// carve-out test).
fn lifecycle_with_cpu_budget(
    driver: Arc<MockLibvirtDriver>,
    digest: Arc<MockLaunchDigest>,
    total_cpus: u32,
) -> CvmLifecycle {
    seed_snp_probe();
    CvmLifecycle::new_with_poll(
        driver,
        digest,
        HostResources {
            total_cpus,
            total_memory_mb: 65536,
            total_disk_gb: 0,
        },
        Duration::from_millis(1),
        5,
    )
    .skip_state_disk_provision_for_tests()
}

#[tokio::test]
async fn launch_infra_runs_and_is_excluded_from_tenant_enumeration() {
    let lc = lifecycle(Arc::new(MockLibvirtDriver::new()), ok_digest());
    let vm = lc.launch_infra(infra_order(&infra_pin_ok())).await.unwrap();
    assert_eq!(vm.as_str(), hippius_miner_agent::INFRA_VM_ID);
    assert_eq!(lc.query(&vm).await.unwrap(), CvmPhase::Running);
    // `list()` (ops/debug) sees the infra domain …
    assert_eq!(lc.list().await.unwrap().len(), 1);
    // … but `list_tenants()` (heartbeat / billing) does NOT.
    assert!(
        lc.list_tenants().await.unwrap().is_empty(),
        "infra must be filtered from the tenant enumeration"
    );
    assert!(lc.infra_is_running().await);
}

#[tokio::test]
async fn launch_infra_fails_closed_on_measurement_pin_mismatch() {
    let driver = Arc::new(MockLibvirtDriver::new());
    let lc = lifecycle(driver.clone(), ok_digest());
    // A pin that does not match the computed digest → refused BEFORE any
    // virsh call. `ff…` != the mock's `00…`.
    let bad = "ff".repeat(48);
    assert!(matches!(
        lc.launch_infra(infra_order(&bad)).await,
        Err(MinerAgentError::LaunchDigest("infra-pin-mismatch"))
    ));
    // Fail-closed: no domain defined, nothing tracked.
    assert_eq!(driver.defined_count().unwrap(), 0);
    assert_eq!(driver.destroy_count(), 0);
    assert!(lc.list().await.unwrap().is_empty());
}

#[tokio::test]
async fn launch_infra_rejects_a_malformed_pin() {
    let lc = lifecycle(Arc::new(MockLibvirtDriver::new()), ok_digest());
    assert!(matches!(
        lc.launch_infra(infra_order("not-hex")).await,
        Err(MinerAgentError::LaunchDigest("infra-pin-format"))
    ));
}

#[tokio::test]
async fn launch_infra_is_a_singleton() {
    let lc = lifecycle(Arc::new(MockLibvirtDriver::new()), ok_digest());
    lc.launch_infra(infra_order(&infra_pin_ok())).await.unwrap();
    // A second launch of the still-live host-attestor is refused.
    assert!(matches!(
        lc.launch_infra(infra_order(&infra_pin_ok())).await,
        Err(MinerAgentError::AlreadyLaunched)
    ));
}

#[tokio::test]
async fn infra_is_not_charged_against_the_tenant_cpu_budget() {
    // Tenant budget = exactly 2 vCPUs. The infra domain (1 vCPU) must NOT
    // consume any of it, so a full 2-vCPU tenant still launches after.
    let lc = lifecycle_with_cpu_budget(Arc::new(MockLibvirtDriver::new()), ok_digest(), 2);
    lc.launch_infra(infra_order(&infra_pin_ok())).await.unwrap();
    // `order()` builds a 2-vCPU tenant; it fits the whole budget because
    // infra's vCPU was carved out separately.
    let vm = lc.launch(order("cvm-1")).await.unwrap();
    assert_eq!(lc.query(&vm).await.unwrap(), CvmPhase::Running);
    // Both are tracked; only the tenant is tenant-visible.
    assert_eq!(lc.list().await.unwrap().len(), 2);
    assert_eq!(lc.list_tenants().await.unwrap().len(), 1);
}

#[tokio::test]
async fn launch_infra_allocates_a_vsock_cid() {
    // PR-10b (S1): the Infra host-attestor now carries a real vsock CID so
    // the diskless guest can dial the host. The lifecycle allocates it from
    // the shared allocator exactly like a tenant CVM.
    let lc = lifecycle(Arc::new(MockLibvirtDriver::new()), ok_digest());
    let vm = lc.launch_infra(infra_order(&infra_pin_ok())).await.unwrap();
    let cid = lc
        .cid_allocator()
        .cid_for_vm(&vm)
        .unwrap()
        .expect("infra must have an allocated CID");
    // A real guest CID (>= MIN_GUEST_CID = 3), and the reverse map resolves.
    assert!(cid >= 3, "cid must be a real guest CID, got {cid}");
    assert_eq!(lc.cid_allocator().vm_id_for_cid(cid).unwrap(), Some(vm));
}

#[tokio::test]
async fn readopt_re_adopts_the_infra_domain_and_reserves_its_cid() {
    // The infra domain must survive an agent restart: re-adopted, marked
    // infra, AND its vsock CID re-reserved (PR-10b, S1) so the relay routes
    // correctly to the same guest.
    let driver = Arc::new(MockLibvirtDriver::new());
    let tmp = tempfile::tempdir().unwrap();
    let lc1 = lifecycle(driver.clone(), ok_digest()).with_state_disk_root(tmp.path().to_path_buf());
    let vm = lc1
        .launch_infra(infra_order(&infra_pin_ok()))
        .await
        .unwrap();
    // Infra allocated a real CID.
    let cid = lc1
        .cid_allocator()
        .cid_for_vm(&vm)
        .unwrap()
        .expect("infra must have an allocated CID");

    // "Restart": fresh lifecycle, same driver (domain still Running) +
    // same state root.
    let lc2 = lifecycle(driver.clone(), ok_digest()).with_state_disk_root(tmp.path().to_path_buf());
    let n = lc2.readopt_running().await.unwrap();
    assert_eq!(n, 1);
    // Re-adopted as infra → excluded from tenant enumeration…
    assert_eq!(lc2.list().await.unwrap().len(), 1);
    assert!(lc2.list_tenants().await.unwrap().is_empty());
    // …and the SAME CID is reserved in the fresh allocator.
    assert_eq!(lc2.cid_allocator().cid_for_vm(&vm).unwrap(), Some(cid));
    assert_eq!(lc2.cid_allocator().vm_id_for_cid(cid).unwrap(), Some(vm));
    assert!(lc2.infra_is_running().await);
}

#[tokio::test]
async fn a_crashed_infra_domain_reads_not_running() {
    // The supervisor relies on `infra_is_running` reflecting the REAL
    // libvirt state — a crashed attestor must read false so it relaunches.
    let driver = Arc::new(MockLibvirtDriver::new());
    let lc = lifecycle(driver.clone(), ok_digest());
    lc.launch_infra(infra_order(&infra_pin_ok())).await.unwrap();
    assert!(lc.infra_is_running().await);
    // The domain crashes out-of-band (handle still says Running).
    driver.force_all_to_state(DomainState::Crashed).unwrap();
    assert!(!lc.infra_is_running().await);
}

/// A driver whose every call fails — models libvirt being genuinely
/// unreachable (e.g. `libvirtd` down / socket gone), as opposed to a
/// domain simply not being defined. Used only to exercise
/// `tenant_domain_liveness`'s `Unknown` fallback: `query_domain_state`
/// errors AND the `list_domains` fallback also errors.
struct AlwaysUnreachableDriver;

#[async_trait]
impl LibvirtDriver for AlwaysUnreachableDriver {
    async fn define_domain(&self, _xml: &str) -> Result<DomainId> {
        Err(MinerAgentError::LibvirtDriver("define"))
    }
    async fn create_domain(&self, _id: &DomainId) -> Result<()> {
        Err(MinerAgentError::LibvirtDriver("create"))
    }
    async fn destroy_domain(&self, _id: &DomainId, _graceful: bool) -> Result<()> {
        Err(MinerAgentError::LibvirtDriver("destroy"))
    }
    async fn undefine_domain(&self, _id: &DomainId) -> Result<()> {
        Err(MinerAgentError::LibvirtDriver("undefine"))
    }
    async fn query_domain_state(&self, _id: &DomainId) -> Result<DomainState> {
        Err(MinerAgentError::LibvirtDriver("domstate"))
    }
    async fn list_domains(&self) -> Result<Vec<(DomainId, DomainState)>> {
        Err(MinerAgentError::LibvirtDriver("list"))
    }
    async fn domain_xml(&self, _id: &DomainId) -> Result<String> {
        Err(MinerAgentError::LibvirtDriver("dumpxml"))
    }
}

/// `query_domain_state` reports a live state ⇒ `Live` directly, no
/// `list_domains` fallback needed.
#[tokio::test]
async fn tenant_domain_liveness_running_domain_is_live() {
    let driver = Arc::new(MockLibvirtDriver::new());
    let lc = lifecycle(driver.clone(), ok_digest());
    let vm = VmId::new("dl-live-1").unwrap();
    let xml = format!(
        "<domain><name>hippius-tenant-{}</name></domain>",
        vm.as_str()
    );
    let id = driver.define_domain(&xml).await.unwrap();
    driver.create_domain(&id).await.unwrap(); // MockLibvirtDriver defaults to Running.
    assert_eq!(lc.tenant_domain_liveness(&vm).await, DomainLiveness::Live);
}

/// `query_domain_state` reports `ShutOff` ⇒ `Down` directly.
#[tokio::test]
async fn tenant_domain_liveness_shut_off_domain_is_down() {
    let driver = Arc::new(MockLibvirtDriver::new());
    let lc = lifecycle(driver.clone(), ok_digest());
    let vm = VmId::new("dl-down-1").unwrap();
    let xml = format!(
        "<domain><name>hippius-tenant-{}</name></domain>",
        vm.as_str()
    );
    // `define_domain` alone leaves the mock domain at `ShutOff` — no
    // `create_domain` call.
    driver.define_domain(&xml).await.unwrap();
    assert_eq!(lc.tenant_domain_liveness(&vm).await, DomainLiveness::Down);
}

/// The domain was never defined: `query_domain_state` errors
/// (`domstate`), and the `list_domains` fallback succeeds but the
/// domain is absent from it ⇒ genuinely down (undefined), not unknown.
#[tokio::test]
async fn tenant_domain_liveness_undefined_domain_is_down() {
    let driver = Arc::new(MockLibvirtDriver::new());
    let lc = lifecycle(driver, ok_digest());
    let vm = VmId::new("dl-down-2").unwrap();
    assert_eq!(lc.tenant_domain_liveness(&vm).await, DomainLiveness::Down);
}

/// `query_domain_state` errors AND the `list_domains` fallback ALSO
/// errors — libvirt itself is unreachable, not merely "domain
/// missing". Must surface as `Unknown`, never folded into `Down`.
#[tokio::test]
async fn tenant_domain_liveness_unreachable_libvirt_is_unknown() {
    let lc = CvmLifecycle::new_with_poll(
        Arc::new(AlwaysUnreachableDriver),
        ok_digest(),
        HostResources {
            total_cpus: 16,
            total_memory_mb: 65536,
            total_disk_gb: 0,
        },
        Duration::from_millis(1),
        5,
    )
    .skip_state_disk_provision_for_tests();
    let vm = VmId::new("dl-unknown-1").unwrap();
    assert_eq!(
        lc.tenant_domain_liveness(&vm).await,
        DomainLiveness::Unknown
    );
}

/// A driver that records, at the instant libvirt is asked to destroy a
/// domain, whether the reboot-watcher would be allowed to restart it.
struct RestartProbeDriver {
    inner: Arc<MockLibvirtDriver>,
    lifecycle: std::sync::OnceLock<std::sync::Weak<CvmLifecycle>>,
    vm: VmId,
    seen: Mutex<Vec<bool>>,
}

#[async_trait]
impl LibvirtDriver for RestartProbeDriver {
    async fn define_domain(&self, xml: &str) -> Result<DomainId> {
        self.inner.define_domain(xml).await
    }
    async fn create_domain(&self, id: &DomainId) -> Result<()> {
        self.inner.create_domain(id).await
    }
    async fn destroy_domain(&self, id: &DomainId, graceful: bool) -> Result<()> {
        if let Some(lc) = self.lifecycle.get().and_then(std::sync::Weak::upgrade) {
            self.seen
                .lock()
                .unwrap()
                .push(lc.restart_eligible(&self.vm));
        }
        self.inner.destroy_domain(id, graceful).await
    }
    async fn undefine_domain(&self, id: &DomainId) -> Result<()> {
        self.inner.undefine_domain(id).await
    }
    async fn query_domain_state(&self, id: &DomainId) -> Result<DomainState> {
        self.inner.query_domain_state(id).await
    }
    async fn list_domains(&self) -> Result<Vec<(DomainId, DomainState)>> {
        self.inner.list_domains().await
    }
    async fn domain_xml(&self, id: &DomainId) -> Result<String> {
        self.inner.domain_xml(id).await
    }
}

#[tokio::test]
async fn the_reboot_watcher_may_not_restart_a_domain_the_agent_is_stopping() {
    // RESURRECTION. `stop` (and so a §24 force-stop) produces a libvirt
    // `Stopped` event while the handle still exists. The watcher used to
    // gate a restart on "has a cached ticket" alone, so it could race the
    // stop and `virsh start` the domain being torn down. It may restart
    // only a CVM that is `Running` — one whose QEMU exited on its own.
    seed_snp_probe();
    let vm = VmId::new("resurrect-1").unwrap();
    let driver = Arc::new(RestartProbeDriver {
        inner: Arc::new(MockLibvirtDriver::new()),
        lifecycle: std::sync::OnceLock::new(),
        vm: vm.clone(),
        seen: Mutex::new(Vec::new()),
    });
    let lc = Arc::new(
        CvmLifecycle::new_with_poll(
            driver.clone(),
            ok_digest(),
            HostResources {
                total_cpus: 16,
                total_memory_mb: 65536,
                total_disk_gb: 0,
            },
            Duration::from_millis(1),
            5,
        )
        .skip_state_disk_provision_for_tests(),
    );
    driver.lifecycle.set(Arc::downgrade(&lc)).unwrap();

    assert_eq!(lc.launch(order("resurrect-1")).await.unwrap(), vm);
    assert!(
        lc.restart_eligible(&vm),
        "a running CVM rebooted by its guest must be restartable"
    );

    lc.stop(&vm, false).await.unwrap();

    assert_eq!(
        *driver.seen.lock().unwrap(),
        vec![false],
        "while the agent destroys the domain, the watcher must refuse to restart it"
    );
    assert!(!lc.restart_eligible(&vm), "a stopped VM is never restarted");
}

// ── Re-adoption with an unreadable domain XML: the CID is held UNVERIFIED ──
//
// The sidecar is miner-local and can be stale; the live XML is the only
// ground truth for the vsock CID. When `dumpxml` fails at re-adoption the
// recorded CID is held (nobody else gets it) but is NOT an identity: no
// ticket push, no relay, until the live XML confirms, re-keys or drops it.

const UNVERIFIED_TICKET: [u8; 4] = [0xde, 0xad, 0xbe, 0xef];

/// Restart onto a sidecar claiming `recorded_cid` for a Running domain
/// whose XML cannot be read.
async fn readopt_unverified(
    vm: &str,
    recorded_cid: u32,
) -> (Arc<MockLibvirtDriver>, CvmLifecycle, tempfile::TempDir) {
    let driver = Arc::new(MockLibvirtDriver::new());
    let tmp = tempfile::tempdir().unwrap();
    write_sidecar(
        tmp.path(),
        vm,
        2,
        2048,
        recorded_cid,
        "/var/lib/hippius-miner/x.img",
    );
    driver.seed_domain(
        DomainId::new(&format!("hippius-tenant-{vm}")).unwrap(),
        DomainState::Running,
    );
    let lc = lifecycle(driver.clone(), ok_digest()).with_state_disk_root(tmp.path().to_path_buf());
    assert_eq!(
        lc.readopt_running().await.unwrap(),
        1,
        "still re-adopted (capacity counts)"
    );
    (driver, lc, tmp)
}

fn far_future() -> std::time::Instant {
    std::time::Instant::now() + Duration::from_secs(24 * 3600)
}

#[tokio::test]
async fn an_unreadable_xml_holds_the_recorded_cid_unverified() {
    let (_driver, lc, _tmp) = readopt_unverified("uv-1", 7).await;
    let vm = VmId::new("uv-1").unwrap();
    let alloc = lc.cid_allocator();
    assert_eq!(alloc.owner_of(7).unwrap(), CidOwner::Unverified(vm.clone()));
    assert_eq!(
        alloc.vm_id_for_cid(7).unwrap(),
        None,
        "the relay must not attribute frames on an unconfirmed record"
    );
    assert_eq!(
        lc.ticket_push_target(&vm, &UNVERIFIED_TICKET),
        (TicketPushState::Wait, 7),
        "the ticket must wait — not be delivered, not be given up on"
    );
    assert!(
        lc.restart_eligible(&vm),
        "an in-guest reboot must still be restarted while the cid is unverified"
    );
    assert_eq!(lc.unverified_cid_count(), 1);
}

#[tokio::test]
async fn the_live_xml_confirming_the_cid_verifies_it() {
    let (driver, lc, _tmp) = readopt_unverified("uv-2", 7).await;
    let vm = VmId::new("uv-2").unwrap();
    // A failed retry keeps it pending.
    assert_eq!(
        lc.verify_pending_cids(far_future()).await,
        vec![(vm.clone(), CidVerdict::Pending)]
    );
    assert_eq!(
        lc.ticket_push_target(&vm, &UNVERIFIED_TICKET).0,
        TicketPushState::Wait
    );

    driver.seed_domain_xml(
        DomainId::new("hippius-tenant-uv-2").unwrap(),
        DomainState::Running,
        &dumpxml("uv-2", 2, 2048 * 1024, 7, "/var/lib/hippius-miner/x.img"),
    );
    // Past the retry's backoff.
    assert_eq!(
        lc.verify_pending_cids(far_future() + CID_VERIFY_MAX_BACKOFF)
            .await,
        vec![(vm.clone(), CidVerdict::Verified)]
    );
    assert_eq!(
        lc.cid_allocator().vm_id_for_cid(7).unwrap(),
        Some(vm.clone())
    );
    assert_eq!(
        lc.ticket_push_target(&vm, &UNVERIFIED_TICKET),
        (TicketPushState::Deliver, 7)
    );
    assert_eq!(lc.unverified_cid_count(), 0);
}

#[tokio::test]
async fn the_live_xml_showing_another_cid_rekeys_to_it() {
    let (driver, lc, _tmp) = readopt_unverified("uv-3", 7).await;
    let vm = VmId::new("uv-3").unwrap();
    driver.seed_domain_xml(
        DomainId::new("hippius-tenant-uv-3").unwrap(),
        DomainState::Running,
        &dumpxml("uv-3", 2, 2048 * 1024, 9, "/var/lib/hippius-miner/x.img"),
    );
    assert_eq!(
        lc.verify_pending_cids(far_future()).await,
        vec![(vm.clone(), CidVerdict::Rekeyed)]
    );
    let alloc = lc.cid_allocator();
    assert_eq!(alloc.vm_id_for_cid(9).unwrap(), Some(vm.clone()));
    assert_eq!(
        alloc.owner_of(7).unwrap(),
        CidOwner::Unknown,
        "the stale cid is freed"
    );
    assert_eq!(
        lc.ticket_push_target(&vm, &UNVERIFIED_TICKET),
        (TicketPushState::Deliver, 9),
        "the ticket goes to the LIVE cid"
    );
}

#[tokio::test]
async fn a_gone_domain_drops_the_unverified_handle() {
    let (driver, lc, _tmp) = readopt_unverified("uv-4", 7).await;
    let vm = VmId::new("uv-4").unwrap();
    driver
        .undefine_domain(&DomainId::new("hippius-tenant-uv-4").unwrap())
        .await
        .unwrap();
    assert_eq!(
        lc.verify_pending_cids(far_future()).await,
        vec![(vm.clone(), CidVerdict::Dropped)]
    );
    assert!(lc.list().await.unwrap().is_empty());
    assert_eq!(lc.cid_allocator().owner_of(7).unwrap(), CidOwner::Unknown);
    assert_eq!(
        lc.ticket_push_target(&vm, &UNVERIFIED_TICKET).0,
        TicketPushState::Abort
    );
    assert_eq!(
        lc.readopt_running().await.unwrap(),
        0,
        "the sidecar went with it"
    );
}

#[tokio::test]
async fn a_shut_off_domain_is_not_gone() {
    // A guest `reboot` passes through shut-off before the reboot-watcher
    // restarts it. Dropping the handle there would strand that restart.
    let (driver, lc, _tmp) = readopt_unverified("uv-5", 7).await;
    let vm = VmId::new("uv-5").unwrap();
    driver.force_all_to_state(DomainState::ShutOff).unwrap();
    assert_eq!(
        lc.verify_pending_cids(far_future()).await,
        vec![(vm.clone(), CidVerdict::Pending)]
    );
    assert!(lc.restart_eligible(&vm));
    assert_eq!(
        lc.cid_allocator().owner_of(7).unwrap(),
        CidOwner::Unverified(vm)
    );
}

#[tokio::test]
async fn a_pending_check_is_not_retried_before_its_backoff() {
    let (_driver, lc, _tmp) = readopt_unverified("uv-6", 7).await;
    let now = std::time::Instant::now() + Duration::from_secs(1);
    assert_eq!(lc.verify_pending_cids(now).await.len(), 1);
    assert!(
        lc.verify_pending_cids(now).await.is_empty(),
        "retried inside its backoff"
    );
    assert_eq!(
        lc.verify_pending_cids(now + CID_VERIFY_BASE_BACKOFF)
            .await
            .len(),
        1
    );
}

/// A driver whose `domain_xml`, once armed, reads the XML at call time and
/// then PARKS before returning it — so a test can stop and relaunch the
/// same `vm_id` while a verification attempt holds a now-stale answer.
struct ParkedXmlDriver {
    inner: Arc<MockLibvirtDriver>,
    armed: std::sync::atomic::AtomicBool,
    entered: Notify,
    release: Notify,
    /// Strip `<uuid>` from the parked answer — models a document the
    /// UUID check cannot catch, so only the generation/handle check can.
    strip_uuid: bool,
}

#[async_trait]
impl LibvirtDriver for ParkedXmlDriver {
    async fn define_domain(&self, xml: &str) -> Result<DomainId> {
        self.inner.define_domain(xml).await
    }
    async fn create_domain(&self, id: &DomainId) -> Result<()> {
        self.inner.create_domain(id).await
    }
    async fn destroy_domain(&self, id: &DomainId, graceful: bool) -> Result<()> {
        self.inner.destroy_domain(id, graceful).await
    }
    async fn undefine_domain(&self, id: &DomainId) -> Result<()> {
        self.inner.undefine_domain(id).await
    }
    async fn query_domain_state(&self, id: &DomainId) -> Result<DomainState> {
        self.inner.query_domain_state(id).await
    }
    async fn list_domains(&self) -> Result<Vec<(DomainId, DomainState)>> {
        self.inner.list_domains().await
    }
    async fn domain_xml(&self, id: &DomainId) -> Result<String> {
        let answer = self.inner.domain_xml(id).await;
        if self.armed.swap(false, std::sync::atomic::Ordering::SeqCst) {
            self.entered.notify_one();
            self.release.notified().await;
        }
        let xml = answer?;
        Ok(if self.strip_uuid {
            xml.lines()
                .filter(|l| !l.contains("<uuid>"))
                .collect::<Vec<_>>()
                .join("\n")
        } else {
            xml
        })
    }
}

/// Verification reads the OLD incarnation's XML (cid 9), parks; meanwhile
/// the VM is stopped and relaunched under the same `vm_id`. The stale
/// answer must not touch the new handle or its cid.
async fn stale_verification_meets_a_relaunch(strip_uuid: bool) {
    let inner = Arc::new(MockLibvirtDriver::new());
    let driver = Arc::new(ParkedXmlDriver {
        inner: inner.clone(),
        armed: std::sync::atomic::AtomicBool::new(false),
        entered: Notify::new(),
        release: Notify::new(),
        strip_uuid,
    });
    let tmp = tempfile::tempdir().unwrap();
    write_sidecar(
        tmp.path(),
        "uv-r",
        2,
        2048,
        7,
        "/var/lib/hippius-miner/x.img",
    );
    let domain = DomainId::new("hippius-tenant-uv-r").unwrap();
    inner.seed_domain(domain.clone(), DomainState::Running);
    seed_snp_probe();
    let lc = Arc::new(
        CvmLifecycle::new_with_poll(
            driver.clone(),
            ok_digest(),
            HostResources {
                total_cpus: 16,
                total_memory_mb: 65536,
                total_disk_gb: 0,
            },
            Duration::from_millis(1),
            5,
        )
        .skip_state_disk_provision_for_tests()
        .with_state_disk_root(tmp.path().to_path_buf()),
    );
    assert_eq!(lc.readopt_running().await.unwrap(), 1);
    let vm = VmId::new("uv-r").unwrap();

    inner.seed_domain_xml(
        domain,
        DomainState::Running,
        &dumpxml("uv-r", 2, 2048 * 1024, 9, "/var/lib/hippius-miner/x.img"),
    );
    driver
        .armed
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let verifying = {
        let lc = Arc::clone(&lc);
        tokio::spawn(async move { lc.verify_pending_cids(far_future()).await })
    };
    driver.entered.notified().await;

    lc.stop(&vm, false).await.unwrap();
    lc.launch(order("uv-r")).await.unwrap();
    let alloc = lc.cid_allocator();
    let fresh = alloc.cid_for_vm(&vm).unwrap().unwrap();
    assert_ne!(fresh, 9);

    driver.release.notify_one();
    let verdicts = verifying.await.unwrap();
    assert_eq!(
        verdicts,
        vec![(vm.clone(), CidVerdict::Pending)],
        "a stale answer must act on nothing"
    );
    assert_eq!(
        alloc.cid_for_vm(&vm).unwrap(),
        Some(fresh),
        "the relaunch's cid was moved"
    );
    assert_eq!(alloc.vm_id_for_cid(fresh).unwrap(), Some(vm.clone()));
    assert_eq!(alloc.owner_of(9).unwrap(), CidOwner::Unknown);
    assert_eq!(
        lc.list().await.unwrap().len(),
        1,
        "the relaunch's handle was dropped"
    );
}

#[tokio::test]
async fn a_stale_verification_never_touches_a_relaunch_of_the_same_vm() {
    stale_verification_meets_a_relaunch(false).await;
}

#[tokio::test]
async fn a_stale_verification_without_a_uuid_is_caught_by_the_check_generation() {
    stale_verification_meets_a_relaunch(true).await;
}

#[tokio::test]
async fn a_shut_off_domains_inactive_xml_proves_nothing() {
    // `dumpxml` of a shut-off domain is its INACTIVE config: no QEMU holds
    // that cid, so it confirms nothing — even when it names the held cid.
    let (driver, lc, _tmp) = readopt_unverified("uv-7", 7).await;
    let vm = VmId::new("uv-7").unwrap();
    driver.seed_domain_xml(
        DomainId::new("hippius-tenant-uv-7").unwrap(),
        DomainState::ShutOff,
        &dumpxml("uv-7", 2, 2048 * 1024, 7, "/var/lib/hippius-miner/x.img"),
    );
    assert_eq!(
        lc.verify_pending_cids(far_future()).await,
        vec![(vm.clone(), CidVerdict::Pending)]
    );
    assert_eq!(
        lc.cid_allocator().owner_of(7).unwrap(),
        CidOwner::Unverified(vm)
    );
}

/// Parks the Nth `list_domains` call after arming, handing back the answer
/// it read BEFORE parking — a stale "not defined" verdict in flight.
struct ParkedListDriver {
    inner: Arc<MockLibvirtDriver>,
    countdown: std::sync::atomic::AtomicUsize,
    entered: Notify,
    release: Notify,
}

#[async_trait]
impl LibvirtDriver for ParkedListDriver {
    async fn define_domain(&self, xml: &str) -> Result<DomainId> {
        self.inner.define_domain(xml).await
    }
    async fn create_domain(&self, id: &DomainId) -> Result<()> {
        self.inner.create_domain(id).await
    }
    async fn destroy_domain(&self, id: &DomainId, graceful: bool) -> Result<()> {
        self.inner.destroy_domain(id, graceful).await
    }
    async fn undefine_domain(&self, id: &DomainId) -> Result<()> {
        self.inner.undefine_domain(id).await
    }
    async fn query_domain_state(&self, id: &DomainId) -> Result<DomainState> {
        self.inner.query_domain_state(id).await
    }
    async fn list_domains(&self) -> Result<Vec<(DomainId, DomainState)>> {
        let answer = self.inner.list_domains().await;
        let park = self
            .countdown
            .fetch_update(
                std::sync::atomic::Ordering::SeqCst,
                std::sync::atomic::Ordering::SeqCst,
                |n| n.checked_sub(1),
            )
            .is_ok_and(|n| n == 1);
        if park {
            self.entered.notify_one();
            self.release.notified().await;
        }
        answer
    }
    async fn domain_xml(&self, id: &DomainId) -> Result<String> {
        self.inner.domain_xml(id).await
    }
}

#[tokio::test]
async fn a_stale_gone_verdict_never_drops_a_relaunch_of_the_same_vm() {
    // Verification learns "domain not defined" and parks before acting.
    // Meanwhile the vm_id is relaunched (the launch reclaims the stale
    // re-adopted handle). The stale verdict must not drop the new VM.
    let inner = Arc::new(MockLibvirtDriver::new());
    let driver = Arc::new(ParkedListDriver {
        inner: inner.clone(),
        countdown: std::sync::atomic::AtomicUsize::new(0),
        entered: Notify::new(),
        release: Notify::new(),
    });
    let tmp = tempfile::tempdir().unwrap();
    write_sidecar(
        tmp.path(),
        "uv-d",
        2,
        2048,
        7,
        "/var/lib/hippius-miner/x.img",
    );
    let domain = DomainId::new("hippius-tenant-uv-d").unwrap();
    inner.seed_domain(domain.clone(), DomainState::Running);
    seed_snp_probe();
    let lc = Arc::new(
        CvmLifecycle::new_with_poll(
            driver.clone(),
            ok_digest(),
            HostResources {
                total_cpus: 16,
                total_memory_mb: 65536,
                total_disk_gb: 0,
            },
            Duration::from_millis(1),
            5,
        )
        .skip_state_disk_provision_for_tests()
        .with_state_disk_root(tmp.path().to_path_buf()),
    );
    assert_eq!(lc.readopt_running().await.unwrap(), 1);
    let vm = VmId::new("uv-d").unwrap();
    inner.undefine_domain(&domain).await.unwrap();

    // domain_liveness lists once (#1), tenant_domain_defined lists (#2) → park.
    driver
        .countdown
        .store(2, std::sync::atomic::Ordering::SeqCst);
    let verifying = {
        let lc = Arc::clone(&lc);
        tokio::spawn(async move { lc.verify_pending_cids(far_future()).await })
    };
    driver.entered.notified().await;

    lc.launch(order("uv-d")).await.unwrap();
    let cid = lc.cid_allocator().cid_for_vm(&vm).unwrap().unwrap();

    driver.release.notify_one();
    assert_eq!(
        verifying.await.unwrap(),
        vec![(vm.clone(), CidVerdict::Pending)],
        "a stale verdict must act on nothing"
    );
    assert_eq!(
        lc.list().await.unwrap().len(),
        1,
        "the relaunch was dropped"
    );
    assert_eq!(
        lc.cid_allocator().vm_id_for_cid(cid).unwrap(),
        Some(vm.clone())
    );
    assert_eq!(
        lc.ticket_push_target(&vm, &ticket_medium()),
        (TicketPushState::Deliver, cid)
    );
    assert_eq!(lc.unverified_cid_count(), 0);
}

#[tokio::test]
async fn a_same_name_domain_with_another_uuid_does_not_verify_the_cid() {
    // The XML must be the RECORDED incarnation's: a same-name domain with
    // a different UUID is another guest, and its cid proves nothing.
    let driver = Arc::new(MockLibvirtDriver::new());
    let tmp = tempfile::tempdir().unwrap();
    write_sidecar(
        tmp.path(),
        "uv-u",
        2,
        2048,
        7,
        "/var/lib/hippius-miner/x.img",
    );
    let other = dumpxml("uv-u", 2, 2048 * 1024, 7, "/var/lib/hippius-miner/x.img").replace(
        "11111111-2222-4333-8444-555555555555",
        "99999999-2222-4333-8444-555555555555",
    );
    driver.seed_domain_xml(
        DomainId::new("hippius-tenant-uv-u").unwrap(),
        DomainState::Running,
        &other,
    );
    let lc = lifecycle(driver.clone(), ok_digest()).with_state_disk_root(tmp.path().to_path_buf());
    assert_eq!(lc.readopt_running().await.unwrap(), 1);
    let vm = VmId::new("uv-u").unwrap();
    assert_eq!(
        lc.cid_allocator().owner_of(7).unwrap(),
        CidOwner::Unverified(vm.clone())
    );
    // …and the background check agrees.
    assert_eq!(
        lc.verify_pending_cids(far_future()).await,
        vec![(vm, CidVerdict::Pending)]
    );
}

#[tokio::test]
async fn a_matching_live_xml_at_readoption_verifies_immediately() {
    let driver = Arc::new(MockLibvirtDriver::new());
    let tmp = tempfile::tempdir().unwrap();
    write_sidecar(
        tmp.path(),
        "uv-m",
        2,
        2048,
        7,
        "/var/lib/hippius-miner/x.img",
    );
    driver.seed_domain_xml(
        DomainId::new("hippius-tenant-uv-m").unwrap(),
        DomainState::Running,
        &dumpxml("uv-m", 2, 2048 * 1024, 7, "/var/lib/hippius-miner/x.img"),
    );
    let lc = lifecycle(driver.clone(), ok_digest()).with_state_disk_root(tmp.path().to_path_buf());
    assert_eq!(lc.readopt_running().await.unwrap(), 1);
    let vm = VmId::new("uv-m").unwrap();
    assert_eq!(lc.cid_allocator().vm_id_for_cid(7).unwrap(), Some(vm));
    assert_eq!(lc.unverified_cid_count(), 0);
}

#[tokio::test]
async fn a_domain_that_stops_during_the_xml_read_does_not_verify_the_cid() {
    // Live before the dump, shut off after it: the XML may be the inactive
    // config, so it proves nothing about the kernel's cid.
    let inner = Arc::new(MockLibvirtDriver::new());
    let driver = Arc::new(ParkedXmlDriver {
        inner: inner.clone(),
        armed: std::sync::atomic::AtomicBool::new(true),
        entered: Notify::new(),
        release: Notify::new(),
        strip_uuid: false,
    });
    let tmp = tempfile::tempdir().unwrap();
    write_sidecar(
        tmp.path(),
        "uv-s",
        2,
        2048,
        7,
        "/var/lib/hippius-miner/x.img",
    );
    inner.seed_domain_xml(
        DomainId::new("hippius-tenant-uv-s").unwrap(),
        DomainState::Running,
        &dumpxml("uv-s", 2, 2048 * 1024, 7, "/var/lib/hippius-miner/x.img"),
    );
    seed_snp_probe();
    let lc = Arc::new(
        CvmLifecycle::new_with_poll(
            driver.clone(),
            ok_digest(),
            HostResources {
                total_cpus: 16,
                total_memory_mb: 65536,
                total_disk_gb: 0,
            },
            Duration::from_millis(1),
            5,
        )
        .skip_state_disk_provision_for_tests()
        .with_state_disk_root(tmp.path().to_path_buf()),
    );
    let adopting = {
        let lc = Arc::clone(&lc);
        tokio::spawn(async move { lc.readopt_running().await.unwrap() })
    };
    driver.entered.notified().await;
    inner.force_all_to_state(DomainState::ShutOff).unwrap();
    driver.release.notify_one();
    assert_eq!(adopting.await.unwrap(), 1);
    assert_eq!(
        lc.cid_allocator().owner_of(7).unwrap(),
        CidOwner::Unverified(VmId::new("uv-s").unwrap())
    );
}

/// After the first `domain_xml`, the domain is shut off AND `domstate`
/// starts failing — the `list_domains` fallback still lists it.
struct FlakyAfterXmlDriver {
    inner: Arc<MockLibvirtDriver>,
    tripped: std::sync::atomic::AtomicBool,
}

#[async_trait]
impl LibvirtDriver for FlakyAfterXmlDriver {
    async fn define_domain(&self, xml: &str) -> Result<DomainId> {
        self.inner.define_domain(xml).await
    }
    async fn create_domain(&self, id: &DomainId) -> Result<()> {
        self.inner.create_domain(id).await
    }
    async fn destroy_domain(&self, id: &DomainId, graceful: bool) -> Result<()> {
        self.inner.destroy_domain(id, graceful).await
    }
    async fn undefine_domain(&self, id: &DomainId) -> Result<()> {
        self.inner.undefine_domain(id).await
    }
    async fn query_domain_state(&self, id: &DomainId) -> Result<DomainState> {
        if self.tripped.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(MinerAgentError::LibvirtDriver("domstate"));
        }
        self.inner.query_domain_state(id).await
    }
    async fn list_domains(&self) -> Result<Vec<(DomainId, DomainState)>> {
        self.inner.list_domains().await
    }
    async fn domain_xml(&self, id: &DomainId) -> Result<String> {
        let xml = self.inner.domain_xml(id).await;
        self.inner.force_all_to_state(DomainState::ShutOff)?;
        self.tripped
            .store(true, std::sync::atomic::Ordering::SeqCst);
        xml
    }
}

#[tokio::test]
async fn a_listed_but_unqueryable_domain_is_not_proof_the_xml_is_live() {
    let inner = Arc::new(MockLibvirtDriver::new());
    let driver = Arc::new(FlakyAfterXmlDriver {
        inner: inner.clone(),
        tripped: std::sync::atomic::AtomicBool::new(false),
    });
    let tmp = tempfile::tempdir().unwrap();
    write_sidecar(
        tmp.path(),
        "uv-f",
        2,
        2048,
        7,
        "/var/lib/hippius-miner/x.img",
    );
    inner.seed_domain_xml(
        DomainId::new("hippius-tenant-uv-f").unwrap(),
        DomainState::Running,
        &dumpxml("uv-f", 2, 2048 * 1024, 7, "/var/lib/hippius-miner/x.img"),
    );
    seed_snp_probe();
    let lc = CvmLifecycle::new_with_poll(
        driver,
        ok_digest(),
        HostResources {
            total_cpus: 16,
            total_memory_mb: 65536,
            total_disk_gb: 0,
        },
        Duration::from_millis(1),
        5,
    )
    .skip_state_disk_provision_for_tests()
    .with_state_disk_root(tmp.path().to_path_buf());
    assert_eq!(lc.readopt_running().await.unwrap(), 1);
    assert_eq!(
        lc.cid_allocator().owner_of(7).unwrap(),
        CidOwner::Unverified(VmId::new("uv-f").unwrap())
    );
}

// ── a survivor blocked by a stale unverified claim is retried (#1149) ──

/// A (stale sidecar, unreadable XML) holds cid 7 UNVERIFIED; B — a live
/// survivor whose domain really runs on 7 — then collides and is left
/// untracked. Returns the lifecycle and driver with both sidecars on disk.
async fn stale_claim_blocks_a_survivor() -> (Arc<MockLibvirtDriver>, CvmLifecycle, tempfile::TempDir)
{
    let driver = Arc::new(MockLibvirtDriver::new());
    let tmp = tempfile::tempdir().unwrap();
    write_sidecar(
        tmp.path(),
        "rc-stale",
        2,
        2048,
        7,
        "/var/lib/hippius-miner/a.img",
    );
    driver.seed_domain(
        DomainId::new("hippius-tenant-rc-stale").unwrap(),
        DomainState::Running,
    );
    let lc = lifecycle(driver.clone(), ok_digest()).with_state_disk_root(tmp.path().to_path_buf());
    assert_eq!(
        lc.readopt_running().await.unwrap(),
        1,
        "A adopted, cid 7 unverified"
    );

    write_sidecar(
        tmp.path(),
        "rc-live",
        2,
        2048,
        7,
        "/var/lib/hippius-miner/b.img",
    );
    driver.seed_domain_xml(
        DomainId::new("hippius-tenant-rc-live").unwrap(),
        DomainState::Running,
        &dumpxml("rc-live", 2, 2048 * 1024, 7, "/var/lib/hippius-miner/b.img"),
    );
    lc.readopt_running().await.unwrap();
    let b = VmId::new("rc-live").unwrap();
    assert!(
        !lc.list().await.unwrap().iter().any(|(v, _)| *v == b),
        "precondition: B collided with A's stale claim"
    );
    (driver, lc, tmp)
}

fn far_future_1149() -> std::time::Instant {
    std::time::Instant::now() + Duration::from_secs(24 * 3600)
}

#[tokio::test]
async fn a_survivor_blocked_by_a_stale_claim_is_adopted_once_the_claim_is_rekeyed() {
    let (driver, lc, _tmp) = stale_claim_blocks_a_survivor().await;
    // A's live XML shows its real cid, 9 → re-key frees (burns) 7 for A…
    driver.seed_domain_xml(
        DomainId::new("hippius-tenant-rc-stale").unwrap(),
        DomainState::Running,
        &dumpxml(
            "rc-stale",
            2,
            2048 * 1024,
            9,
            "/var/lib/hippius-miner/a.img",
        ),
    );
    lc.verify_pending_cids(far_future_1149()).await;
    // …and B, retried, now holds 7 — verified by its own live XML.
    let b = VmId::new("rc-live").unwrap();
    assert!(
        lc.list().await.unwrap().iter().any(|(v, _)| *v == b),
        "B re-adopted"
    );
    assert_eq!(lc.cid_allocator().vm_id_for_cid(7).unwrap(), Some(b));
}

#[tokio::test]
async fn a_survivor_blocked_by_a_stale_claim_is_adopted_once_the_claim_is_dropped() {
    let (driver, lc, _tmp) = stale_claim_blocks_a_survivor().await;
    driver
        .undefine_domain(&DomainId::new("hippius-tenant-rc-stale").unwrap())
        .await
        .unwrap();
    lc.verify_pending_cids(far_future_1149()).await;
    let b = VmId::new("rc-live").unwrap();
    assert!(
        lc.list().await.unwrap().iter().any(|(v, _)| *v == b),
        "B re-adopted"
    );
    assert_eq!(lc.cid_allocator().vm_id_for_cid(7).unwrap(), Some(b));
}

#[tokio::test]
async fn a_survivor_is_adopted_once_the_stale_claims_vm_is_stopped() {
    // The commonest way a stale claim goes away is its VM being stopped or
    // destroyed: `release_cid` frees the cid with no verification verdict,
    // so the release itself must make the retry due.
    let (_driver, lc, _tmp) = stale_claim_blocks_a_survivor().await;
    lc.stop(&VmId::new("rc-stale").unwrap(), false)
        .await
        .unwrap();
    assert_eq!(lc.unverified_cid_count(), 0);
    assert!(
        lc.readopt_retry_due(),
        "the release must make the retry due"
    );
    lc.verify_pending_cids(far_future_1149()).await;
    let b = VmId::new("rc-live").unwrap();
    assert!(
        lc.list().await.unwrap().iter().any(|(v, _)| *v == b),
        "B re-adopted"
    );
    assert!(!lc.readopt_retry_due());
}

// ── Relaunch: existing disks REQUIRED, never blank-created ───────────
//
// Seen in production 2026-09-25: vali's reboot-recovery relaunched a golden VM
// on a host that had never held its disks, and the launch path CREATED a
// blank 40 GiB overlay + a blank boot-counter disk and booted. A relaunch
// order (`require_existing_disks`) must refuse instead — before any domain
// is defined and without creating a single file.

/// A lifecycle whose provisioning is ON (unlike `lifecycle()`), rooted at
/// `root` — so a guard that let the launch through would really create the
/// blank disks these tests assert are never created.
fn provisioning_lifecycle(driver: Arc<MockLibvirtDriver>, root: &std::path::Path) -> CvmLifecycle {
    seed_snp_probe();
    CvmLifecycle::new_with_poll(
        driver,
        ok_digest(),
        HostResources {
            total_cpus: 16,
            total_memory_mb: 65536,
            total_disk_gb: 0,
        },
        Duration::from_millis(1),
        5,
    )
    .with_state_disk_root(root.to_path_buf())
}

fn touch(path: &std::path::Path) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, b"existing tenant bytes").unwrap();
}

fn state_path(root: &std::path::Path, vm: &str) -> PathBuf {
    root.join("state").join(format!("{vm}.raw"))
}

fn overlay_path(root: &std::path::Path, vm: &str) -> PathBuf {
    root.join("overlay").join(format!("{vm}.img"))
}

fn data_path(root: &std::path::Path, vm: &str) -> PathBuf {
    root.join("data").join(format!("{vm}.img"))
}

fn relaunch(mut o: LaunchOrder) -> LaunchOrder {
    o.require_existing_disks = true;
    o
}

#[tokio::test]
async fn golden_relaunch_without_its_overlay_is_refused_and_creates_nothing() {
    let tmp = tempfile::tempdir().unwrap();
    let vm = "cvm-relaunch-no-overlay";
    touch(&state_path(tmp.path(), vm));
    let driver = Arc::new(MockLibvirtDriver::new());
    let lc = provisioning_lifecycle(driver.clone(), tmp.path());

    let err = lc.launch(relaunch(golden_order(vm))).await.unwrap_err();

    assert!(
        matches!(err, MinerAgentError::RelaunchDisksMissing("overlay")),
        "got {err:?}"
    );
    assert!(
        !overlay_path(tmp.path(), vm).exists(),
        "a relaunch must never create a blank golden overlay"
    );
    assert_eq!(driver.defined_count().unwrap(), 0);
    // Nothing was reserved: the same vm_id launches once its disks exist.
    touch(&overlay_path(tmp.path(), vm));
    lc.launch(relaunch(golden_order(vm))).await.unwrap();
}

#[tokio::test]
async fn golden_relaunch_without_its_state_disk_is_refused_and_creates_nothing() {
    let tmp = tempfile::tempdir().unwrap();
    let vm = "cvm-relaunch-no-state";
    touch(&overlay_path(tmp.path(), vm));
    let driver = Arc::new(MockLibvirtDriver::new());
    let lc = provisioning_lifecycle(driver.clone(), tmp.path());

    let err = lc.launch(relaunch(golden_order(vm))).await.unwrap_err();

    assert!(
        matches!(err, MinerAgentError::RelaunchDisksMissing("state-disk")),
        "got {err:?}"
    );
    assert!(
        !state_path(tmp.path(), vm).exists(),
        "a relaunch must never format a blank boot-counter disk"
    );
    assert_eq!(driver.defined_count().unwrap(), 0);
}

#[tokio::test]
async fn legacy_relaunch_without_its_data_disk_is_refused_and_creates_nothing() {
    let tmp = tempfile::tempdir().unwrap();
    let vm = "cvm-relaunch-no-data";
    touch(&state_path(tmp.path(), vm));
    let driver = Arc::new(MockLibvirtDriver::new());
    let lc = provisioning_lifecycle(driver.clone(), tmp.path());
    let mut o = order(vm);
    o.data_disk_size_gb = 10;

    let err = lc.launch(relaunch(o)).await.unwrap_err();

    assert!(
        matches!(err, MinerAgentError::RelaunchDisksMissing("data-disk")),
        "got {err:?}"
    );
    assert!(!data_path(tmp.path(), vm).exists());
    assert_eq!(driver.defined_count().unwrap(), 0);
}

#[tokio::test]
async fn golden_relaunch_with_its_disks_reuses_them_untouched() {
    let tmp = tempfile::tempdir().unwrap();
    let vm = "cvm-relaunch-ok";
    touch(&state_path(tmp.path(), vm));
    touch(&overlay_path(tmp.path(), vm));
    let driver = Arc::new(MockLibvirtDriver::new());
    let lc = provisioning_lifecycle(driver.clone(), tmp.path());

    let id = lc.launch(relaunch(golden_order(vm))).await.unwrap();

    assert_eq!(lc.query(&id).await.unwrap(), CvmPhase::Running);
    for p in [state_path(tmp.path(), vm), overlay_path(tmp.path(), vm)] {
        assert_eq!(std::fs::read(&p).unwrap(), b"existing tenant bytes");
    }
}

#[tokio::test]
async fn a_first_launch_still_creates_its_overlay() {
    // The guard is scoped to relaunches: a first launch (the default)
    // provisions its blank overlay exactly as before.
    let tmp = tempfile::tempdir().unwrap();
    let vm = "cvm-first-launch";
    touch(&state_path(tmp.path(), vm)); // no mkfs.ext4 needed on the runner
    let driver = Arc::new(MockLibvirtDriver::new());
    let lc = provisioning_lifecycle(driver.clone(), tmp.path());
    let mut o = golden_order(vm);
    o.data_disk_size_gb = 1;

    lc.launch(o).await.unwrap();

    assert!(overlay_path(tmp.path(), vm).exists());
}

#[tokio::test]
async fn a_relaunch_whose_disk_cannot_be_statted_is_unreadable_not_missing() {
    // EACCES / EIO / a late storage mount proves nothing about presence:
    // it must NOT surface as `missing` (which vali latches on for good).
    use std::os::unix::fs::PermissionsExt;
    let tmp = tempfile::tempdir().unwrap();
    let vm = "cvm-relaunch-unreadable";
    let state = state_path(tmp.path(), vm);
    touch(&state);
    touch(&overlay_path(tmp.path(), vm));
    let state_dir = state.parent().unwrap().to_path_buf();
    std::fs::set_permissions(&state_dir, std::fs::Permissions::from_mode(0o000)).unwrap();
    if state.try_exists().is_ok() {
        // Running as root: permissions do not bind, nothing to prove here.
        std::fs::set_permissions(&state_dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        return;
    }
    let driver = Arc::new(MockLibvirtDriver::new());
    let lc = provisioning_lifecycle(driver.clone(), tmp.path());

    let err = lc.launch(relaunch(golden_order(vm))).await.unwrap_err();
    std::fs::set_permissions(&state_dir, std::fs::Permissions::from_mode(0o755)).unwrap();

    assert!(
        matches!(err, MinerAgentError::RelaunchDisksUnreadable("state-disk")),
        "got {err:?}"
    );
    assert_eq!(driver.defined_count().unwrap(), 0);
    assert_eq!(std::fs::read(&state).unwrap(), b"existing tenant bytes");
}
