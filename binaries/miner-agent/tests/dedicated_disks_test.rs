//! Dedicated disks through the lifecycle and the order handlers: a launch
//! claims and records them and renders them into the domain, a relaunch
//! re-attaches exactly them, a failed launch gives them back, §24 releases
//! them through the privileged helper, and a pinned VM refuses every
//! operation that would move it. libvirt is the mock driver; the disk facts
//! and the privileged helper are scripted.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::http::StatusCode;
use ciborium::value::Value;
use coset::{CborSerializable, CoseSign1Builder, HeaderBuilder};
use hippius_miner_agent::config::{DedicatedDiskConfig, StorageDesiredStateConfig};
use hippius_miner_agent::lifecycle::{
    DomainId, DomainState, LibvirtDriver, MockLaunchDigest, MockLibvirtDriver,
};
use hippius_miner_agent::orders::handler::{self, reject_dispatch, REASON_HEADER};
use hippius_miner_agent::orders::{ExtraDisk, MigrationStore};
use hippius_miner_agent::snp_config::{install_for_tests, SnpCpuConfig};
use hippius_miner_agent::storage::assignment::{self, DedicatedDisks, DedicatedHelper};
use hippius_miner_agent::storage::dedicated::{DiskFact, DiskFacts, FactsSource, IdentityMap};
use hippius_miner_agent::storage::state::{EffectiveStorage, StorageState};
use hippius_miner_agent::storage::StoragePools;
use hippius_miner_agent::{CvmLifecycle, HostResources, LaunchOrder, MinerAgentError, VmId};

#[derive(Default)]
struct Facts(Mutex<Option<DiskFacts>>);

struct SharedFacts(Arc<Facts>);

impl FactsSource for SharedFacts {
    fn facts(&self) -> std::result::Result<DiskFacts, &'static str> {
        self.0 .0.lock().unwrap().clone().ok_or("disk-facts-stale")
    }
}

#[derive(Default)]
struct Helper {
    hold_err: Mutex<Option<&'static str>>,
    release_err: Mutex<Option<&'static str>>,
    calls: Mutex<Vec<String>>,
}

struct SharedHelper(Arc<Helper>);

impl DedicatedHelper for SharedHelper {
    fn installed(&self) -> bool {
        true
    }
    fn hold(&self, disk_id: &str) -> std::result::Result<(), &'static str> {
        self.0.calls.lock().unwrap().push(format!("hold {disk_id}"));
        self.0.hold_err.lock().unwrap().map_or(Ok(()), Err)
    }
    fn unhold(&self, disk_id: &str) -> std::result::Result<(), &'static str> {
        self.0
            .calls
            .lock()
            .unwrap()
            .push(format!("unhold {disk_id}"));
        Ok(())
    }
    fn release(&self, disk_id: &str) -> std::result::Result<(), &'static str> {
        self.0
            .calls
            .lock()
            .unwrap()
            .push(format!("release {disk_id}"));
        self.0.release_err.lock().unwrap().map_or(Ok(()), Err)
    }
}

fn ticket_medium() -> Vec<u8> {
    let payload = Value::Map(vec![
        (Value::Text("v".into()), Value::Integer(2.into())),
        (Value::Text("flavor".into()), Value::Text("medium".into())),
    ]);
    let mut buf = Vec::new();
    ciborium::ser::into_writer(&payload, &mut buf).unwrap();
    CoseSign1Builder::new()
        .protected(
            HeaderBuilder::new()
                .algorithm(coset::iana::Algorithm::EdDSA)
                .build(),
        )
        .payload(buf)
        .create_signature(b"", |_| vec![0u8; 64])
        .build()
        .to_vec()
        .unwrap()
}

fn extra(slot: &str, disk_id: &str) -> ExtraDisk {
    ExtraDisk {
        slot: slot.into(),
        kind: "dedicated".into(),
        disk_id: disk_id.into(),
    }
}

/// The measured token for `extra_disks` (vali's E4 emits it).
fn anchor(extra_disks: &[ExtraDisk]) -> String {
    if extra_disks.is_empty() {
        return String::new();
    }
    let slots: Vec<String> = extra_disks
        .iter()
        .map(|d| format!("{}:16000", d.slot))
        .collect();
    format!(" hippius.dedicated={}", slots.join(","))
}

fn order(vm_id: &str, extra_disks: Vec<ExtraDisk>) -> LaunchOrder {
    install_for_tests(SnpCpuConfig {
        cbitpos: 51,
        reduced_phys_bits: 1,
    });
    LaunchOrder {
        vm_id: VmId::new(vm_id).unwrap(),
        ovmf_path: PathBuf::from("/var/lib/hippius-miner/ovmf.fd"),
        kernel_path: PathBuf::from("/var/lib/hippius-miner/vmlinuz"),
        initrd_path: PathBuf::from("/var/lib/hippius-miner/initrd"),
        cmdline: format!("quiet panic=0{}", anchor(&extra_disks)),
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
        net: None,
        on_guest_poweroff: None,
        os_pool: None,
        extra_disks,
    }
}

struct World {
    dir: tempfile::TempDir,
    facts: Arc<Facts>,
    helper: Arc<Helper>,
    driver: Arc<MockLibvirtDriver>,
}

impl World {
    /// `wwn-0x1` (`naa.1`) and `wwn-0x2` (`naa.2`): declared, clean, bound.
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let mut disks = BTreeMap::new();
        for (id, identity, dev) in [("wwn-0x1", "naa.1", "250:1"), ("wwn-0x2", "naa.2", "250:2")] {
            disks.insert(
                id.to_string(),
                DiskFact {
                    size_mb: 18 * 1024 * 1024,
                    error: String::new(),
                    identity: Some(identity.into()),
                    dev: Some(dev.into()),
                    offline: false,
                },
            );
        }
        let facts = Arc::new(Facts(Mutex::new(Some(DiskFacts {
            collected_at_unix: 1,
            disks,
        }))));
        let mut ids = IdentityMap::default();
        ids.disks.insert("wwn-0x1".into(), "naa.1".into());
        ids.disks.insert("wwn-0x2".into(), "naa.2".into());
        ids.save(dir.path()).unwrap();
        Self {
            dir,
            facts,
            helper: Arc::new(Helper::default()),
            driver: Arc::new(MockLibvirtDriver::new()),
        }
    }

    /// A lifecycle over this world: a fresh one is an agent restart.
    fn lifecycle(&self) -> CvmLifecycle {
        let root = self.dir.path().to_path_buf();
        let storage = Arc::new(StorageState::new(EffectiveStorage::local(
            Arc::new(StoragePools::implicit(root.clone(), 0)),
            ["wwn-0x1", "wwn-0x2"]
                .iter()
                .map(|id| DedicatedDiskConfig {
                    id: (*id).into(),
                    state: StorageDesiredStateConfig::Active,
                })
                .collect(),
            Default::default(),
        )));
        CvmLifecycle::new_with_poll(
            Arc::clone(&self.driver) as Arc<dyn LibvirtDriver>,
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
        .with_state_disk_root(root)
        .with_storage_state(storage)
        .with_dedicated(Arc::new(DedicatedDisks::new(
            Box::new(SharedFacts(Arc::clone(&self.facts))),
            Box::new(SharedHelper(Arc::clone(&self.helper))),
            Arc::default(),
        )))
    }

    fn record(&self, vm: &str) -> Option<assignment::VmDedicatedRecord> {
        assignment::read_vm(self.dir.path(), vm).unwrap()
    }

    fn calls(&self) -> Vec<String> {
        self.helper.calls.lock().unwrap().clone()
    }

    async fn xml(&self, vm: &str) -> String {
        let id = DomainId::new(&format!("hippius-tenant-{vm}")).unwrap();
        self.driver.domain_xml(&id).await.unwrap()
    }
}

fn class(err: &MinerAgentError) -> (StatusCode, &'static str, Option<String>) {
    let rej = reject_dispatch(err, "vm");
    (rej.status, rej.class, rej.reason)
}

#[tokio::test]
async fn a_launch_claims_records_holds_and_attaches_its_disks_by_virtual_serial() {
    let w = World::new();
    let lc = w.lifecycle();
    lc.launch(order(
        "vm-a",
        vec![extra("x0", "wwn-0x2"), extra("x1", "wwn-0x1")],
    ))
    .await
    .unwrap();
    let record = w.record("vm-a").unwrap();
    assert_eq!(record.disks.len(), 2);
    assert_eq!(record.disks[0].identity, "naa.2");
    assert_eq!(w.calls(), vec!["hold wwn-0x2", "hold wwn-0x1"]);
    let xml = w.xml("vm-a").await;
    assert!(xml.contains("<source dev='/dev/disk/by-id/wwn-0x2'/>\n      <target dev='vdf' bus='virtio'/>\n      <serial>hippius-x0</serial>"));
    assert!(xml.contains("<source dev='/dev/disk/by-id/wwn-0x1'/>\n      <target dev='vdg' bus='virtio'/>\n      <serial>hippius-x1</serial>"));
    // The guest never sees the device's own identity.
    assert!(!xml.contains("naa."));
    // Another VM cannot have them.
    let err = lc
        .launch(order("vm-b", vec![extra("x0", "wwn-0x1")]))
        .await
        .unwrap_err();
    assert_eq!(
        class(&err),
        (
            StatusCode::CONFLICT,
            "dedicated-disk-assigned:x0",
            Some("dedicated-disk-assigned:x0".into())
        )
    );
    assert!(w.record("vm-b").is_none());
}

#[tokio::test]
async fn a_refused_or_malformed_list_defines_nothing() {
    let w = World::new();
    let lc = w.lifecycle();
    let err = lc
        .launch(order("vm-a", vec![extra("x0", "wwn-0x9")]))
        .await
        .unwrap_err();
    assert_eq!(class(&err).1, "dedicated-disk-unknown:x0");
    let err = lc
        .launch(order(
            "vm-a",
            vec![extra("x0", "wwn-0x1"), extra("x0", "wwn-0x2")],
        ))
        .await
        .unwrap_err();
    assert_eq!(
        class(&err),
        (
            StatusCode::BAD_REQUEST,
            "dedicated-invalid",
            Some("dedicated-invalid/slot-duplicate".into())
        )
    );
    // Stale facts: retryable, nothing claimed.
    *w.facts.0.lock().unwrap() = None;
    let err = lc
        .launch(order("vm-a", vec![extra("x0", "wwn-0x1")]))
        .await
        .unwrap_err();
    assert_eq!(class(&err).0, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(w.driver.defined_count().unwrap(), 0);
    assert!(w.record("vm-a").is_none());
    assert!(w.calls().is_empty());
}

#[tokio::test]
async fn a_launch_failing_before_the_domain_starts_gives_the_disks_back() {
    let w = World::new();
    let lc = w.lifecycle();
    *w.helper.hold_err.lock().unwrap() = Some("hold-busy");
    let err = lc
        .launch(order("vm-a", vec![extra("x0", "wwn-0x1")]))
        .await
        .unwrap_err();
    assert_eq!(class(&err).1, "dedicated-disk-busy:x0");
    assert!(w.record("vm-a").is_none());
    assert_eq!(w.driver.defined_count().unwrap(), 0);
    assert_eq!(
        w.calls(),
        vec!["hold wwn-0x1", "unhold wwn-0x1", "unhold wwn-0x1"]
    );
    // Free for the next launch.
    *w.helper.hold_err.lock().unwrap() = None;
    lc.launch(order("vm-b", vec![extra("x0", "wwn-0x1")]))
        .await
        .unwrap();
}

#[tokio::test]
async fn a_launch_failing_after_the_domain_started_keeps_its_disks_until_destroy() {
    let w = World {
        driver: Arc::new(MockLibvirtDriver::with_post_create_state(
            DomainState::ShutOff,
        )),
        ..World::new()
    };
    let lc = w.lifecycle();
    assert!(lc
        .launch(order("vm-a", vec![extra("x0", "wwn-0x1")]))
        .await
        .is_err());
    // A guest may have written to it: only §24 frees it.
    assert!(w.record("vm-a").is_some());
}

#[tokio::test]
async fn relaunch_power_start_and_agent_restart_reattach_exactly_the_same_disks() {
    let w = World::new();
    let lc = w.lifecycle();
    let disks = vec![extra("x0", "wwn-0x1")];
    lc.launch(order("vm-a", disks.clone())).await.unwrap();
    lc.stop(&VmId::new("vm-a").unwrap(), false).await.unwrap();
    // The agent restarts: a fresh lifecycle over the same state root.
    let lc = w.lifecycle();
    // Another disk, or none: refused, never attached.
    for other in [vec![extra("x0", "wwn-0x2")], vec![]] {
        let err = lc.launch(order("vm-a", other)).await.unwrap_err();
        assert_eq!(class(&err).1, "dedicated-order-mismatch");
    }
    // The device behind the recorded name changed: refused.
    w.facts
        .0
        .lock()
        .unwrap()
        .as_mut()
        .unwrap()
        .disks
        .get_mut("wwn-0x1")
        .unwrap()
        .identity = Some("naa.swapped".into());
    let err = lc.launch(order("vm-a", disks.clone())).await.unwrap_err();
    assert_eq!(class(&err).1, "dedicated-disk-mismatch:x0");
    assert_eq!(w.driver.defined_count().unwrap(), 0);
    // Back to the right device: the same disk, re-held.
    w.facts
        .0
        .lock()
        .unwrap()
        .as_mut()
        .unwrap()
        .disks
        .get_mut("wwn-0x1")
        .unwrap()
        .identity = Some("naa.1".into());
    lc.launch(order("vm-a", disks)).await.unwrap();
    assert!(w.xml("vm-a").await.contains("/dev/disk/by-id/wwn-0x1"));
    assert_eq!(w.calls().iter().filter(|c| *c == "hold wwn-0x1").count(), 2);
    // The reboot-watcher's restart path checks the same way.
    let vm = VmId::new("vm-a").unwrap();
    assert!(lc.check_dedicated_before_restart(&vm).await.is_ok());
}

#[tokio::test]
async fn destroy_releases_the_disks_through_the_helper_and_retries_a_failed_wipe() {
    let w = World::new();
    let lc = w.lifecycle();
    let vm = VmId::new("vm-a").unwrap();
    lc.launch(order(
        "vm-a",
        vec![extra("x0", "wwn-0x1"), extra("x1", "wwn-0x2")],
    ))
    .await
    .unwrap();
    lc.stop(&vm, false).await.unwrap();
    *w.helper.release_err.lock().unwrap() = Some("release-signature-remains");
    lc.destroy(&vm, None).await.unwrap();
    assert!(w.record("vm-a").is_none());
    // Queued by the destroy, wiped off its path.
    let want = [
        "unhold wwn-0x1".to_string(),
        "release wwn-0x1".to_string(),
        "unhold wwn-0x2".to_string(),
        "release wwn-0x2".to_string(),
    ];
    for _ in 0..200 {
        if w.calls().ends_with(&want) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let calls = w.calls();
    assert!(calls.ends_with(&[
        "unhold wwn-0x1".to_string(),
        "release wwn-0x1".to_string(),
        "unhold wwn-0x2".to_string(),
        "release wwn-0x2".to_string()
    ]));
    // Not wiped: still the agent's, never given.
    assert!(assignment::read_release(w.dir.path(), "wwn-0x1")
        .unwrap()
        .is_some());
    let err = lc
        .launch(order("vm-b", vec![extra("x0", "wwn-0x1")]))
        .await
        .unwrap_err();
    assert_eq!(class(&err).1, "dedicated-disk-releasing:x0");
    // The drain wipes them once the helper succeeds.
    *w.helper.release_err.lock().unwrap() = None;
    assert_eq!(lc.drain_dedicated_releases().await, 2);
    assert!(assignment::read_release(w.dir.path(), "wwn-0x1")
        .unwrap()
        .is_none());
    // A second destroy is a no-op.
    lc.destroy(&vm, None).await.unwrap();
}

#[tokio::test]
async fn a_pinned_vm_refuses_migration_storage_moves_backups_and_restores() {
    let w = World::new();
    let lc = Arc::new(w.lifecycle());
    let vm = VmId::new("vm-a").unwrap();
    lc.launch(order("vm-a", vec![extra("x0", "wwn-0x1")]))
        .await
        .unwrap();
    let pinned = |rej: hippius_miner_agent::orders::OrderRejection| {
        assert_eq!(rej.status, StatusCode::CONFLICT);
        assert_eq!(rej.class, "dedicated-pinned");
        assert_eq!(rej.reason.as_deref(), Some("dedicated-pinned"));
    };
    // §25 source: quiesce, snapshot.
    let migration = Arc::new(MigrationStore::new());
    struct NoSigner;
    #[async_trait::async_trait]
    impl hippius_miner_agent::orders::migration::GuestStoppedAckSigner for NoSigner {
        async fn sign(
            &self,
            _vm_id: &VmId,
            _inputs: &hippius_miner_agent::orders::migration::SourceAckInputs,
        ) -> hippius_miner_agent::Result<Option<Vec<u8>>> {
            Ok(None)
        }
    }
    let quiesce: hippius_miner_agent::orders::MigrateQuiesceOrder =
        serde_json::from_value(serde_json::json!({"vm_id": "vm-a", "node_id": "n"})).unwrap();
    pinned(
        handler::handle_migrate_quiesce(&lc, &migration, &NoSigner, quiesce)
            .await
            .unwrap_err(),
    );
    assert!(migration.phase(&vm).is_none(), "refused before any state");
    // The domain was not touched.
    assert!(w.xml("vm-a").await.contains("wwn-0x1"));
    // A storage move.
    let start: hippius_miner_agent::orders::MoveVmStorageOrder =
        serde_json::from_value(serde_json::json!({
            "vm_id": "vm-a", "move_id": "0123456789abcdef0123456789abcdef",
            "action": "start", "target_pool": "hdd0", "expected_source_pool": "default",
            "bandwidth_mib_s": hippius_miner_agent::orders::types::MOVE_BANDWIDTH_MIB_S.start(),
            "not_after_unix": u64::MAX
        }))
        .unwrap();
    pinned(
        handler::handle_move_vm_storage(&lc, &migration, None, start)
            .await
            .unwrap_err(),
    );
    // The lifecycle check every other path uses (backup, restore, the
    // §25 destination).
    assert!(matches!(
        lc.check_not_pinned(&vm),
        Err(MinerAgentError::DedicatedRefused("dedicated-pinned"))
    ));
    assert!(lc.check_not_pinned(&VmId::new("vm-b").unwrap()).is_ok());
    // The §25 destination refuses on the measured cmdline alone too.
    assert!(assignment::cmdline_is_pinned(
        &order("x", vec![extra("x0", "wwn-0x1")]).cmdline
    ));
    let _ = REASON_HEADER;
}

#[tokio::test]
async fn a_launch_whose_measured_cmdline_does_not_anchor_its_disks_is_refused() {
    let w = World::new();
    let lc = w.lifecycle();
    // Disks without the measured token.
    let mut o = order("vm-a", vec![extra("x0", "wwn-0x1")]);
    o.cmdline = "quiet panic=0".into();
    let err = lc.launch(o).await.unwrap_err();
    assert_eq!(
        class(&err),
        (
            StatusCode::BAD_REQUEST,
            "dedicated-invalid",
            Some("dedicated-invalid/cmdline-missing".into())
        )
    );
    // A token naming another slot.
    let mut o = order("vm-a", vec![extra("x0", "wwn-0x1")]);
    o.cmdline = "quiet panic=0 hippius.dedicated=x1:16000".into();
    assert_eq!(
        class(&lc.launch(o).await.unwrap_err()).2.as_deref(),
        Some("dedicated-invalid/cmdline-slots")
    );
    // The token without disks.
    let mut o = order("vm-a", vec![]);
    o.cmdline = "quiet panic=0 hippius.dedicated=x0:16000".into();
    assert_eq!(
        class(&lc.launch(o).await.unwrap_err()).2.as_deref(),
        Some("dedicated-invalid/cmdline-without-disks")
    );
    assert!(w.record("vm-a").is_none());
    assert!(w.calls().is_empty());
    assert_eq!(w.driver.defined_count().unwrap(), 0);
}

#[tokio::test]
async fn a_launch_whose_domain_never_started_gives_the_disks_back() {
    // The define went through, the create never did (here every attempt
    // collides on its vsock CID; on a host, AppArmor/DAC on the block
    // device or the SEV ASID pool): no guest saw the disks.
    let w = World::new();
    w.driver.set_cid_conflicts(100);
    let lc = w.lifecycle();
    assert!(lc
        .launch(order("vm-a", vec![extra("x0", "wwn-0x1")]))
        .await
        .is_err());
    assert!(
        w.record("vm-a").is_none(),
        "the disks leaked to a VM that never ran"
    );
    // Free for the next launch.
    w.driver.set_cid_conflicts(0);
    lc.launch(order("vm-b", vec![extra("x0", "wwn-0x1")]))
        .await
        .unwrap();
}
