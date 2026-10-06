//! Live test against a REAL libvirt + QEMU domain — `#[ignore]`d; run by
//! hand on a throwaway host with:
//!
//! ```text
//! HIPPIUS_BK_LIVE_ROOT=/var/lib/hippius-miner HIPPIUS_BK_LIVE_VM=vm-live \
//!   <test-binary> --ignored --test-threads 1 backup::live_tests::
//! ```
//!
//! The domain `hippius-tenant-<vm>` must be running with
//! `<root>/overlay/<vm>.img` as a raw `vda` (qdev id `virtio-disk0`) and
//! `<root>/state/<vm>.raw` a formatted state disk. Guest writes are
//! simulated with HMP `qemu-io` on the device, which goes through the
//! same block graph as guest I/O.
//!
//! What it proves on real QEMU: the fd-passed target (add-fd over
//! `--pass-fds` + `/dev/fdset`), full + incremental transactions with
//! point bitmaps, upload through presigned-style part URLs, that a run
//! whose UPLOAD failed loses nothing (the retry from the same parent
//! carries its writes), the Rust qcow2 applier rebuilding a chain that
//! byte-matches the live overlay, pruning, and that nothing is left in
//! QEMU afterwards.

use std::path::PathBuf;
use std::sync::Arc;

use serde_json::json;
use sha2::{Digest, Sha256};

use super::image_tool::QemuImg;
use super::qmp::{self, QmpTransport, VirshQmp};
use super::restore::{BackupChainRestorer, ChainPiece, ChainRestorer, RestoreChain};
use super::transfer::{test_server, Transfer, MIN_PART_SIZE, PART_ATTEMPTS};
use super::{BackupKind, BackupManager, BackupRequest, RunPhase};
use crate::lifecycle::{
    CvmLifecycle, DomainId, HostResources, MockLaunchDigest, VirshDriver, VmId,
};

async fn qemu_io(qmp: &VirshQmp, domain: &DomainId, cmd: &str) {
    let hmp = json!({"execute": "human-monitor-command",
        "arguments": {"command-line":
            format!("qemu-io -d /machine/peripheral/virtio-disk0/virtio-backend \"{cmd}\"")}});
    let out = qmp.execute(domain, &hmp, None).await.unwrap();
    let text = out.as_str().unwrap_or_default();
    assert!(!text.to_lowercase().contains("error"), "qemu-io: {text}");
}

fn sha_file(p: &std::path::Path) -> String {
    hex::encode(Sha256::digest(std::fs::read(p).unwrap()))
}

#[tokio::test]
#[ignore = "needs a live libvirt domain; see module docs"]
async fn live_chain_round_trip() {
    let root = PathBuf::from(std::env::var("HIPPIUS_BK_LIVE_ROOT").unwrap());
    let vm = VmId::new(&std::env::var("HIPPIUS_BK_LIVE_VM").unwrap()).unwrap();
    let domain = DomainId::new(&format!("hippius-tenant-{vm}")).unwrap();

    let lifecycle = CvmLifecycle::new(
        Arc::new(VirshDriver::default()),
        Arc::new(MockLaunchDigest::failing()),
        HostResources {
            total_cpus: 1,
            total_memory_mb: 1,
            total_disk_gb: 0,
        },
    )
    .with_state_disk_root(root.clone());
    let qmp = Arc::new(VirshQmp::default());
    let store = test_server::Store::default();
    let base = test_server::start(store.clone()).await;
    let manager = BackupManager::new(
        qmp.clone(),
        Arc::new(QemuImg::default()),
        Arc::new(Transfer::new().unwrap()),
    );

    let run = |run_id: &str, parent: Option<&str>, kind: BackupKind| BackupRequest {
        vm_id: vm.clone(),
        run_id: run_id.into(),
        parent_run_id: parent.map(str::to_string),
        kind,
        part_size: MIN_PART_SIZE,
        disk_part_urls: (1..=64).map(|i| format!("{base}/{run_id}-p{i}")).collect(),
        state_put_url: format!("{base}/{run_id}-state"),
    };
    let do_run = |r: BackupRequest| {
        let m = &manager;
        let l = &lifecycle;
        async move {
            assert!(m.begin(&r).unwrap());
            let vm = r.vm_id.clone();
            m.run(l, r).await;
            m.status(&vm).unwrap()
        }
    };
    // What vali does on commit: reassemble the parts into one object.
    let publish = |run_id: &str, st: &super::RunStatus| -> ChainPiece {
        let mut objs = store.objects.lock().unwrap();
        let mut whole = Vec::new();
        for p in &st.disk.as_ref().unwrap().parts {
            whole.extend_from_slice(&objs[&format!("{run_id}-p{}", p.part_number)]);
        }
        let sha = hex::encode(Sha256::digest(&whole));
        assert_eq!(sha, st.disk.as_ref().unwrap().sha256_hex);
        let size = whole.len() as u64;
        objs.insert(format!("{run_id}-obj"), whole);
        // The part layout the upload recorded: the restore fetches the
        // object as ranges aligned on it, each checked on its own.
        let parts = &st.disk.as_ref().unwrap().parts;
        ChainPiece {
            url: format!("{base}/{run_id}-obj?X-Amz-Signature=x"),
            sha256_hex: sha,
            size,
            part_size: MIN_PART_SIZE,
            part_sha256_hex: parts.iter().map(|p| p.sha256_hex.clone()).collect(),
        }
    };

    qemu_io(&qmp, &domain, "write -P 0x11 0 1M").await;
    let full = do_run(run("r1", None, BackupKind::Full)).await;
    assert_eq!(full.status, RunPhase::Done, "{:?}", full.error);
    assert_eq!(full.bitmap_present, Some(true));
    assert_eq!(full.boot_counter, Some(5));
    let full_piece = publish("r1", &full);

    qemu_io(&qmp, &domain, "write -P 0x22 4M 3M").await;
    let inc = do_run(run("r2", Some("r1"), BackupKind::Incremental)).await;
    assert_eq!(inc.status, RunPhase::Done, "{:?}", inc.error);
    let inc_piece = publish("r2", &inc);

    // r3's QEMU copy succeeds but its upload fails: the writes it held
    // must reach the next run taken against the same parent.
    qemu_io(&qmp, &domain, "write -P 0x33 5M 64k").await;
    *store.fail_next.lock().unwrap() = PART_ATTEMPTS;
    let lost = do_run(run("r3", Some("r2"), BackupKind::Incremental)).await;
    assert_eq!(lost.status, RunPhase::Failed);
    assert_eq!(
        lost.bitmap_present,
        Some(false),
        "a failed run is no parent"
    );

    qemu_io(&qmp, &domain, "write -P 0x44 20M 1M").await;
    let retry = do_run(run("r4", Some("r2"), BackupKind::Incremental)).await;
    assert_eq!(retry.status, RunPhase::Done, "{:?}", retry.error);
    let retry_piece = publish("r4", &retry);
    eprintln!(
        "sizes: full {:?} inc {:?} retry {:?}",
        full.disk.as_ref().map(|d| d.size),
        inc.disk.as_ref().map(|d| d.size),
        retry.disk.as_ref().map(|d| d.size)
    );

    let overlay = lifecycle.golden_overlay_path(&vm);
    let reference = sha_file(&overlay);
    assert_ne!(reference, full.disk.as_ref().unwrap().sha256_hex);

    // Nothing of ours is left in QEMU but the point bitmaps.
    let nodes = qmp
        .execute(&domain, &qmp::query_named_block_nodes(), None)
        .await
        .unwrap();
    assert!(!qmp::has_node(&nodes, qmp::TARGET_NODE));
    let src = qmp::find_file_node(&nodes, &overlay).unwrap();
    let mut names: Vec<&str> = src.bitmaps.iter().map(|b| b.name.as_str()).collect();
    names.sort_unstable();
    assert_eq!(names, ["hippius-bk-r2", "hippius-bk-r4"]);
    let sets = qmp
        .execute(&domain, &qmp::query_fdsets(), None)
        .await
        .unwrap();
    assert!(qmp::our_fdsets(&sets).is_empty(), "{sets}");
    let jobs = qmp
        .execute(&domain, &qmp::query_jobs(), None)
        .await
        .unwrap();
    assert!(qmp::find_job(&jobs, qmp::JOB_ID).is_none(), "{jobs}");

    // Rebuild r1 + r2 + r4 and compare with the live overlay.
    let state = retry.state.as_ref().unwrap();
    let chain = RestoreChain {
        restore_id: "live-1".into(),
        full: full_piece,
        incrementals: vec![inc_piece, retry_piece],
        state: ChainPiece {
            url: format!("{base}/r4-state"),
            sha256_hex: state.sha256_hex.clone(),
            size: state.size,
            part_size: 0,
            part_sha256_hex: Vec::new(),
        },
    };
    let out = root.join("restore-check");
    BackupChainRestorer::new(Transfer::new().unwrap(), manager.space_ledger())
        .restore(
            &chain,
            &root.join("backup").join(vm.as_str()).join("restore"),
            &out.join("overlay.img"),
            &out.join("state.raw"),
            Some(full.virtual_size.unwrap()),
        )
        .await
        .unwrap();
    assert_eq!(
        sha_file(&out.join("overlay.img")),
        reference,
        "rebuild == live overlay"
    );
    assert_eq!(
        sha_file(&out.join("state.raw")),
        sha_file(&lifecycle.state_disk_path(&vm))
    );

    // A new full keeping r4 prunes r2; an incremental from r2 is refused.
    let full2 = do_run(run("r5", Some("r4"), BackupKind::Full)).await;
    assert_eq!(full2.status, RunPhase::Done, "{:?}", full2.error);
    let stale = do_run(run("r6", Some("r2"), BackupKind::Incremental)).await;
    assert_eq!(stale.status, RunPhase::Failed);
    assert_eq!(stale.error, Some("bitmap-missing"));
    let ok = do_run(run("r7", Some("r5"), BackupKind::Incremental)).await;
    assert_eq!(ok.status, RunPhase::Done, "{:?}", ok.error);
    eprintln!("live chain round trip OK: rebuild sha {reference}");
}

/// An agent that died mid-run leaves a running job, the fd-passed target
/// node, our fdset and the run's new point bitmap inside QEMU. Recreate that
/// state for real (a throttled job that cannot finish) and check startup
/// recovery releases all of it.
#[tokio::test]
#[ignore = "needs a live libvirt domain; see module docs"]
async fn live_restart_recovery_releases_an_interrupted_full() {
    let root = PathBuf::from(std::env::var("HIPPIUS_BK_LIVE_ROOT").unwrap());
    let vm = VmId::new(&std::env::var("HIPPIUS_BK_LIVE_VM").unwrap()).unwrap();
    let domain = DomainId::new(&format!("hippius-tenant-{vm}")).unwrap();
    let overlay = root.join("overlay").join(format!("{vm}.img"));
    let work = root.join("backup").join(vm.as_str());
    std::fs::create_dir_all(&work).unwrap();
    let qmp = Arc::new(VirshQmp::default());

    let nodes = qmp
        .execute(&domain, &qmp::query_named_block_nodes(), None)
        .await
        .unwrap();
    let src = qmp::find_file_node(&nodes, &overlay).unwrap();
    let target = work.join("target.raw");
    let f = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(&target)
        .unwrap();
    f.set_len(src.virtual_size).unwrap();
    let ret = qmp
        .execute(&domain, &qmp::add_fd(), Some(f.try_clone().unwrap()))
        .await
        .unwrap();
    let fdset = qmp::parse_add_fd(&ret).unwrap();
    qmp.execute(
        &domain,
        &qmp::blockdev_add_target(qmp::TargetFormat::Raw, fdset, false),
        None,
    )
    .await
    .unwrap();
    let tx = qmp::transaction_full(&src.node_name, "hippius-bk-crashed", 1024);
    qmp.execute(&domain, &tx, None).await.unwrap();
    let jobs = qmp
        .execute(&domain, &qmp::query_jobs(), None)
        .await
        .unwrap();
    assert_eq!(
        qmp::find_job(&jobs, qmp::JOB_ID).unwrap().status,
        "running",
        "{jobs}"
    );
    std::fs::write(
        work.join(super::capture::INFLIGHT_MARKER),
        serde_json::to_vec(&super::capture::InflightMarker {
            new_bitmap: Some("hippius-bk-crashed".into()),
            source_path: overlay.clone(),
        })
        .unwrap(),
    )
    .unwrap();
    drop(f);

    let manager = BackupManager::new(
        qmp.clone(),
        Arc::new(QemuImg::default()),
        Arc::new(Transfer::new().unwrap()),
    );
    manager.recover_on_startup(&root.join("backup")).await;

    let jobs = qmp
        .execute(&domain, &qmp::query_jobs(), None)
        .await
        .unwrap();
    assert!(qmp::find_job(&jobs, qmp::JOB_ID).is_none(), "{jobs}");
    let nodes = qmp
        .execute(&domain, &qmp::query_named_block_nodes(), None)
        .await
        .unwrap();
    assert!(!qmp::has_node(&nodes, qmp::TARGET_NODE));
    let src = qmp::find_file_node(&nodes, &overlay).unwrap();
    assert!(
        src.bitmap("hippius-bk-crashed").is_none(),
        "the interrupted run's point is dropped"
    );
    let sets = qmp
        .execute(&domain, &qmp::query_fdsets(), None)
        .await
        .unwrap();
    assert!(qmp::our_fdsets(&sets).is_empty(), "{sets}");
    assert_eq!(std::fs::read_dir(&work).unwrap().count(), 0);
    eprintln!("live restart recovery OK");
}
