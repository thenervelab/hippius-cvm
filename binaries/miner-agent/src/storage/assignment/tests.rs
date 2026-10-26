use super::*;
use crate::config::DedicatedDiskConfig;
use crate::storage::dedicated::DiskFact;
use std::sync::Arc;

const TIB_MB: u64 = 1024 * 1024;

/// Facts the test sets, counting refreshes.
#[derive(Default)]
struct Facts {
    facts: Mutex<Option<DiskFacts>>,
    refreshes: Mutex<u32>,
}

impl Facts {
    fn set(&self, facts: Option<DiskFacts>) {
        *self.facts.lock().unwrap() = facts;
    }
}

impl FactsSource for Arc<Facts> {
    fn facts(&self) -> std::result::Result<DiskFacts, &'static str> {
        self.facts.lock().unwrap().clone().ok_or("disk-facts-stale")
    }
    fn refresh(&self) {
        *self.refreshes.lock().unwrap() += 1;
    }
}

/// A helper that records its calls and answers as told.
#[derive(Default)]
struct Helper {
    missing: bool,
    hold_err: Mutex<Option<&'static str>>,
    release_err: Mutex<Option<&'static str>>,
    calls: Mutex<Vec<String>>,
    /// Udev rules installed (`rule_ids`).
    rules: Mutex<Vec<String>>,
    /// Run on every unhold (a concurrent claim landing meanwhile).
    on_unhold: Mutex<Option<Box<dyn Fn() + Send>>>,
    unhold_err: Mutex<Option<&'static str>>,
}

impl Helper {
    fn calls(&self) -> Vec<String> {
        self.calls.lock().unwrap().clone()
    }
}

impl DedicatedHelper for Arc<Helper> {
    fn installed(&self) -> bool {
        !self.missing
    }
    fn hold(&self, disk_id: &str) -> std::result::Result<(), &'static str> {
        self.calls.lock().unwrap().push(format!("hold {disk_id}"));
        self.hold_err.lock().unwrap().map_or(Ok(()), Err)
    }
    fn unhold(&self, disk_id: &str) -> std::result::Result<(), &'static str> {
        self.calls.lock().unwrap().push(format!("unhold {disk_id}"));
        if let Some(hook) = self.on_unhold.lock().unwrap().as_ref() {
            hook();
        }
        self.unhold_err.lock().unwrap().map_or(Ok(()), Err)
    }
    fn rule_ids(&self) -> Vec<String> {
        self.rules.lock().unwrap().clone()
    }
    fn release(&self, disk_id: &str) -> std::result::Result<(), &'static str> {
        self.calls
            .lock()
            .unwrap()
            .push(format!("release {disk_id}"));
        self.release_err.lock().unwrap().map_or(Ok(()), Err)
    }
}

fn fact(identity: &str) -> DiskFact {
    DiskFact {
        size_mb: 18 * TIB_MB,
        error: String::new(),
        identity: Some(identity.into()),
        dev: Some("250:1".into()),
        offline: false,
    }
}

struct World {
    dir: tempfile::TempDir,
    facts: Arc<Facts>,
    helper: Arc<Helper>,
    disks: DedicatedDisks,
    declared: Vec<DedicatedDiskConfig>,
}

impl World {
    /// Two declared, clean, bound disks: `wwn-0x1` (`naa.1`) and `wwn-0x2`
    /// (`naa.2`).
    fn new() -> Self {
        Self::with_helper(Helper::default())
    }

    fn with_helper(helper: Helper) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let facts = Arc::new(Facts::default());
        let mut f = DiskFacts {
            collected_at_unix: 1,
            disks: BTreeMap::new(),
        };
        f.disks.insert("wwn-0x1".into(), fact("naa.1"));
        let mut two = fact("naa.2");
        two.dev = Some("250:2".into());
        f.disks.insert("wwn-0x2".into(), two);
        facts.set(Some(f));
        let mut ids = IdentityMap::default();
        ids.disks.insert("wwn-0x1".into(), "naa.1".into());
        ids.disks.insert("wwn-0x2".into(), "naa.2".into());
        ids.save(dir.path()).unwrap();
        let helper = Arc::new(helper);
        let disks = DedicatedDisks::new(
            Box::new(Arc::clone(&facts)),
            Box::new(Arc::clone(&helper)),
            Arc::default(),
        );
        let declared = vec![cfg("wwn-0x1"), cfg("wwn-0x2")];
        Self {
            dir,
            facts,
            helper,
            disks,
            declared,
        }
    }

    fn root(&self) -> &Path {
        self.dir.path()
    }

    fn prepare(&self, vm: &str, extra: &[ExtraDisk], require_existing: bool) -> Result<Prepared> {
        let storage = self.storage();
        self.disks.prepare(
            &Ctx {
                state_root: self.root(),
                storage: &storage,
            },
            &vid(vm),
            extra,
            require_existing,
        )
    }

    /// The storage set in force: the implicit pool, the declared disks.
    fn storage(&self) -> crate::storage::state::StorageState {
        crate::storage::state::StorageState::new(crate::storage::state::EffectiveStorage::local(
            Arc::new(crate::storage::StoragePools::implicit(
                self.root().to_path_buf(),
                0,
            )),
            self.declared.clone(),
            Default::default(),
        ))
    }

    fn edit_fact(&self, id: &str, edit: impl FnOnce(&mut DiskFact)) {
        let mut f = self.facts.facts().unwrap();
        edit(f.disks.get_mut(id).unwrap());
        self.facts.set(Some(f));
    }
}

fn cfg(id: &str) -> DedicatedDiskConfig {
    DedicatedDiskConfig {
        id: id.into(),
        state: StorageDesiredStateConfig::Active,
    }
}

fn vid(s: &str) -> VmId {
    VmId::new(s).unwrap()
}

fn extra(slot: &str, disk_id: &str) -> ExtraDisk {
    ExtraDisk {
        slot: slot.into(),
        kind: KIND_DEDICATED.into(),
        disk_id: disk_id.into(),
    }
}

fn refused(r: Result<Prepared>) -> &'static str {
    match r {
        Err(MinerAgentError::DedicatedRefused(c)) => c,
        other => panic!("expected a 409 refusal, got {other:?}"),
    }
}

fn unavailable(r: Result<Prepared>) -> &'static str {
    match r {
        Err(MinerAgentError::DedicatedUnavailable(c)) => c,
        other => panic!("expected a 503, got {other:?}"),
    }
}

#[test]
fn slots_are_x0_to_x23_without_leading_zeros() {
    assert_eq!(slot_index("x0"), Some(0));
    assert_eq!(slot_index("x9"), Some(9));
    assert_eq!(slot_index("x23"), Some(23));
    for bad in ["x24", "x01", "x", "y1", "x-1", "X1", "x100", "x1 ", ""] {
        assert_eq!(slot_index(bad), None, "{bad:?}");
    }
}

#[test]
fn every_shape_refusal_has_its_code() {
    let ok = [extra("x0", "wwn-0x1"), extra("x3", "wwn-0x2")];
    assert!(validate_shape(&ok).is_ok());
    assert!(validate_shape(&[]).is_ok());
    let code = |e: &[ExtraDisk]| match validate_shape(e) {
        Err(MinerAgentError::DedicatedInvalid(c)) => c,
        other => panic!("{other:?}"),
    };
    let nine: Vec<ExtraDisk> = (0..9)
        .map(|i| extra(&format!("x{i}"), &format!("wwn-0x{i}")))
        .collect();
    assert_eq!(code(&nine), "too-many");
    assert!(validate_shape(&nine[..8]).is_ok());
    assert_eq!(code(&[extra("x24", "wwn-0x1")]), "slot");
    let mut kind = extra("x0", "wwn-0x1");
    kind.kind = "pool".into();
    assert_eq!(code(&[kind]), "kind");
    assert_eq!(code(&[extra("x0", "sdb")]), "disk-id");
    assert_eq!(code(&[extra("x0", "wwn-0x1-part1")]), "disk-id");
    assert_eq!(
        code(&[extra("x0", "wwn-0x1"), extra("x0", "wwn-0x2")]),
        "slot-duplicate"
    );
    assert_eq!(
        code(&[extra("x0", "wwn-0x1"), extra("x1", "wwn-0x1")]),
        "disk-duplicate"
    );
}

#[test]
fn refusal_classes_name_the_slot_and_map_to_their_status() {
    assert_eq!(SlotRefusal::Replaced.class(1), "dedicated-disk-replaced:x1");
    assert_eq!(
        SlotRefusal::Unavailable.class(23),
        "dedicated-disk-unavailable:x23"
    );
    assert_eq!(SlotRefusal::Busy.class(0), "dedicated-disk-busy:x0");
    assert!(matches!(
        SlotRefusal::Mismatch.error(2),
        MinerAgentError::DedicatedRefused("dedicated-disk-mismatch:x2")
    ));
    assert!(matches!(
        SlotRefusal::HoldFailed.error(4),
        MinerAgentError::DedicatedUnavailable("dedicated-hold-failed:x4")
    ));
}

#[test]
fn a_first_launch_claims_free_disks_and_records_them_in_slot_order() {
    let w = World::new();
    let p = w
        .prepare(
            "vm-a",
            &[extra("x1", "wwn-0x2"), extra("x0", "wwn-0x1")],
            false,
        )
        .unwrap();
    assert!(p.created);
    assert_eq!(
        p.attach,
        vec![
            AttachDisk {
                slot: "x0".into(),
                disk_id: "wwn-0x1".into()
            },
            AttachDisk {
                slot: "x1".into(),
                disk_id: "wwn-0x2".into()
            },
        ]
    );
    let record = read_vm(w.root(), "vm-a").unwrap().unwrap();
    assert_eq!(record.disks[0].identity, "naa.1");
    assert_eq!(record.disks[1].identity, "naa.2");
    // Fresh facts were asked for first.
    assert_eq!(*w.facts.refreshes.lock().unwrap(), 1);
    // Nothing asked: nothing done, no collector run.
    let none = w.prepare("vm-b", &[], false).unwrap();
    assert_eq!(none, Prepared::default());
    assert_eq!(*w.facts.refreshes.lock().unwrap(), 1);
}

#[test]
fn a_disk_is_refused_for_every_reason_with_its_slot() {
    let w = World::new();
    // Not declared.
    assert_eq!(
        refused(w.prepare("vm-a", &[extra("x2", "wwn-0x9")], false)),
        "dedicated-disk-unknown:x2"
    );
    // Held by another VM.
    w.prepare("vm-b", &[extra("x0", "wwn-0x1")], false).unwrap();
    assert_eq!(
        refused(w.prepare("vm-a", &[extra("x0", "wwn-0x1")], false)),
        "dedicated-disk-assigned:x0"
    );
    // Awaiting its wipe.
    write_release(
        w.root(),
        "wwn-0x2",
        &ReleaseRecord {
            vm_id: "old".into(),
            slot: "x0".into(),
            identity: "naa.2".into(),
        },
    )
    .unwrap();
    assert_eq!(
        refused(w.prepare("vm-a", &[extra("x1", "wwn-0x2")], false)),
        "dedicated-disk-releasing:x1"
    );
    remove_release(w.root(), "wwn-0x2").unwrap();
    // Another device behind the name.
    w.edit_fact("wwn-0x2", |f| f.identity = Some("naa.other".into()));
    assert_eq!(
        refused(w.prepare("vm-a", &[extra("x1", "wwn-0x2")], false)),
        "dedicated-disk-replaced:x1"
    );
    // Gone after having been seen.
    let mut f = w.facts.facts().unwrap();
    f.disks.remove("wwn-0x2");
    w.facts.set(Some(f));
    assert_eq!(
        refused(w.prepare("vm-a", &[extra("x1", "wwn-0x2")], false)),
        "dedicated-disk-failed:x1"
    );
    // Not one of ours to read any more: no record was written.
    assert_eq!(read_vm(w.root(), "vm-a"), Ok(None));
}

#[test]
fn a_disk_must_be_clean_bound_active_and_backed_by_the_helper() {
    // A signature (or any inventory refusal).
    let w = World::new();
    w.edit_fact("wwn-0x1", |f| f.error = "disk-has-signature".into());
    assert_eq!(
        refused(w.prepare("vm-a", &[extra("x0", "wwn-0x1")], false)),
        "dedicated-disk-unavailable:x0"
    );
    // Draining.
    let mut w = World::new();
    w.declared[0].state = StorageDesiredStateConfig::Draining;
    assert_eq!(
        refused(w.prepare("vm-a", &[extra("x0", "wwn-0x1")], false)),
        "dedicated-disk-draining:x0"
    );
    // Not yet bound to an identity (no heartbeat has offered it).
    let w = World::new();
    let mut ids = IdentityMap::load(w.root()).unwrap();
    ids.disks.remove("wwn-0x1");
    ids.save(w.root()).unwrap();
    assert_eq!(
        refused(w.prepare("vm-a", &[extra("x0", "wwn-0x1")], false)),
        "dedicated-disk-unavailable:x0"
    );
    // No privileged helper on this host: never given.
    let w = World::with_helper(Helper {
        missing: true,
        ..Helper::default()
    });
    assert_eq!(
        refused(w.prepare("vm-a", &[extra("x0", "wwn-0x1")], false)),
        "dedicated-disk-unavailable:x0"
    );
    // Facts the agent cannot use: retryable, never a guess.
    let w = World::new();
    w.facts.set(None);
    assert_eq!(
        unavailable(w.prepare("vm-a", &[extra("x0", "wwn-0x1")], false)),
        "dedicated-facts-unavailable"
    );
    // An unreadable record is never read as "no disks".
    let w = World::new();
    std::fs::create_dir_all(w.root().join(VM_DIR)).unwrap();
    std::fs::write(vm_record_path(w.root(), "vm-a"), b"{").unwrap();
    assert_eq!(
        unavailable(w.prepare("vm-a", &[extra("x0", "wwn-0x1")], false)),
        "dedicated-record-unreadable"
    );
}

#[test]
fn a_relaunch_reattaches_exactly_the_recorded_disks_after_an_identity_check() {
    let w = World::new();
    let first = w
        .prepare(
            "vm-a",
            &[extra("x0", "wwn-0x1"), extra("x1", "wwn-0x2")],
            false,
        )
        .unwrap();
    // A restart of the agent: a new service over the same state root.
    let again = DedicatedDisks::new(
        Box::new(Arc::clone(&w.facts)),
        Box::new(Arc::clone(&w.helper)),
        Arc::default(),
    );
    let storage = w.storage();
    let ctx = Ctx {
        state_root: w.root(),
        storage: &storage,
    };
    let same = [extra("x1", "wwn-0x2"), extra("x0", "wwn-0x1")];
    let p = again.prepare(&ctx, &vid("vm-a"), &same, true).unwrap();
    assert!(!p.created);
    assert_eq!(p.attach, first.attach);
    // Not the same set: refused, never another disk.
    for other in [
        vec![extra("x0", "wwn-0x1")],
        vec![extra("x0", "wwn-0x2"), extra("x1", "wwn-0x1")],
        vec![],
    ] {
        assert_eq!(
            refused(again.prepare(&ctx, &vid("vm-a"), &other, true)),
            "dedicated-order-mismatch"
        );
    }
    // Another device behind a recorded name: the start is refused.
    w.edit_fact("wwn-0x2", |f| f.identity = Some("naa.swapped".into()));
    assert_eq!(
        refused(again.prepare(&ctx, &vid("vm-a"), &same, true)),
        "dedicated-disk-mismatch:x1"
    );
    w.edit_fact("wwn-0x2", |f| f.identity = None);
    assert_eq!(
        refused(again.prepare(&ctx, &vid("vm-a"), &same, true)),
        "dedicated-disk-mismatch:x1"
    );
    // The host mounted it meanwhile.
    w.edit_fact("wwn-0x2", |f| {
        f.identity = Some("naa.2".into());
        f.error = "disk-in-use".into();
    });
    assert_eq!(
        refused(again.prepare(&ctx, &vid("vm-a"), &same, true)),
        "dedicated-disk-busy:x1"
    );
    // A guest-written signature is the tenant's data, not a refusal.
    w.edit_fact("wwn-0x2", |f| f.error = "disk-has-signature".into());
    assert_eq!(
        again
            .prepare(&ctx, &vid("vm-a"), &same, true)
            .unwrap()
            .attach
            .len(),
        2
    );
    // Gone or offline: started without it (the guest sees it missing).
    w.edit_fact("wwn-0x2", |f| f.offline = true);
    let p = again.prepare(&ctx, &vid("vm-a"), &same, true).unwrap();
    assert_eq!(p.attach.len(), 1);
    assert_eq!(p.attach[0].disk_id, "wwn-0x1");
    let mut f = w.facts.facts().unwrap();
    f.disks.remove("wwn-0x2");
    w.facts.set(Some(f));
    assert_eq!(
        again
            .prepare(&ctx, &vid("vm-a"), &same, true)
            .unwrap()
            .attach
            .len(),
        1
    );
    // Stale facts: retryable.
    w.facts.set(None);
    assert_eq!(
        unavailable(again.prepare(&ctx, &vid("vm-a"), &same, true)),
        "dedicated-facts-unavailable"
    );
    // The record is untouched by any of it.
    assert_eq!(read_vm(w.root(), "vm-a").unwrap().unwrap().disks.len(), 2);
}

#[test]
fn a_relaunch_never_claims_disks_a_vm_did_not_have() {
    let w = World::new();
    assert_eq!(
        refused(w.prepare("vm-a", &[extra("x0", "wwn-0x1")], true)),
        "dedicated-order-mismatch"
    );
    assert_eq!(read_vm(w.root(), "vm-a"), Ok(None));
    // Without disks, nothing to say.
    assert_eq!(w.prepare("vm-a", &[], true).unwrap(), Prepared::default());
}

#[test]
fn a_failed_first_launch_gives_its_disks_back_but_never_a_relaunchs() {
    let w = World::new();
    let p = w.prepare("vm-a", &[extra("x0", "wwn-0x1")], false).unwrap();
    w.disks.rollback(w.root(), &vid("vm-a"), &p);
    assert_eq!(read_vm(w.root(), "vm-a"), Ok(None));
    assert_eq!(w.helper.calls(), vec!["unhold wwn-0x1", "unhold wwn-0x1"]);
    // Free again for another VM.
    assert!(w.prepare("vm-b", &[extra("x0", "wwn-0x1")], false).is_ok());
    // A relaunch's prepare did not create the record: kept.
    let p = w.prepare("vm-b", &[extra("x0", "wwn-0x1")], false).unwrap();
    assert!(!p.created);
    w.disks.rollback(w.root(), &vid("vm-b"), &p);
    assert!(read_vm(w.root(), "vm-b").unwrap().is_some());
}

#[test]
fn confirm_catches_a_record_taken_back_meanwhile() {
    let w = World::new();
    let p = w.prepare("vm-a", &[extra("x0", "wwn-0x1")], false).unwrap();
    assert!(w.disks.confirm(w.root(), &vid("vm-a"), &p).is_ok());
    remove_vm(w.root(), "vm-a").unwrap();
    assert!(matches!(
        w.disks.confirm(w.root(), &vid("vm-a"), &p),
        Err(MinerAgentError::DedicatedUnavailable(
            "dedicated-record-lost"
        ))
    ));
    // Nothing to confirm without disks.
    assert!(w
        .disks
        .confirm(w.root(), &vid("vm-a"), &Prepared::default())
        .is_ok());
}

#[test]
fn hold_failures_map_to_their_refusals() {
    let w = World::new();
    let attach = vec![AttachDisk {
        slot: "x3".into(),
        disk_id: "wwn-0x1".into(),
    }];
    assert!(w.disks.hold_all(&attach).is_ok());
    for (code, want) in [
        ("hold-busy", "dedicated-disk-busy:x3"),
        ("hold-identity-mismatch", "dedicated-disk-mismatch:x3"),
    ] {
        *w.helper.hold_err.lock().unwrap() = Some(code);
        assert!(
            matches!(w.disks.hold_all(&attach), Err(MinerAgentError::DedicatedRefused(c)) if c == want)
        );
    }
    *w.helper.hold_err.lock().unwrap() = Some("helper-missing");
    assert!(matches!(
        w.disks.hold_all(&attach),
        Err(MinerAgentError::DedicatedUnavailable(
            "dedicated-hold-failed:x3"
        ))
    ));
}

#[test]
fn release_queues_wipes_and_forgets_the_vm_and_a_failed_wipe_is_retried() {
    let w = World::new();
    w.prepare(
        "vm-a",
        &[extra("x0", "wwn-0x1"), extra("x1", "wwn-0x2")],
        false,
    )
    .unwrap();
    *w.helper.release_err.lock().unwrap() = Some("release-device-open");
    // §24 only queues (file writes): nothing touches a disk on its path.
    let queued = w.disks.release_vm(w.root(), &vid("vm-a")).unwrap();
    assert_eq!(queued, vec!["wwn-0x1".to_string(), "wwn-0x2".to_string()]);
    assert!(w.helper.calls().is_empty());
    assert_eq!(read_vm(w.root(), "vm-a"), Ok(None));
    let pending = read_release(w.root(), "wwn-0x1").unwrap().unwrap();
    assert_eq!(
        pending,
        ReleaseRecord {
            vm_id: "vm-a".into(),
            slot: "x0".into(),
            identity: "naa.1".into()
        }
    );
    assert!(read_release(w.root(), "wwn-0x2").unwrap().is_some());
    // The caller's detached wipe of just these disks: the hold is dropped
    // before each.
    assert_eq!(w.disks.drain_disks(w.root(), Some(&queued)), 0);
    assert_eq!(
        w.helper.calls(),
        vec![
            "unhold wwn-0x1",
            "release wwn-0x1",
            "unhold wwn-0x2",
            "release wwn-0x2"
        ]
    );
    // A releasing disk is not given out.
    assert_eq!(
        refused(w.prepare("vm-b", &[extra("x0", "wwn-0x1")], false)),
        "dedicated-disk-releasing:x0"
    );
    // The drain retries; a wiped disk leaves the queue and the collector
    // re-reads the host.
    *w.helper.release_err.lock().unwrap() = None;
    let before = *w.facts.refreshes.lock().unwrap();
    assert_eq!(w.disks.drain_disks(w.root(), None), 2);
    assert_eq!(read_release(w.root(), "wwn-0x1"), Ok(None));
    assert_eq!(*w.facts.refreshes.lock().unwrap(), before + 1);
    assert!(w.prepare("vm-b", &[extra("x0", "wwn-0x1")], false).is_ok());
    // A VM without disks: nothing.
    assert!(w
        .disks
        .release_vm(w.root(), &vid("vm-none"))
        .unwrap()
        .is_empty());
}

#[test]
fn the_drain_never_wipes_a_disk_a_vm_record_names() {
    let w = World::new();
    w.prepare("vm-a", &[extra("x0", "wwn-0x1")], false).unwrap();
    // A stray release record for a held disk.
    write_release(
        w.root(),
        "wwn-0x1",
        &ReleaseRecord {
            vm_id: "old".into(),
            slot: "x0".into(),
            identity: "naa.1".into(),
        },
    )
    .unwrap();
    assert_eq!(w.disks.drain_disks(w.root(), None), 0);
    assert!(w.helper.calls().is_empty());
}

#[test]
fn owners_fold_into_the_heartbeat_report() {
    let w = World::new();
    w.prepare("vm-a", &[extra("x0", "wwn-0x1")], false).unwrap();
    write_release(
        w.root(),
        "wwn-0x2",
        &ReleaseRecord {
            vm_id: "old".into(),
            slot: "x0".into(),
            identity: "naa.2".into(),
        },
    )
    .unwrap();
    let owners = owners(w.root()).unwrap();
    let facts = w.facts.facts().unwrap();
    let report = |id: &str, state| DedicatedDiskReport {
        id: id.into(),
        size_mb: 1,
        state,
        vm: String::new(),
        error: "disk-has-signature".into(),
    };
    let base = vec![
        report("wwn-0x1", DedicatedDiskState::Unavailable),
        report("wwn-0x2", DedicatedDiskState::Unavailable),
    ];
    let mut reports = base.clone();
    apply_owners(&mut reports, &owners, Ok(&facts));
    assert_eq!(reports[0].state, DedicatedDiskState::Assigned);
    assert_eq!(reports[0].vm, "vm-a");
    assert_eq!(reports[0].error, "");
    assert_eq!(reports[0].size_mb, 18 * TIB_MB);
    assert_eq!(reports[1].state, DedicatedDiskState::Unavailable);
    assert_eq!(reports[1].error, "disk-release-pending");
    // Gone, offline, another device: never `assigned`.
    let mut gone = facts.clone();
    gone.disks.remove("wwn-0x1");
    let mut reports = base.clone();
    apply_owners(&mut reports, &owners, Ok(&gone));
    assert_eq!(reports[0].state, DedicatedDiskState::Failed);
    assert_eq!(
        (reports[0].vm.as_str(), reports[0].error.as_str()),
        ("", "disk-not-found")
    );
    let mut offline = facts.clone();
    offline.disks.get_mut("wwn-0x1").unwrap().offline = true;
    let mut reports = base.clone();
    apply_owners(&mut reports, &owners, Ok(&offline));
    assert_eq!(reports[0].state, DedicatedDiskState::Failed);
    let mut swapped = facts.clone();
    swapped.disks.get_mut("wwn-0x1").unwrap().identity = Some("naa.x".into());
    let mut reports = base.clone();
    apply_owners(&mut reports, &owners, Ok(&swapped));
    assert_eq!(reports[0].state, DedicatedDiskState::Replaced);
    assert_eq!(reports[0].vm, "");
    // Unusable facts: still assigned (the agent knows), the reason said.
    let mut reports = base.clone();
    apply_owners(&mut reports, &owners, Err("disk-facts-stale"));
    assert_eq!(reports[0].state, DedicatedDiskState::Assigned);
    assert_eq!(reports[0].error, "disk-facts-stale");
    // A held disk the declaration dropped is still reported.
    let mut reports = vec![];
    apply_owners(&mut reports, &owners, Ok(&facts));
    assert_eq!(reports.len(), 2);
    assert_eq!(reports[0].id, "wwn-0x1");
    assert_eq!(reports[0].state, DedicatedDiskState::Assigned);
    // The wire rules hold.
    let r = hippius_types::storage_report::StorageReport {
        disk_pools: vec![hippius_types::storage_report::DiskPoolReport {
            id: "default".into(),
            class: hippius_types::storage_report::PoolClass::Undeclared,
            total_gb: 0,
            available_gb: 0,
            budget_gb: 0,
            committed_gb: 0,
            os_disks: true,
            state: hippius_types::storage_report::PoolState::Active,
            error: String::new(),
        }],
        dedicated_disks: reports,
        storage_config_revision: 0,
    };
    assert_eq!(r.validate(), Ok(()));
}

#[test]
fn a_pinned_vm_is_refused_and_an_unreadable_record_is_not_unpinned() {
    let w = World::new();
    assert!(w.disks.check_not_pinned(w.root(), &vid("vm-a")).is_ok());
    w.prepare("vm-a", &[extra("x0", "wwn-0x1")], false).unwrap();
    assert!(matches!(
        w.disks.check_not_pinned(w.root(), &vid("vm-a")),
        Err(MinerAgentError::DedicatedRefused("dedicated-pinned"))
    ));
    std::fs::write(vm_record_path(w.root(), "vm-b"), b"not json").unwrap();
    assert!(matches!(
        w.disks.check_not_pinned(w.root(), &vid("vm-b")),
        Err(MinerAgentError::DedicatedUnavailable(
            "dedicated-record-unreadable"
        ))
    ));
    assert!(cmdline_is_pinned(
        "quiet hippius.dedicated=x0:16000 panic=0"
    ));
    assert!(!cmdline_is_pinned(
        "quiet hippius.dedicatedx=1 xhippius.dedicated=1"
    ));
}

#[test]
fn the_reboot_watcher_restart_rechecks_identity_and_holds() {
    let w = World::new();
    assert!(w.disks.check_before_restart(w.root(), &vid("vm-a")).is_ok());
    assert!(w.helper.calls().is_empty());
    w.prepare("vm-a", &[extra("x0", "wwn-0x1")], false).unwrap();
    assert!(w.disks.check_before_restart(w.root(), &vid("vm-a")).is_ok());
    assert_eq!(w.helper.calls(), vec!["hold wwn-0x1"]);
    w.edit_fact("wwn-0x1", |f| f.identity = Some("naa.swapped".into()));
    assert!(matches!(
        w.disks.check_before_restart(w.root(), &vid("vm-a")),
        Err(MinerAgentError::DedicatedRefused(
            "dedicated-disk-mismatch:x0"
        ))
    ));
    w.edit_fact("wwn-0x1", |f| {
        f.identity = Some("naa.1".into());
        f.offline = true;
    });
    assert!(matches!(
        w.disks.check_before_restart(w.root(), &vid("vm-a")),
        Err(MinerAgentError::DedicatedRefused(
            "dedicated-disk-failed:x0"
        ))
    ));
    w.facts.set(None);
    assert!(matches!(
        w.disks.check_before_restart(w.root(), &vid("vm-a")),
        Err(MinerAgentError::DedicatedUnavailable(
            "dedicated-facts-unavailable"
        ))
    ));
}

#[test]
fn start_holds_every_recorded_disk() {
    let w = World::new();
    w.prepare("vm-a", &[extra("x0", "wwn-0x2")], false).unwrap();
    w.disks.hold_recorded(w.root());
    assert_eq!(w.helper.calls(), vec!["hold wwn-0x2"]);
}

#[test]
fn target_devices_follow_the_os_disks() {
    assert_eq!(AttachDisk::target_dev(0), "vdf");
    assert_eq!(AttachDisk::target_dev(7), "vdm");
    assert_eq!(
        AttachDisk {
            slot: "x0".into(),
            disk_id: "wwn-0x1".into()
        }
        .source(),
        Path::new("/dev/disk/by-id/wwn-0x1")
    );
}

#[test]
fn the_systemd_helper_is_installed_only_with_both_units_and_reads_fresh_verdicts() {
    let dir = tempfile::tempdir().unwrap();
    let helper = SystemdHelper {
        unit_dir: dir.path().to_path_buf(),
        run_dir: dir.path().join("run"),
        udev_rules_dir: dir.path().join("rules"),
        systemctl: "systemctl".into(),
    };
    assert!(!helper.installed());
    std::fs::write(dir.path().join(format!("{HOLD_UNIT}.service")), "").unwrap();
    assert!(!helper.installed());
    std::fs::write(dir.path().join(format!("{RELEASE_UNIT}.service")), "").unwrap();
    assert!(helper.installed());
    assert_eq!(
        SystemdHelper::unit(HOLD_UNIT, "wwn-0x5000c500a1b2c3d4"),
        Ok("hippius-miner-dedicated-hold@wwn-0x5000c500a1b2c3d4.service".to_string())
    );
    assert_eq!(
        SystemdHelper::unit(RELEASE_UNIT, "../etc"),
        Err("helper-bad-disk-id")
    );
    // Not installed: no systemctl call at all.
    let bare = SystemdHelper {
        unit_dir: dir.path().join("none"),
        run_dir: dir.path().join("run"),
        udev_rules_dir: dir.path().join("rules"),
        systemctl: "systemctl".into(),
    };
    assert_eq!(bare.hold("wwn-0x1"), Err("helper-missing"));
    assert_eq!(bare.release("wwn-0x1"), Err("helper-missing"));
}

#[test]
fn the_measured_token_names_exactly_the_ordered_slots() {
    let disks = [extra("x0", "wwn-0x1"), extra("x2", "wwn-0x2")];
    assert_eq!(
        cmdline_slots("quiet hippius.dedicated=x0:16000,x2:22300 panic=0"),
        Ok(Some([0, 2].into()))
    );
    assert_eq!(cmdline_slots("quiet panic=0"), Ok(None));
    // §9: an integrity slot (`:i`) is the same slot to the agent.
    assert_eq!(
        cmdline_slots("quiet hippius.dedicated=x0:16000:i,x2:22300 panic=0"),
        Ok(Some([0, 2].into()))
    );
    assert_eq!(
        cmdline_slots("hippius.dedicated=x0:16000:i,x2:22300:i"),
        Ok(Some([0, 2].into()))
    );
    for bad in [
        "hippius.dedicated=x0:16000:j",
        "hippius.dedicated=x0:16000:i:i",
        "hippius.dedicated=x0:16000i",
        "hippius.dedicated=x0::i",
        "hippius.dedicated=x0:i",
        "hippius.dedicated=x0:0:i",
        "hippius.dedicated=x0:100:i,x0:200",
    ] {
        assert_eq!(cmdline_slots(bad), Err("cmdline-malformed"), "{bad}");
    }
    for bad in [
        "hippius.dedicated=",
        "hippius.dedicated=x0",
        "hippius.dedicated=x0:",
        "hippius.dedicated=x0:0",
        "hippius.dedicated=x0:+5",
        "hippius.dedicated=x0:1e3",
        "hippius.dedicated=x24:100",
        "hippius.dedicated=x0:100,x0:200",
        "hippius.dedicated=x0:100 hippius.dedicated=x1:100",
    ] {
        assert_eq!(cmdline_slots(bad), Err("cmdline-malformed"), "{bad}");
    }
    let code = |cmdline: &str, extra: &[ExtraDisk]| match check_anchor(cmdline, extra) {
        Ok(()) => "",
        Err(MinerAgentError::DedicatedInvalid(c)) => c,
        Err(other) => panic!("{other:?}"),
    };
    assert_eq!(code("q hippius.dedicated=x0:16000,x2:16000", &disks), "");
    assert_eq!(code("q", &[]), "");
    assert_eq!(code("q", &disks), "cmdline-missing");
    assert_eq!(
        code("q hippius.dedicated=x0:16000", &[]),
        "cmdline-without-disks"
    );
    assert_eq!(
        code("q hippius.dedicated=x0:16000", &disks),
        "cmdline-slots"
    );
    assert_eq!(
        code("q hippius.dedicated=x0:16000,x1:1,x2:1", &disks),
        "cmdline-slots"
    );
    assert_eq!(code("q hippius.dedicated=x0", &disks), "cmdline-malformed");
}

#[tokio::test]
async fn the_vm_operations_lock_serialises_one_vm_and_not_two() {
    let w = World::new();
    let a = w.disks.vm_ops(&vid("vm-a")).await;
    // Another VM is not held up.
    let b = w.disks.vm_ops(&vid("vm-b")).await;
    drop(b);
    // The same VM waits for the first holder.
    let waiting = tokio::time::timeout(
        std::time::Duration::from_millis(50),
        w.disks.vm_ops(&vid("vm-a")),
    )
    .await;
    assert!(waiting.is_err(), "a second holder got the lock");
    drop(a);
    let _again = w.disks.vm_ops(&vid("vm-a")).await;
}

#[test]
fn confirm_needs_the_same_slots_too() {
    let w = World::new();
    let p = w
        .prepare(
            "vm-a",
            &[extra("x0", "wwn-0x1"), extra("x1", "wwn-0x2")],
            false,
        )
        .unwrap();
    // Rewritten meanwhile with the slots swapped.
    let mut record = read_vm(w.root(), "vm-a").unwrap().unwrap();
    record.disks[0].slot = "x1".into();
    record.disks[1].slot = "x0".into();
    write_vm(w.root(), "vm-a", &record).unwrap();
    assert!(matches!(
        w.disks.confirm(w.root(), &vid("vm-a"), &p),
        Err(MinerAgentError::DedicatedUnavailable(
            "dedicated-record-lost"
        ))
    ));
}

#[test]
fn a_claim_reads_the_declaration_in_force_at_claim_time() {
    let w = World::new();
    let storage = w.storage();
    // The route replaced the set (the disk dropped) before the claim ran.
    let mut set = (*storage.current()).clone();
    set.dedicated.retain(|d| d.id != "wwn-0x1");
    storage.replace(set);
    let r = w.disks.prepare(
        &Ctx {
            state_root: w.root(),
            storage: &storage,
        },
        &vid("vm-a"),
        &[extra("x0", "wwn-0x1")],
        false,
    );
    assert_eq!(refused(r), "dedicated-disk-unknown:x0");
}

#[test]
fn a_rollback_stops_its_holds_while_its_record_still_keeps_other_launches_off() {
    let w = World::new();
    let p = w.prepare("vm-a", &[extra("x0", "wwn-0x1")], false).unwrap();
    // While the hold stops, the record still names the disk: no other
    // launch can claim it (so none can adopt the hold being stopped).
    let root = w.root().to_path_buf();
    let seen = Arc::new(Mutex::new(None));
    let seen_in = Arc::clone(&seen);
    *w.helper.on_unhold.lock().unwrap() = Some(Box::new(move || {
        // The first stop is the one that matters (the second runs after the
        // record is gone, under the claim lock).
        seen_in
            .lock()
            .unwrap()
            .get_or_insert(read_vm(&root, "vm-a").unwrap().is_some());
    }));
    *w.helper.rules.lock().unwrap() = vec!["wwn-0x1".into()];
    w.disks.rollback(w.root(), &vid("vm-a"), &p);
    assert_eq!(
        *seen.lock().unwrap(),
        Some(true),
        "record gone before the unhold"
    );
    assert_eq!(read_vm(w.root(), "vm-a"), Ok(None));
    // A hold the periodic re-hold restarted meanwhile is stopped again
    // under the claim lock, and the rule the hold kept (it saw the record)
    // is swept once nobody's.
    assert_eq!(
        w.helper.calls(),
        vec![
            "unhold wwn-0x1",
            "unhold wwn-0x1",
            "unhold wwn-0x1",
            "release wwn-0x1"
        ]
    );
}

#[test]
fn a_rollback_whose_hold_will_not_stop_keeps_the_disks_assigned() {
    let w = World::new();
    let p = w.prepare("vm-a", &[extra("x0", "wwn-0x1")], false).unwrap();
    *w.helper.unhold_err.lock().unwrap() = Some("helper-timeout");
    w.disks.rollback(w.root(), &vid("vm-a"), &p);
    // Held for vm-a until §24, never held for nobody.
    assert!(read_vm(w.root(), "vm-a").unwrap().is_some());
    assert_eq!(w.helper.calls(), vec!["unhold wwn-0x1"]);
}

#[test]
fn stale_udev_rules_of_disks_nobody_holds_are_swept() {
    let w = World::new();
    w.prepare("vm-a", &[extra("x0", "wwn-0x1")], false).unwrap();
    *w.helper.rules.lock().unwrap() = vec!["wwn-0x1".into(), "wwn-0x9".into()];
    *w.helper.release_err.lock().unwrap() = Some("release-not-pending");
    w.disks.sweep_rules(w.root());
    // Only the disk no record names, and only through the release unit
    // (which, for such a disk, only drops the rule).
    assert_eq!(w.helper.calls(), vec!["unhold wwn-0x9", "release wwn-0x9"]);
}

/// `major:minor` of the filesystem holding `path`, as sysfs spells it.
fn dev_of(path: &Path) -> String {
    use std::os::unix::fs::MetadataExt;
    crate::storage::dedicated::dev_string(std::fs::metadata(path).unwrap().dev())
}

#[test]
fn a_disk_carrying_the_state_root_is_never_given_nor_reattached() {
    // Claim: the disk's device is the state root's filesystem.
    let w = World::new();
    let root_dev = dev_of(w.root());
    w.edit_fact("wwn-0x1", |f| f.dev = Some(root_dev.clone()));
    assert_eq!(
        refused(w.prepare("vm-a", &[extra("x0", "wwn-0x1")], false)),
        "dedicated-disk-unavailable:x0"
    );
    // Re-attach: given while clean, the state root moved onto it since.
    let w = World::new();
    w.prepare("vm-a", &[extra("x0", "wwn-0x1")], false).unwrap();
    w.edit_fact("wwn-0x1", |f| f.dev = Some(dev_of(w.root())));
    assert_eq!(
        refused(w.prepare("vm-a", &[extra("x0", "wwn-0x1")], true)),
        "dedicated-disk-busy:x0"
    );
}

#[test]
fn the_units_exit_status_decides_and_the_verdict_only_names_a_failure() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    for u in [HOLD_UNIT, RELEASE_UNIT] {
        std::fs::write(dir.path().join(format!("{u}.service")), "").unwrap();
    }
    let script = |name: &str, rc: u8| {
        let p = dir.path().join(name);
        std::fs::write(&p, format!("#!/bin/sh\nexit {rc}\n")).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        p
    };
    let helper = |systemctl: PathBuf| SystemdHelper {
        unit_dir: dir.path().to_path_buf(),
        run_dir: dir.path().join("run"),
        udev_rules_dir: dir.path().join("rules"),
        systemctl,
    };
    let run = dir.path().join("run");
    // The unit succeeded: a failure verdict left on disk does not count.
    crate::storage::dedicated_helper::write_result(&run, "wwn-0x1", "hold", "hold-busy");
    assert_eq!(helper(script("ok", 0)).hold("wwn-0x1"), Ok(()));
    // It failed: its fresh verdict names why…
    assert_eq!(helper(script("fail", 1)).hold("wwn-0x1"), Err("hold-busy"));
    crate::storage::dedicated_helper::write_result(&run, "wwn-0x1", "release", "");
    // …and a success verdict never turns a failure into a success.
    assert_eq!(
        helper(script("fail", 1)).release("wwn-0x1"),
        Err("helper-failed")
    );
    assert_eq!(
        helper(script("fail", 1)).unhold("wwn-0x1"),
        Err("helper-failed")
    );
    assert_eq!(helper(script("ok", 0)).unhold("wwn-0x1"), Ok(()));
}

#[test]
fn stray_files_in_the_record_dirs_are_skipped_not_fatal() {
    let w = World::new();
    w.prepare("vm-a", &[extra("x0", "wwn-0x1")], false).unwrap();
    // An editor's backup, a non-VM name, a non-disk name.
    std::fs::write(w.root().join(VM_DIR).join("vm-a~"), b"junk").unwrap();
    std::fs::write(w.root().join(VM_DIR).join("Not_A_Vm"), b"junk").unwrap();
    std::fs::create_dir_all(w.root().join(RELEASE_DIR)).unwrap();
    std::fs::write(w.root().join(RELEASE_DIR).join("sdb"), b"junk").unwrap();
    let o = owners(w.root()).unwrap();
    assert_eq!(o.keys().collect::<Vec<_>>(), ["wwn-0x1"]);
    // Another VM's launch is not wedged by them.
    assert!(w.prepare("vm-b", &[extra("x0", "wwn-0x2")], false).is_ok());
    // A record naming an invalid disk id: that entry is skipped (it could
    // never be attached), the rest stands.
    write_vm(
        w.root(),
        "vm-c",
        &VmDedicatedRecord {
            disks: vec![AssignedDisk {
                slot: "x0".into(),
                disk_id: "../sdz".into(),
                identity: "naa.z".into(),
            }],
        },
    )
    .unwrap();
    let o = owners(w.root()).unwrap();
    assert_eq!(o.keys().collect::<Vec<_>>(), ["wwn-0x1", "wwn-0x2"]);
}
