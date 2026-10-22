use super::*;
use crate::storage::assignment::{
    write_release, write_vm, AssignedDisk, ReleaseRecord, VmDedicatedRecord,
};
use crate::storage::dedicated::ProbeFailed;

const MIB: u64 = 1024 * 1024;

/// A fixture host: `dev/<name>` (a regular file standing for the disk),
/// `by-id/<id>` → it, `sys/<name>/…`, a `proc/` tree, the agent's state
/// root and a udev rules dir.
struct Host {
    dir: tempfile::TempDir,
}

impl Host {
    fn new() -> Self {
        let h = Self {
            dir: tempfile::tempdir().unwrap(),
        };
        for d in ["dev", "by-id", "sys", "proc", "state", "rules"] {
            std::fs::create_dir_all(h.p(d)).unwrap();
        }
        h
    }

    fn p(&self, rel: &str) -> PathBuf {
        self.dir.path().join(rel)
    }

    fn env(&self) -> HelperEnv {
        HelperEnv {
            paths: SysPaths {
                by_id: self.p("by-id"),
                sys_block: self.p("sys"),
                mountinfo: self.p("none"),
                swaps: self.p("none"),
                require_block_device: false,
            },
            proc_dir: self.p("proc"),
            state_root: self.p("state"),
            udev_rules_dir: Some(self.p("rules")),
        }
    }

    /// A 64 MiB "disk" of `0xAA` bytes, `wwid`, linked as `id`.
    fn disk(&self, id: &str, name: &str, wwid: &str) -> PathBuf {
        let dev = self.p("dev").join(name);
        std::fs::write(&dev, vec![0xAAu8; (64 * MIB) as usize]).unwrap();
        let sys = self.p("sys").join(name);
        std::fs::create_dir_all(sys.join("device")).unwrap();
        std::fs::write(sys.join("device/wwid"), format!("{wwid}\n")).unwrap();
        std::fs::write(sys.join("dev"), "8:16\n").unwrap();
        let link = self.p("by-id").join(id);
        let _ = std::fs::remove_file(&link);
        std::os::unix::fs::symlink(&dev, link).unwrap();
        // The agent bound it.
        let mut ids = IdentityMap::load(&self.p("state")).unwrap();
        ids.disks.insert(id.into(), wwid.into());
        ids.save(&self.p("state")).unwrap();
        dev
    }

    fn assign(&self, vm: &str, id: &str, identity: &str) {
        write_vm(
            &self.p("state"),
            vm,
            &VmDedicatedRecord {
                disks: vec![AssignedDisk {
                    slot: "x0".into(),
                    disk_id: id.into(),
                    identity: identity.into(),
                }],
            },
        )
        .unwrap();
    }

    fn queue_release(&self, id: &str, identity: &str) {
        write_release(
            &self.p("state"),
            id,
            &ReleaseRecord {
                vm_id: "vm-a".into(),
                slot: "x0".into(),
                identity: identity.into(),
            },
        )
        .unwrap();
    }

    /// Process `pid` holds `target` open as fd 3.
    fn opener(&self, pid: &str, target: &Path) {
        let fd = self.p("proc").join(pid).join("fd");
        std::fs::create_dir_all(&fd).unwrap();
        std::os::unix::fs::symlink(target, fd.join("3")).unwrap();
    }
}

struct Probe(std::result::Result<bool, ProbeFailed>);
impl SignatureProbe for Probe {
    fn has_signature(&self, _device: &Path) -> std::result::Result<bool, ProbeFailed> {
        self.0
    }
}
const CLEAN: Probe = Probe(Ok(false));

#[test]
fn resolve_reads_the_whole_disk_and_its_identity() {
    let h = Host::new();
    let dev = h.disk("wwn-0x1", "sdb", "naa.1");
    let d = resolve(&h.env(), "wwn-0x1").unwrap();
    assert_eq!(d.path, std::fs::canonicalize(dev).unwrap());
    assert_eq!((d.name.as_str(), d.identity.as_str()), ("sdb", "naa.1"));
    assert_eq!(resolve(&h.env(), "../x").unwrap_err(), "helper-bad-disk-id");
    assert_eq!(
        resolve(&h.env(), "wwn-0x9").unwrap_err(),
        "helper-not-found"
    );
    // A partition is not under /sys/block.
    std::fs::write(h.p("dev/sdb1"), b"").unwrap();
    std::os::unix::fs::symlink(h.p("dev/sdb1"), h.p("by-id/wwn-0x2")).unwrap();
    assert_eq!(
        resolve(&h.env(), "wwn-0x2").unwrap_err(),
        "helper-not-whole-disk"
    );
    // The host check: a regular file is not a block device.
    let mut env = h.env();
    env.paths.require_block_device = true;
    assert_eq!(
        resolve(&env, "wwn-0x1").unwrap_err(),
        "helper-not-block-device"
    );
    std::fs::remove_file(h.p("sys/sdb/device/wwid")).unwrap();
    assert_eq!(
        resolve(&h.env(), "wwn-0x1").unwrap_err(),
        "helper-no-identity"
    );
}

#[test]
fn the_hold_needs_a_vm_record_and_the_same_device() {
    let h = Host::new();
    h.disk("wwn-0x1", "sdb", "naa.1");
    assert_eq!(hold(&h.env(), "wwn-0x1").unwrap_err(), "hold-not-assigned");
    // Freed and queued for its wipe: not held.
    h.queue_release("wwn-0x1", "naa.1");
    assert_eq!(hold(&h.env(), "wwn-0x1").unwrap_err(), "hold-not-assigned");
    h.assign("vm-a", "wwn-0x1", "naa.other");
    assert_eq!(
        hold(&h.env(), "wwn-0x1").unwrap_err(),
        "hold-identity-mismatch"
    );
    h.assign("vm-a", "wwn-0x1", "naa.1");
    // The agent's identity map disagrees: refused too.
    let mut ids = IdentityMap::load(&h.p("state")).unwrap();
    ids.disks.insert("wwn-0x1".into(), "naa.else".into());
    ids.save(&h.p("state")).unwrap();
    assert_eq!(
        hold(&h.env(), "wwn-0x1").unwrap_err(),
        "hold-identity-mismatch"
    );
    ids.disks.insert("wwn-0x1".into(), "naa.1".into());
    ids.save(&h.p("state")).unwrap();
    let held = hold(&h.env(), "wwn-0x1").unwrap();
    drop(held);
    // The udev rule is in place, matching the disk and its partitions.
    let rule = std::fs::read_to_string(udev_rule_path(&h.p("rules"), "wwn-0x1")).unwrap();
    assert!(rule.contains("SYMLINK==\"disk/by-id/wwn-0x1\""));
    assert!(rule.contains("SYMLINK==\"disk/by-id/wwn-0x1-part*\""));
    assert!(rule.contains("ENV{UDISKS_IGNORE}=\"1\""));
    assert!(rule.contains("ENV{ID_FS_TYPE}=\"\""));
    // Unreadable records: refused, never guessed.
    std::fs::write(h.p("state/vm-dedicated/vm-b"), b"{").unwrap();
    assert_eq!(
        hold(&h.env(), "wwn-0x1").unwrap_err(),
        "helper-records-unreadable"
    );
}

#[test]
fn the_release_wipes_head_and_tail_only_and_verifies() {
    let h = Host::new();
    let dev = h.disk("wwn-0x1", "sdb", "naa.1");
    std::fs::write(udev_rule_path(&h.p("rules"), "wwn-0x1"), "x").unwrap();
    h.queue_release("wwn-0x1", "naa.1");
    release(&h.env(), "wwn-0x1", &CLEAN).unwrap();
    let bytes = std::fs::read(&dev).unwrap();
    assert_eq!(bytes.len() as u64, 64 * MIB);
    let w = WIPE_BYTES as usize;
    assert!(bytes[..w].iter().all(|b| *b == 0), "head zeroed");
    assert!(
        bytes[bytes.len() - w..].iter().all(|b| *b == 0),
        "tail zeroed"
    );
    assert!(
        bytes[w..bytes.len() - w].iter().all(|b| *b == 0xAA),
        "the middle untouched"
    );
    // The disk is the host's again: its udev rule is gone.
    assert!(!udev_rule_path(&h.p("rules"), "wwn-0x1").exists());
}

#[test]
fn the_release_refuses_every_disk_it_may_not_wipe() {
    let h = Host::new();
    let dev = h.disk("wwn-0x1", "sdb", "naa.1");
    let untouched = || std::fs::read(&dev).unwrap().iter().all(|b| *b == 0xAA);
    assert_eq!(
        release(&h.env(), "wwn-0x1", &CLEAN).unwrap_err(),
        "release-not-pending"
    );
    assert_eq!(
        release(&h.env(), "../../x", &CLEAN).unwrap_err(),
        "helper-bad-disk-id"
    );
    // A VM holds it (whatever a release record says).
    h.queue_release("wwn-0x1", "naa.1");
    h.assign("vm-b", "wwn-0x1", "naa.1");
    assert_eq!(
        release(&h.env(), "wwn-0x1", &CLEAN).unwrap_err(),
        "release-assigned"
    );
    std::fs::remove_file(h.p("state/vm-dedicated/vm-b")).unwrap();
    // Another device behind the name.
    h.queue_release("wwn-0x1", "naa.other");
    assert_eq!(
        release(&h.env(), "wwn-0x1", &CLEAN).unwrap_err(),
        "release-identity-mismatch"
    );
    h.queue_release("wwn-0x1", "naa.1");
    // A process (QEMU of a domain still up) has it open.
    h.opener("4242", &std::fs::canonicalize(&dev).unwrap());
    assert_eq!(
        release(&h.env(), "wwn-0x1", &CLEAN).unwrap_err(),
        "release-device-open"
    );
    assert!(untouched());
    std::fs::remove_dir_all(h.p("proc/4242")).unwrap();
    // Our own fds do not count.
    h.opener(
        &std::process::id().to_string(),
        &std::fs::canonicalize(&dev).unwrap(),
    );
    // A signature left (or a probe that cannot tell) fails the release.
    assert_eq!(
        release(&h.env(), "wwn-0x1", &Probe(Ok(true))).unwrap_err(),
        "release-signature-remains"
    );
    assert_eq!(
        release(&h.env(), "wwn-0x1", &Probe(Err(ProbeFailed))).unwrap_err(),
        "release-verify-failed"
    );
    // A records dir that cannot be read refuses.
    std::fs::write(h.p("state/vm-dedicated/vm-c"), b"{").unwrap();
    assert_eq!(
        release(&h.env(), "wwn-0x1", &CLEAN).unwrap_err(),
        "helper-records-unreadable"
    );
}

#[test]
fn an_unreadable_proc_counts_as_open() {
    let h = Host::new();
    h.disk("wwn-0x1", "sdb", "naa.1");
    let device = resolve(&h.env(), "wwn-0x1").unwrap();
    assert!(!opened_by_another(&h.p("proc"), &device));
    assert!(opened_by_another(&h.p("no-proc"), &device));
}

#[test]
fn a_device_smaller_than_both_ends_is_zeroed_whole() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("small");
    std::fs::write(&path, vec![0xAAu8; (20 * MIB) as usize]).unwrap();
    let mut f = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&path)
        .unwrap();
    zero_ends(&mut f).unwrap();
    let bytes = std::fs::read(&path).unwrap();
    assert_eq!(bytes.len() as u64, 20 * MIB);
    assert!(bytes.iter().all(|b| *b == 0));
}

#[test]
fn verdicts_are_read_only_when_fresh_and_known() {
    let dir = tempfile::tempdir().unwrap();
    let before = std::time::SystemTime::now() - std::time::Duration::from_secs(5);
    assert_eq!(
        read_result(&result_path(dir.path(), "wwn-0x1", "hold"), before),
        None
    );
    write_result(dir.path(), "wwn-0x1", "hold", "");
    assert_eq!(
        read_result(&result_path(dir.path(), "wwn-0x1", "hold"), before),
        Some("")
    );
    write_result(dir.path(), "wwn-0x1", "release", "release-device-open");
    assert_eq!(
        read_result(&result_path(dir.path(), "wwn-0x1", "release"), before),
        Some("release-device-open")
    );
    write_result(dir.path(), "wwn-0x1", "release", "something-new");
    assert_eq!(
        read_result(&result_path(dir.path(), "wwn-0x1", "release"), before),
        Some("helper-failed")
    );
    // Older than the call: not this run's verdict.
    let later = std::time::SystemTime::now() + std::time::Duration::from_secs(30);
    assert_eq!(
        read_result(&result_path(dir.path(), "wwn-0x1", "release"), later),
        None
    );
}

#[test]
fn every_written_code_is_a_known_code() {
    let source = include_str!("../dedicated_helper.rs");
    for line in source.lines() {
        for code in line.split('"').skip(1).step_by(2) {
            if (code.starts_with("hold-")
                || code.starts_with("release-")
                || code.starts_with("helper-"))
                && !code.contains(' ')
                && !code.ends_with('-')
            {
                assert!(CODES.contains(&code), "{code} missing from CODES");
            }
        }
    }
}

#[test]
fn a_stopped_hold_keeps_its_udev_rule_only_while_a_record_names_the_disk() {
    let h = Host::new();
    h.disk("wwn-0x1", "sdb", "naa.1");
    h.assign("vm-a", "wwn-0x1", "naa.1");
    drop(hold(&h.env(), "wwn-0x1").unwrap());
    let rule = udev_rule_path(&h.p("rules"), "wwn-0x1");
    after_hold(&h.env(), "wwn-0x1");
    assert!(rule.exists(), "still assigned: hidden across a reboot");
    // §24 queued it: the release removes it after the wipe.
    std::fs::remove_file(h.p("state/vm-dedicated/vm-a")).unwrap();
    h.queue_release("wwn-0x1", "naa.1");
    after_hold(&h.env(), "wwn-0x1");
    assert!(rule.exists());
    // A launch rolled back: nobody's any more, the host's again.
    std::fs::remove_file(h.p("state/dedicated-release/wwn-0x1")).unwrap();
    after_hold(&h.env(), "wwn-0x1");
    assert!(!rule.exists());
}

#[test]
fn a_disk_swapped_behind_the_name_after_the_check_is_caught_on_the_open_fd() {
    let h = Host::new();
    h.disk("wwn-0x1", "sdb", "naa.1");
    let device = resolve(&h.env(), "wwn-0x1").unwrap();
    let file = std::fs::File::open(&device.path).unwrap();
    assert!(same_device(&h.env(), "wwn-0x1", &device, &file));
    // The name now points at another disk.
    h.disk("wwn-0x1", "sdc", "naa.2");
    assert!(!same_device(&h.env(), "wwn-0x1", &device, &file));
    // Same name, another identity read for it.
    h.disk("wwn-0x1", "sdb", "naa.3");
    assert!(!same_device(&h.env(), "wwn-0x1", &device, &file));
}

#[test]
fn a_release_of_a_disk_nobody_names_only_drops_its_leftover_rule() {
    let h = Host::new();
    let dev = h.disk("wwn-0x1", "sdb", "naa.1");
    let rule = udev_rule_path(&h.p("rules"), "wwn-0x1");
    std::fs::write(&rule, "x").unwrap();
    std::fs::write(h.p("rules/90-other.rules"), "x").unwrap();
    assert_eq!(rule_ids(&h.p("rules")), vec!["wwn-0x1".to_string()]);
    assert_eq!(
        release(&h.env(), "wwn-0x1", &CLEAN).unwrap_err(),
        "release-not-pending"
    );
    assert!(!rule.exists());
    assert!(
        std::fs::read(&dev).unwrap().iter().all(|b| *b == 0xAA),
        "never wiped"
    );
    assert!(rule_ids(&h.p("rules")).is_empty());
}

#[test]
fn a_sweep_racing_a_new_claim_leaves_the_new_holders_rule_in_place() {
    // The sweep read "nobody's", then a launch claimed the disk (and its
    // hold wrote the rule) before the removal: the rule comes back.
    let h = Host::new();
    h.disk("wwn-0x1", "sdb", "naa.1");
    let rule = udev_rule_path(&h.p("rules"), "wwn-0x1");
    std::fs::write(&rule, "x").unwrap();
    h.assign("vm-b", "wwn-0x1", "naa.1");
    // `release` read the owners before the claim: its removal step runs
    // with the claim's record already there.
    drop_unowned_rule(&h.env(), "wwn-0x1");
    assert!(rule.exists());
    assert_eq!(
        std::fs::read_to_string(&rule).unwrap(),
        udev_rule("wwn-0x1")
    );
    // Truly nobody's: gone.
    std::fs::remove_file(h.p("state/vm-dedicated/vm-b")).unwrap();
    drop_unowned_rule(&h.env(), "wwn-0x1");
    assert!(!rule.exists());
}

#[test]
fn the_release_compares_the_device_with_the_release_record_itself() {
    // The agent's identity map was rewritten to the new device too (or
    // lost it): the release record's identity alone still refuses.
    let h = Host::new();
    let dev = h.disk("wwn-0x1", "sdb", "naa.new");
    h.queue_release("wwn-0x1", "naa.old");
    assert_eq!(
        release(&h.env(), "wwn-0x1", &CLEAN).unwrap_err(),
        "release-identity-mismatch"
    );
    std::fs::remove_file(h.p("state/dedicated-disks.json")).unwrap();
    assert_eq!(
        release(&h.env(), "wwn-0x1", &CLEAN).unwrap_err(),
        "release-identity-mismatch"
    );
    assert!(std::fs::read(&dev).unwrap().iter().all(|b| *b == 0xAA));
}

#[test]
fn a_process_whose_fds_cannot_be_read_counts_as_holding_the_disk() {
    use std::os::unix::fs::PermissionsExt;
    let h = Host::new();
    h.disk("wwn-0x1", "sdb", "naa.1");
    let device = resolve(&h.env(), "wwn-0x1").unwrap();
    // A process that exited between the listing and the read: gone.
    std::fs::create_dir_all(h.p("proc/4243")).unwrap();
    assert!(!opened_by_another(&h.p("proc"), &device));
    // One whose fd table this scan may not read (an LSM, hidepid).
    let fd = h.p("proc/4242/fd");
    std::fs::create_dir_all(&fd).unwrap();
    std::fs::set_permissions(&fd, std::fs::Permissions::from_mode(0o000)).unwrap();
    let readable = std::fs::read_dir(&fd).is_ok();
    let open = opened_by_another(&h.p("proc"), &device);
    std::fs::set_permissions(&fd, std::fs::Permissions::from_mode(0o755)).unwrap();
    if !readable {
        // (Root reads it anyway: nothing to prove then.)
        assert!(open, "an unreadable fd table was taken for no opener");
    }
}
