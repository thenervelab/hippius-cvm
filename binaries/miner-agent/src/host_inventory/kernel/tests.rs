//! Kernel journal tests: the NVMe host fixture (storage tests) plus a dm
//! device named like a VM's LV, journal JSON lines through an injected
//! runner. `journalctl` is never run.

use std::time::Duration;

use hippius_host_inventory::{AdvisorySubject, StorageSection};

use super::super::fixture::{Host, Runner};
use super::super::storage::tests::nvme_md_host;
use super::super::{run_collect_locked, run_kernel, KernelOutcome, Mode, SystemClock};
use super::*;

const T: i64 = 1_800_000_000;
const DM_NAME: &str = "hippius--vg-vm_abc123";
const DAY: i64 = 24 * 3600;

/// The NVMe host (`sda` on `ata1`, `sdb` on `ata2`, `nvme0n1`,
/// `nvme1n1`, `md127`), `dm-2` named [`DM_NAME`], and `/sys/class/nvme`
/// (`nvme1` a multipath path `nvme1c1n1` whose head is `nvme1n1`).
fn host() -> (Host, super::super::storage::StorageView) {
    let h = Host::new();
    let v = nvme_md_host(&h);
    h.write("sys/devices/virtual/block/dm-2/dev", "253:2\n");
    h.write("sys/devices/virtual/block/dm-2/size", "1024\n");
    h.write(
        "sys/devices/virtual/block/dm-2/dm/name",
        format!("{DM_NAME}\n"),
    );
    h.symlink("sys/block/dm-2", "../devices/virtual/block/dm-2");
    h.mkdir("sys/class/nvme/nvme0/nvme0n1");
    h.mkdir("sys/class/nvme/nvme1/nvme1c1n1");
    (h, v)
}

/// One journal entry as `journalctl -o json` prints it, at `T + i`.
fn entry(i: u64, msg: &str) -> String {
    entry_at(i, T + i as i64, msg)
}

fn entry_at(i: u64, at: i64, msg: &str) -> String {
    serde_json::json!({
        "__CURSOR": format!("s=abc;i={i:x};b=b0;m=1;t=1;x=1"),
        "__REALTIME_TIMESTAMP": format!("{}", at * 1_000_000),
        "MESSAGE": msg,
    })
    .to_string()
}

const MESSAGES: [&str; 17] = [
    // kernel_io_error
    "blk_update_request: I/O error, dev sdb, sector 1234567 op 0x0:(READ) flags 0x0 phys_seg 1 prio class 0",
    "I/O error, dev nvme0n1, sector 8 op 0x1:(WRITE) flags 0x800 phys_seg 1 prio class 2",
    // kernel_timeout_reset
    "ata2: hard resetting link",
    "ata2.00: exception Emask 0x0 SAct 0x0 SErr 0x0 action 0x6 frozen",
    "nvme nvme0: I/O 12 (Write) QID 3 timeout, aborting",
    "nvme nvme9: resetting controller",
    // kernel_medium_error
    "sd 1:0:0:0: [sdb] tag#5 Sense Key : Medium Error [current]",
    "sd 1:0:0:0: [sdb] tag#5 Add. Sense: Unrecovered read error - auto reallocate failed",
    // fs_error
    "EXT4-fs error (device md127): ext4_find_entry:1455: inode #2: comm qemu-system-x86: reading directory lblock 0",
    "XFS (dm-2): Metadata corruption detected at xfs_buf_ioend+0x51/0x1a0 [xfs], /var/lib/hippius-miner/data/vm_abc123.img",
    "BTRFS error (device hippius--vg-vm_abc123): bdev /dev/mapper/hippius--vg-vm_abc123 errs: wr 1, rd 0",
    "EXT4-fs error (device mystery--name): ext4_lookup: comm qemu-kvm",
    // fs_remounted_ro
    "EXT4-fs (sda2): Remounting filesystem read-only",
    // not matched
    "usb 1-1: new high-speed USB device number 2 using xhci_hcd",
    "audit: type=1400 apparmor=\"DENIED\" profile=\"libvirt-vm_abc123\" name=\"/var/lib/hippius-miner/x\"",
    "kvm: SEV-SNP API:1.55 build:21",
    "EXT4-fs (sda2): mounted filesystem with ordered data mode",
];

fn journal() -> String {
    let mut out: Vec<String> = MESSAGES
        .iter()
        .enumerate()
        .map(|(i, m)| entry(i as u64 + 1, m))
        .collect();
    // A message as bytes (journald's form for one that is not clean
    // UTF-8).
    let bytes: Vec<u64> = "I/O error, dev sdb, sector 9 op 0x0:(READ) \u{fffd}"
        .bytes()
        .map(u64::from)
        .collect();
    out.push(
        serde_json::json!({
            "__CURSOR": "s=abc;i=12;b=b0;m=1;t=1;x=1",
            "__REALTIME_TIMESTAMP": format!("{}", (T + 18) * 1_000_000),
            "MESSAGE": bytes,
        })
        .to_string(),
    );
    // The last line cut by the output cap: ignored, the cursor stays.
    out.push(r#"{"__CURSOR":"s=abc;i=99","MESSAGE":"I/O err"#.to_string());
    out.join("\n")
}

/// The runner key of `state`'s journal read.
fn key(state: &KernelState) -> String {
    format!("journalctl {}", journal_args(state).join(" "))
}

fn ev<'a>(state: &'a KernelState, code: &str, device: &str) -> Option<&'a KernelEvent> {
    state.pending.get(&format!("{code}/{device}"))
}

fn kernel_run(h: &Host, runner: &Runner, now: i64) -> KernelOutcome {
    run_kernel(
        &h.paths(),
        runner,
        now,
        &h.dir.path().join("out"),
        std::time::Instant::now(),
        &SystemClock,
        Duration::ZERO,
    )
    .unwrap()
}

fn storage_run(h: &Host, v: &super::super::storage::StorageView, now: i64) -> StorageSection {
    let out = h.dir.path().join("out");
    let summary = run_collect_locked(
        Mode::Counters,
        &h.paths(),
        &Runner::default(),
        now,
        &out,
        Some(v),
        Duration::ZERO,
        std::time::Instant::now(),
        &SystemClock,
    )
    .unwrap();
    assert_eq!(summary.skipped, None);
    serde_json::from_slice(&std::fs::read(out.join("storage.json")).unwrap()).unwrap()
}

fn has(
    s: &StorageSection,
    kind: AdvisorySubject,
    subject: &str,
    code: AdvisoryCode,
) -> Option<u64> {
    s.advisories
        .iter()
        .find(|a| a.subject_kind == kind && a.subject == subject && a.code == code)
        .map(|a| a.count)
}

// ─── the allowlist ───────────────────────────────────────────────────

#[test]
fn every_pattern_and_nothing_else() {
    let (h, _) = host();
    let resolver = Resolver::from_sysfs(&h.paths());
    let mut state = KernelState::default();
    let stats = ingest(&journal(), &mut state, &resolver, T);
    assert_eq!(stats.entries, 18, "the cut line is not an entry");
    // 13 matched lines: 2 unresolved (nvme9 has no namespace, an unmapped
    // name), 11 counted.
    assert_eq!(
        (stats.matched, stats.unresolved, stats.overflow),
        (13, 2, 0)
    );
    let sample = |code, dev| ev(&state, code, dev).map(|e| e.sample.as_str());
    let io = ev(&state, "kernel_io_error", "sdb").unwrap();
    assert_eq!(io.count, 2, "the byte-array message too");
    assert_eq!((io.first_seen_unix, io.last_seen_unix), (T + 1, T + 18));
    assert_eq!(
        sample("kernel_io_error", "nvme0n1"),
        Some("I/O error, dev nvme0n1, sector 8 op WRITE")
    );
    assert_eq!(
        sample("kernel_timeout_reset", "sdb"),
        Some("sdb: hard resetting link"),
        "ata2 is sdb's port"
    );
    assert_eq!(
        sample("kernel_timeout_reset", "nvme0n1"),
        Some("nvme0n1: command timeout")
    );
    let medium = ev(&state, "kernel_medium_error", "sdb").unwrap();
    assert_eq!(medium.count, 2, "two seconds apart: two events");
    assert_eq!(medium.sample, "sdb: Unrecovered read error");
    assert_eq!(
        sample("fs_error", "md127"),
        Some("EXT4-fs error (device md127): <redacted>")
    );
    let dm = ev(&state, "fs_error", "dm-2").unwrap();
    assert_eq!(dm.count, 2, "XFS on dm-2, and BTRFS by its dm name");
    assert_eq!(dm.sample, "BTRFS error (device dm-2): <redacted>");
    assert_eq!(
        sample("fs_remounted_ro", "sda2"),
        Some("EXT4-fs (sda2): Remounting filesystem read-only")
    );
    assert_eq!(state.pending.len(), 8);
    // The cursor and the time of the last complete entry.
    assert_eq!(state.cursor.as_deref(), Some("s=abc;i=12;b=b0;m=1;t=1;x=1"));
    assert_eq!(state.last_realtime_us, Some((T + 18) * 1_000_000));
}

#[test]
fn the_block_layers_error_kinds() {
    let (h, _) = host();
    let r = Resolver::from_sysfs(&h.paths());
    let code = |msg: &str| classify(msg, &r).map(|m| (m.code, m.sample));
    use AdvisoryCode as C;
    assert_eq!(
        code("critical medium error, dev sdb, sector 5 op 0x0:(READ) flags 0x0"),
        Some((
            C::KernelMediumError,
            "critical medium error, dev sdb, sector 5 op READ".into()
        ))
    );
    assert_eq!(
        code("blk_update_request: timeout error, dev sdb, sector 9 op 0x1:(WRITE)"),
        Some((
            C::KernelTimeoutReset,
            "timeout error, dev sdb, sector 9 op WRITE".into()
        ))
    );
    for kind in [
        "critical target",
        "critical nexus",
        "critical space allocation",
        "recoverable transport",
        "I/O",
        "protection",
    ] {
        let m = classify(
            &format!("{kind} error, dev nvme0n1, sector 1 op 0x0:(READ)"),
            &r,
        )
        .unwrap();
        assert_eq!(m.code, C::KernelIoError, "{kind}");
        assert_eq!(m.device.as_deref(), Some("nvme0n1"));
    }
    // A kind the block layer does not have: no match.
    assert_eq!(code("something odd error, dev sdb, sector 1"), None);
}

#[test]
fn look_alikes_do_not_match() {
    let (h, _) = host();
    let r = Resolver::from_sysfs(&h.paths());
    for msg in [
        "nvme nvme0: Shutdown timeout set to 8 seconds",
        "nvme nvme0: 16/0/0 default/read/poll queues",
        "BTRFS info (device sdb): bdev /dev/sdb errs: wr 0, rd 1, flush 0, corrupt 0, gen 0",
        "BTRFS info (device sdb): read error corrected: ino 257 off 0 (dev /dev/sdb sector 2048)",
        "BTRFS warning (device sdb): checksum verify failed",
    ] {
        assert_eq!(classify(msg, &r), None, "{msg}");
    }
    // The error levels do.
    for msg in [
        "BTRFS critical (device sdb): corrupt leaf",
        "BTRFS: error (device sdb) in btrfs_commit_transaction",
    ] {
        assert_eq!(
            classify(msg, &r).map(|m| m.code),
            Some(AdvisoryCode::FsError),
            "{msg}"
        );
    }
    // A command timeout by QID, and a controller reset, through the
    // multipath head.
    let m = classify("nvme nvme1: I/O 7 QID 2 timeout, reset controller", &r).unwrap();
    assert_eq!(
        (m.code, m.device.as_deref()),
        (AdvisoryCode::KernelTimeoutReset, Some("nvme1n1"))
    );
}

#[test]
fn a_medium_error_printed_twice_in_one_second_is_one_event() {
    let (h, _) = host();
    let mut state = KernelState::default();
    let out = [
        entry_at(
            1,
            T,
            "sd 1:0:0:0: [sdb] tag#5 Sense Key : Medium Error [current]",
        ),
        entry_at(
            2,
            T,
            "sd 1:0:0:0: [sdb] tag#5 Add. Sense: Unrecovered read error",
        ),
        entry_at(
            3,
            T + 5,
            "sd 1:0:0:0: [sdb] tag#9 Sense Key : Medium Error [current]",
        ),
    ]
    .join("\n");
    ingest(&out, &mut state, &Resolver::from_sysfs(&h.paths()), T);
    assert_eq!(ev(&state, "kernel_medium_error", "sdb").unwrap().count, 2);
}

#[test]
fn nothing_of_a_message_is_kept_but_the_template() {
    let (h, _) = host();
    let mut state = KernelState::default();
    ingest(&journal(), &mut state, &Resolver::from_sysfs(&h.paths()), T);
    let json = serde_json::to_string(&state).unwrap();
    for leaked in [
        DM_NAME,
        "vm_abc123",
        "/var/lib",
        "/dev/mapper",
        "qemu",
        "inode",
        "comm qemu",
        "xfs_buf",
        "xhci",
        "apparmor",
        "mystery",
        "nvme9",
        "Emask",
    ] {
        assert!(!json.contains(leaked), "{leaked} in {json}");
    }
    for e in state.pending.values() {
        assert!(e.sample.len() <= 120 && e.sample.is_ascii(), "{}", e.sample);
        assert!(hippius_host_inventory::is_kernel_name(&e.device));
    }
}

// ─── the read ────────────────────────────────────────────────────────

#[test]
fn the_journal_arguments() {
    let first = KernelState::default();
    assert_eq!(
        journal_args(&first),
        [
            "-k",
            "-o",
            "json",
            "--no-pager",
            "--output-fields=MESSAGE,__REALTIME_TIMESTAMP",
            "-n",
            "1000"
        ],
        "only the very first run: the current boot's recent entries"
    );
    let mut st = KernelState {
        cursor: Some("s=abc;i=1".into()),
        last_realtime_us: Some(1_800_000_000_999_999),
        ..KernelState::default()
    };
    let args = journal_args(&st);
    assert!(
        !args.contains(&"-k".to_string()),
        "-k is the current boot only"
    );
    assert_eq!(
        &args[args.len() - 2..],
        ["_TRANSPORT=kernel", "--after-cursor=s=abc;i=1"]
    );
    // The cursor failed too often: the last entry's time, never `-n`.
    st.cursor_failures = MAX_CURSOR_FAILURES;
    let args = journal_args(&st);
    assert_eq!(
        &args[args.len() - 2..],
        ["_TRANSPORT=kernel", "--since=@1800000001.000000"]
    );
    assert!(!args.contains(&"-n".to_string()));
}

#[test]
fn a_log_storm_is_read_up_to_the_cap() {
    // What `run_capped` hands back past a storm: complete entries, then
    // the line the cap cut. A success, the cursor at the last complete
    // entry; the rest is next run's.
    let (h, _) = host();
    let mut lines: Vec<String> = (1..=3000)
        .map(|i| {
            entry(
                i,
                "blk_update_request: I/O error, dev sdb, sector 1 op 0x0:(READ)",
            )
        })
        .collect();
    lines.push(r#"{"__CURSOR":"s=abc;i=ffff","__REALTIME_TI"#.into());
    let storm = lines.join("\n");
    let runner = Runner::default().with(&key(&KernelState::default()), Ok(&storm));
    let r = kernel_run(&h, &runner, T + 4000);
    assert!(
        matches!(r, KernelOutcome::Read(s) if s.entries == 3000),
        "{r:?}"
    );
    let saved = KernelState::load(&h.dir.path().join("out"));
    assert_eq!(
        saved.cursor.as_deref(),
        Some("s=abc;i=bb8;b=b0;m=1;t=1;x=1")
    );
    assert_eq!(ev(&saved, "kernel_io_error", "sdb").unwrap().count, 3000);
}

#[test]
fn the_cursor_is_kept_through_failures_then_the_time_takes_over() {
    let (h, _) = host();
    let out = h.dir.path().join("out");
    kernel_run(
        &h,
        &Runner::default().with(&key(&KernelState::default()), Ok(&journal())),
        T + 100,
    );
    let saved = KernelState::load(&out);
    let cursor = saved.cursor.clone().unwrap();
    assert_eq!(cursor, "s=abc;i=12;b=b0;m=1;t=1;x=1");
    let counted = ev(&saved, "kernel_io_error", "sdb").unwrap().count;

    // A failure keeps the cursor: the next run asks after the same one,
    // and counts nothing twice.
    let after = key(&saved);
    assert!(after.ends_with(&format!("_TRANSPORT=kernel --after-cursor={cursor}")));
    let r = kernel_run(
        &h,
        &Runner::default().with(&after, Err(CommandError::Failed)),
        T + 200,
    );
    assert_eq!(r, KernelOutcome::JournalFault(CommandError::Failed));
    let saved = KernelState::load(&out);
    assert_eq!(saved.cursor.as_deref(), Some(cursor.as_str()));
    assert_eq!(saved.cursor_failures, 1);
    assert_eq!(key(&saved), after, "the same cursor again");
    let more = entry(0x20, "I/O error, dev sdb, sector 1 op 0x0:(READ)");
    kernel_run(&h, &Runner::default().with(&after, Ok(&more)), T + 300);
    let saved = KernelState::load(&out);
    assert_eq!(
        ev(&saved, "kernel_io_error", "sdb").unwrap().count,
        counted + 1,
        "only the new entry"
    );
    assert_eq!(saved.cursor_failures, 0);

    // Three failures in a row: the run goes on from the last entry's time.
    let cursor = saved.cursor.clone().unwrap();
    let k = key(&saved);
    for _ in 0..MAX_CURSOR_FAILURES {
        kernel_run(
            &h,
            &Runner::default().with(&k, Err(CommandError::Failed)),
            T + 400,
        );
    }
    let saved = KernelState::load(&out);
    assert_eq!(saved.cursor.as_deref(), Some(cursor.as_str()));
    let since = key(&saved);
    assert!(
        since.contains("--since=@") && !since.contains("--after-cursor"),
        "{since}"
    );
    // A read by time with nothing new: the given-up cursor stays gone.
    kernel_run(&h, &Runner::default().with(&since, Ok("")), T + 500);
    let saved = KernelState::load(&out);
    assert_eq!(saved.cursor, None);
    assert!(key(&saved).contains("--since=@"));

    // No journalctl: nothing to do, no fault.
    assert_eq!(
        kernel_run(&h, &Runner::default(), T + 600),
        KernelOutcome::NoJournal
    );
}

#[test]
fn a_hand_edited_state_is_rechecked() {
    let (h, _) = host();
    let out = h.dir.path().join("out");
    std::fs::create_dir_all(&out).unwrap();
    let state = serde_json::json!({
        "cursor": "x;reboot now",
        "pending": {
            "fs_error/sdb": {"device": "sdb", "code": "fs_error", "count": 1,
                "first_seen_unix": T, "last_seen_unix": T, "sample": "ok sample"},
            "fs_error/sdc": {"device": "sdb", "code": "fs_error", "count": 1,
                "first_seen_unix": T, "last_seen_unix": T, "sample": "key mismatch"},
            "smart_overall_failed/sdb": {"device": "sdb", "code": "smart_overall_failed",
                "count": 1, "first_seen_unix": T, "last_seen_unix": T, "sample": "not ours"},
            "fs_error/md127": {"device": "md127", "code": "fs_error", "count": 1,
                "first_seen_unix": T, "last_seen_unix": T, "sample": "bad\nline"},
            "fs_error/hippius--vg-x": {"device": "hippius--vg-x", "code": "fs_error",
                "count": 1, "first_seen_unix": T, "last_seen_unix": T, "sample": "x"}
        }
    });
    std::fs::write(out.join(".kernel-state.json"), state.to_string()).unwrap();
    let loaded = KernelState::load(&out);
    assert_eq!(loaded.cursor, None);
    assert_eq!(
        loaded.pending.keys().collect::<Vec<_>>(),
        ["fs_error/sdb"],
        "{loaded:?}"
    );
}

#[test]
fn a_busy_lock_or_no_time_skips() {
    use nix::fcntl::{Flock, FlockArg};
    let (h, _) = host();
    let out = h.dir.path().join("out");
    std::fs::create_dir_all(&out).unwrap();
    let file = std::fs::File::create(out.join(super::super::LOCK_NAME)).unwrap();
    let held = Flock::lock(file, FlockArg::LockExclusiveNonblock).unwrap();
    let runner = Runner::default().with(&key(&KernelState::default()), Ok(&journal()));
    let r = run_kernel(
        &h.paths(),
        &runner,
        T,
        &out,
        std::time::Instant::now(),
        &SystemClock,
        Duration::from_millis(100),
    )
    .unwrap();
    assert_eq!(r, KernelOutcome::Busy);
    assert!(!out.join(".kernel-state.json").exists());
    drop(held);
    // Started too long ago for its own deadline.
    if let Some(old) = std::time::Instant::now().checked_sub(KERNEL_RUN_DEADLINE) {
        let r = run_kernel(
            &h.paths(),
            &runner,
            T,
            &out,
            old,
            &SystemClock,
            Duration::ZERO,
        )
        .unwrap();
        assert_eq!(r, KernelOutcome::NoTime);
    }
}

// ─── the hand-off: a retention window, never a clear ─────────────────

#[test]
fn events_are_folded_into_every_storage_run_until_they_expire() {
    let (h, v) = host();
    let out = h.dir.path().join("out");
    kernel_run(
        &h,
        &Runner::default().with(&key(&KernelState::default()), Ok(&journal())),
        T + 100,
    );
    let state_before = std::fs::read(out.join(".kernel-state.json")).unwrap();

    // Several storage runs (a poster in back-off, two within its gap, an
    // invalid section: whatever became of the last write) all carry them.
    for now in [T + 300, T + 600, T + 3600, T + DAY] {
        let s = storage_run(&h, &v, now);
        assert_eq!(
            has(&s, AdvisorySubject::Pool, "nvme0", AdvisoryCode::FsError),
            Some(1),
            "{now}"
        );
        assert_eq!(
            has(
                &s,
                AdvisorySubject::Device,
                "sdb",
                AdvisoryCode::KernelIoError
            ),
            Some(2)
        );
        assert!(has(&s, AdvisorySubject::Device, "dm-2", AdvisoryCode::FsError).is_some());
        assert!(!serde_json::to_string(&s).unwrap().contains(DM_NAME));
    }
    // A storage run never writes the kernel state.
    assert_eq!(
        std::fs::read(out.join(".kernel-state.json")).unwrap(),
        state_before
    );
    // Its journal time is the advisory's.
    let s = storage_run(&h, &v, T + 400);
    let pool = s
        .advisories
        .iter()
        .find(|a| a.subject == "nvme0" && a.code == AdvisoryCode::FsError)
        .unwrap();
    assert_eq!((pool.first_seen_unix, pool.last_seen_unix), (T + 9, T + 9));
    assert_eq!(pool.severity, Severity::Critical);

    // 24 h after its last occurrence an event is gone from the report
    // (vali resolves it); the later ones are still there.
    let s = storage_run(&h, &v, T + 9 + DAY + 1);
    assert_eq!(
        has(&s, AdvisorySubject::Pool, "nvme0", AdvisoryCode::FsError),
        None
    );
    assert!(has(
        &s,
        AdvisorySubject::Device,
        "sdb",
        AdvisoryCode::KernelIoError
    )
    .is_some());
    let s = storage_run(&h, &v, T + 18 + DAY + 1);
    assert!(s
        .advisories
        .iter()
        .all(|a| a.code != AdvisoryCode::KernelIoError));
}

#[test]
fn seen_again_within_the_window_extends_it_and_counts_up() {
    let (h, v) = host();
    let out = h.dir.path().join("out");
    let io = |i: u64, at: i64| entry_at(i, at, "I/O error, dev sdb, sector 1 op 0x0:(READ)");
    kernel_run(
        &h,
        &Runner::default().with(&key(&KernelState::default()), Ok(&io(1, T))),
        T,
    );
    // 20 h later, again: the window runs from this one.
    let state = KernelState::load(&out);
    kernel_run(
        &h,
        &Runner::default().with(&key(&state), Ok(&io(2, T + 20 * 3600))),
        T + 20 * 3600,
    );
    let e = ev(&KernelState::load(&out), "kernel_io_error", "sdb")
        .unwrap()
        .clone();
    assert_eq!(
        (e.count, e.first_seen_unix, e.last_seen_unix),
        (2, T, T + 20 * 3600)
    );
    let s = storage_run(&h, &v, T + 30 * 3600);
    assert_eq!(
        has(
            &s,
            AdvisorySubject::Device,
            "sdb",
            AdvisoryCode::KernelIoError
        ),
        Some(2)
    );
    // Past the window, seen again: a new episode.
    let state = KernelState::load(&out);
    let later = T + 20 * 3600 + DAY + 60;
    kernel_run(
        &h,
        &Runner::default().with(&key(&state), Ok(&io(3, later))),
        later,
    );
    let e = ev(&KernelState::load(&out), "kernel_io_error", "sdb")
        .unwrap()
        .clone();
    assert_eq!(
        (e.count, e.first_seen_unix, e.last_seen_unix),
        (1, later, later)
    );
}

#[test]
fn the_cap_evicts_the_least_recently_seen() {
    let (h, _) = host();
    let r = Resolver::from_sysfs(&h.paths());
    let mut state = KernelState::default();
    // 128 partitions of sdb (`sdb1`…), the first seen earliest.
    let lines: Vec<String> = (1..=MAX_PENDING as u64 + 1)
        .map(|i| entry(i, &format!("I/O error, dev sdb{i}, sector 1 op 0x0:(READ)")))
        .collect();
    let stats = ingest(&lines.join("\n"), &mut state, &r, T);
    assert_eq!(state.pending.len(), MAX_PENDING);
    assert_eq!(stats.overflow, 1);
    assert!(
        ev(&state, "kernel_io_error", "sdb1").is_none(),
        "the oldest went"
    );
    assert!(ev(&state, "kernel_io_error", "sdb129").is_some());
}
