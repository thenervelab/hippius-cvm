//! Poster tests: fixture section dirs, a scripted mock Edge client, an
//! injected clock (the `now` handed to each tick) and a fixed jitter.

use std::collections::VecDeque;
use std::sync::Mutex;

use ed25519_dalek::{Signature, Verifier};
use hippius_host_inventory::{
    CpuSection, Device, DeviceKind, DeviceRole, MemorySection, NetworkSection, PciSection,
    SectionStatus, SensorsSection, SoftwareSection, StorageSection, SystemSection, Transport,
};

use super::*;

const T0: i64 = 1_800_000_000;

/// Replies in order, then 200s; every envelope kept.
#[derive(Default)]
struct MockEdge {
    replies: Mutex<VecDeque<Result<EdgeReply, ()>>>,
    sent: Mutex<Vec<Vec<u8>>>,
    /// When set, the state on disk at the moment of each post:
    /// `(sequence, last_sent_unix)`.
    watch_state: Option<PathBuf>,
    on_disk_at_post: Mutex<Vec<(u64, Option<i64>)>>,
    /// Never answer (a post hanging past any timeout).
    hang: bool,
}

fn reply(status: u16, retry_after: Option<u64>) -> Result<EdgeReply, ()> {
    Ok(EdgeReply {
        status,
        retry_after,
    })
}

impl MockEdge {
    fn then(self, r: Result<EdgeReply, ()>) -> Self {
        self.replies.lock().unwrap().push_back(r);
        self
    }
    fn sent(&self) -> Vec<Vec<u8>> {
        self.sent.lock().unwrap().clone()
    }
}

#[async_trait]
impl InventoryClient for MockEdge {
    async fn post(&self, envelope: &[u8]) -> Result<EdgeReply, ()> {
        self.sent.lock().unwrap().push(envelope.to_vec());
        if let Some(path) = &self.watch_state {
            let on_disk = state::InventoryState::load(path).unwrap();
            self.on_disk_at_post
                .lock()
                .unwrap()
                .push((on_disk.sequence, on_disk.last_sent_unix));
        }
        if self.hang {
            std::future::pending::<()>().await;
        }
        self.replies
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or_else(|| reply(200, None))
    }
}

/// A fixture: the collector's dir and the agent's state root.
struct Fixture {
    dir: tempfile::TempDir,
}

impl Fixture {
    fn new() -> Self {
        let f = Self {
            dir: tempfile::tempdir().unwrap(),
        };
        std::fs::create_dir_all(f.inv()).unwrap();
        f
    }
    fn inv(&self) -> PathBuf {
        self.dir.path().join("run/inventory")
    }
    fn state_path(&self) -> PathBuf {
        self.dir
            .path()
            .join("var/lib/hippius-miner")
            .join(state::STATE_FILE)
    }
    fn write<T: serde::Serialize>(&self, name: &str, section: &T) {
        std::fs::write(
            self.inv().join(format!("{name}.json")),
            serde_json::to_vec_pretty(section).unwrap(),
        )
        .unwrap();
    }
    fn write_raw(&self, name: &str, bytes: &[u8]) {
        std::fs::write(self.inv().join(format!("{name}.json")), bytes).unwrap();
    }
    fn read(&self) -> ReadOutcome {
        read::read_sections(&self.inv())
    }
    fn config(&self) -> PosterConfig {
        PosterConfig {
            miner_id: "miner-a".into(),
            dir: self.inv(),
            state_path: self.state_path(),
            cadence: Cadence {
                full_interval: 86400,
                full_jitter: 3600,
                counters_interval: 21600,
                min_gap: 300,
            },
            poll: Duration::from_secs(60),
        }
    }
    /// A poster on a fresh state (no state file).
    async fn fresh(&self, edge: &Arc<MockEdge>, identity: &Arc<MinerIdentity>) -> Poster {
        let _ = std::fs::remove_file(self.state_path());
        self.poster(edge, identity).await
    }
    async fn poster(&self, edge: &Arc<MockEdge>, identity: &Arc<MinerIdentity>) -> Poster {
        Poster::open(
            self.config(),
            Arc::clone(identity),
            Arc::clone(edge) as Arc<dyn InventoryClient>,
        )
        .await
        // The middle of the jitter span: no offset.
        .with_jitter(Box::new(|| 3600))
    }
    /// Every section the collector writes today (no sensors).
    fn write_full_set(&self, uptime_s: u64) {
        self.write("system", &system());
        self.write("cpu", &cpu());
        self.write(
            "memory",
            &MemorySection {
                status: SectionStatus::Ok,
                total_mib: 65536,
                dimms: vec![],
                edac: None,
            },
        );
        self.write("storage", &storage(0));
        self.write(
            "network",
            &NetworkSection {
                status: SectionStatus::Ok,
                nics: vec![],
                netbird: None,
                virtual_interfaces: 3,
            },
        );
        self.write(
            "pci",
            &PciSection {
                status: SectionStatus::Ok,
                devices: vec![],
            },
        );
        self.write("software", &software(uptime_s));
    }
}

fn system() -> SystemSection {
    SystemSection {
        status: SectionStatus::Ok,
        vendor: Some("Dell Inc.".into()),
        product: Some("PowerEdge R6515".into()),
        serial: Some("SERIAL-DO-NOT-LOG".into()),
        board_vendor: None,
        board_product: None,
        bios_vendor: None,
        bios_version: None,
        bios_date: None,
        bmc_present: false,
        ipmi_version: None,
        bmc_firmware: None,
    }
}

fn cpu() -> CpuSection {
    CpuSection {
        status: SectionStatus::Ok,
        model: Some("AMD EPYC 9254".into()),
        family: 25,
        model_id: 17,
        stepping: 1,
        sockets: 1,
        cores: 24,
        threads: 24,
        smt_control: None,
        smt_active: false,
        base_mhz: None,
        max_mhz: None,
        microcode: None,
        sev: true,
        sev_es: true,
        sev_snp: true,
        flags: vec![],
    }
}

fn software(uptime_s: u64) -> SoftwareSection {
    SoftwareSection {
        status: SectionStatus::Ok,
        kernel: Some("6.17.0".into()),
        os_name: Some("Ubuntu".into()),
        os_version_id: Some("26.04".into()),
        agent_version: None,
        qemu_version: None,
        libvirt_version: None,
        uptime_s,
        last_boot_unix: None,
    }
}

/// A storage section of `n` disks with long by-id names.
fn storage(n: usize) -> StorageSection {
    StorageSection {
        status: SectionStatus::Ok,
        devices: (0..n)
            .map(|i| Device {
                name: format!("nvme{i}n1"),
                kind: DeviceKind::Disk,
                size_bytes: 4 << 40,
                ids: (0..4)
                    .map(|k| {
                        format!(
                            "nvme-VENDOR_MODEL_WITH_A_RATHER_LONG_NAME_SERIAL{i:06}_{k}_{}",
                            "x".repeat(24)
                        )
                    })
                    .collect(),
                model: Some("VENDOR NVME MODEL WITH A RATHER LONG MARKETING NAME".into()),
                transport: Transport::Nvme,
                rotational_hint: Some(false),
                removable: false,
                read_only: false,
                behind_controller: None,
                partitions: vec![],
                holders: vec![],
                md: None,
                fs: None,
                mounts: vec![],
                role: DeviceRole::EligibleDedicated,
                pool_ids: vec![],
                reasons: vec![],
            })
            .collect(),
        advisories: vec![],
        advisories_truncated: false,
        devices_truncated: false,
    }
}

fn identity() -> Arc<MinerIdentity> {
    Arc::new(MinerIdentity::generate().unwrap())
}

/// The envelope verified with the miner's public key, its body decoded
/// through the crate.
fn open(identity: &MinerIdentity, envelope: &[u8]) -> HostInventory {
    assert!(envelope.len() <= MAX_ENVELOPE_BYTES);
    let env = SignedHostInventory::decode(envelope).unwrap();
    let sig = Signature::from_slice(&env.sig).unwrap();
    identity.verifying_key().verify(&env.body, &sig).unwrap();
    HostInventory::decode(&env.body).unwrap()
}

fn names(body: &HostInventory) -> Vec<&'static str> {
    let s = &body.sections;
    [
        ("system", s.system.is_some()),
        ("cpu", s.cpu.is_some()),
        ("memory", s.memory.is_some()),
        ("storage", s.storage.is_some()),
        ("network", s.network.is_some()),
        ("pci", s.pci.is_some()),
        ("sensors", s.sensors.is_some()),
        ("software", s.software.is_some()),
    ]
    .into_iter()
    .filter(|(_, p)| *p)
    .map(|(n, _)| n)
    .collect()
}

fn sent(slot: Slot, kind: ReportKind, outcome: Outcome) -> impl Fn(&Tick) -> bool {
    move |t| matches!(t, Tick::Sent { slot: s, kind: k, outcome: o, .. } if *s == slot && *k == kind && *o == outcome)
}

// ─── cadence ─────────────────────────────────────────────────────────

#[tokio::test]
async fn full_change_and_counters_cadence() {
    let f = Fixture::new();
    let edge = Arc::new(MockEdge::default());
    let id = identity();
    let mut p = f.poster(&edge, &id).await;

    // Nothing to send before the collector has written anything.
    assert_eq!(p.tick(T0 - 10, &f.read()).await, Tick::Idle);
    assert!(edge.sent().is_empty());

    // Start: the full slot, as a `change` carrying every section (no
    // sensors yet: a `full` would be refused by the crate).
    f.write_full_set(100);
    let t = p.tick(T0, &f.read()).await;
    assert!(
        sent(Slot::Full, ReportKind::Change, Outcome::Accepted)(&t),
        "{t:?}"
    );
    let body = open(&id, &edge.sent()[0]);
    assert_eq!(body.report, ReportKind::Change);
    assert_eq!(
        names(&body),
        ["system", "cpu", "memory", "storage", "network", "pci", "software"]
    );
    assert_eq!(body.miner_id, "miner-a");
    assert_eq!(body.timestamp_unix, T0);
    // The next full: 24 h from now (the fixed jitter draw is the centre).
    assert_eq!(p.state().next_full_unix, Some(T0 + 86400));

    // Unchanged: nothing.
    assert_eq!(p.tick(T0 + 600, &f.read()).await, Tick::Idle);
    // A change within the 5 min debounce waits; past it, only that
    // section goes.
    f.write("software", &software(200));
    assert_eq!(p.tick(T0 + 60, &f.read()).await, Tick::Idle, "debounced");
    let t = p.tick(T0 + 900, &f.read()).await;
    assert!(
        sent(Slot::Change, ReportKind::Change, Outcome::Accepted)(&t),
        "{t:?}"
    );
    assert_eq!(names(&open(&id, &edge.sent()[1])), ["software"]);

    // Counters, 6 h after the full: memory, storage, software (no sensors).
    assert_eq!(p.tick(T0 + 21599, &f.read()).await, Tick::Idle);
    let t = p.tick(T0 + 21600, &f.read()).await;
    assert!(
        sent(Slot::Counters, ReportKind::Counters, Outcome::Accepted)(&t),
        "{t:?}"
    );
    assert_eq!(
        names(&open(&id, &edge.sent()[2])),
        ["memory", "storage", "software"]
    );

    // The counters come back every 6 h; the next full at its due time.
    let t = p.tick(T0 + 86000, &f.read()).await;
    assert!(
        sent(Slot::Counters, ReportKind::Counters, Outcome::Accepted)(&t),
        "{t:?}"
    );
    let t = p.tick(T0 + 86400, &f.read()).await;
    assert!(
        sent(Slot::Full, ReportKind::Change, Outcome::Accepted)(&t),
        "{t:?}"
    );

    // Never two reports within the gap, whatever is due.
    let times: Vec<i64> = edge
        .sent()
        .iter()
        .map(|e| open(&id, e).timestamp_unix)
        .collect();
    assert!(times.windows(2).all(|w| w[1] - w[0] >= 300), "{times:?}");
}

#[test]
fn the_full_jitter_stays_within_bounds() {
    let c = Cadence {
        full_interval: 86400,
        full_jitter: 3600,
        counters_interval: 21600,
        min_gap: 300,
    };
    assert_eq!(plan::next_full(T0, &c, 0), T0 + 86400 - 3600);
    assert_eq!(plan::next_full(T0, &c, 7200), T0 + 86400 + 3600);
    assert_eq!(plan::next_full(T0, &c, 3600), T0 + 86400);
    for draw in [1, 7201, 12345, u64::MAX, u64::MAX / 3, 1 << 40] {
        let at = plan::next_full(T0, &c, draw);
        assert!((T0 + 82800..=T0 + 90000).contains(&at), "{draw}: {at}");
    }
}

#[tokio::test]
async fn with_sensors_the_full_slot_is_a_real_full_report() {
    let f = Fixture::new();
    f.write_full_set(100);
    f.write(
        "sensors",
        &SensorsSection {
            status: SectionStatus::Unavailable,
            temperatures: vec![],
            fans: vec![],
            psus: vec![],
        },
    );
    let edge = Arc::new(MockEdge::default());
    let id = identity();
    let mut p = f.poster(&edge, &id).await;
    let t = p.tick(T0, &f.read()).await;
    assert!(
        sent(Slot::Full, ReportKind::Full, Outcome::Accepted)(&t),
        "{t:?}"
    );
    let body = open(&id, &edge.sent()[0]);
    assert_eq!(body.report, ReportKind::Full);
    assert_eq!(names(&body).len(), 8);
    // Counters now carry sensors too.
    let t = p.tick(T0 + 21600, &f.read()).await;
    assert!(sent(
        Slot::Counters,
        ReportKind::Counters,
        Outcome::Accepted
    )(&t));
    assert_eq!(
        names(&open(&id, &edge.sent()[1])),
        ["memory", "storage", "sensors", "software"]
    );
}

// ─── state ───────────────────────────────────────────────────────────

#[tokio::test]
async fn the_sequence_survives_a_restart_and_the_state_is_owner_only() {
    let f = Fixture::new();
    f.write_full_set(100);
    let edge = Arc::new(MockEdge::default());
    let id = identity();
    let mut p = f.poster(&edge, &id).await;
    let Tick::Sent { sequence: s1, .. } = p.tick(T0, &f.read()).await else {
        panic!("not sent")
    };
    assert!(s1 >= u64::try_from(T0).unwrap() * state::SEQUENCE_CLOCK_SCALE);
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(f.state_path())
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600);
    drop(p);

    // A restart: the same file and its digests, a higher sequence (the
    // full is recent: only the change goes, see the restart test).
    let mut p = f.poster(&edge, &id).await;
    assert_eq!(p.state().sequence, s1);
    assert_eq!(p.state().digests.len(), 7);
    f.write("software", &software(700));
    let Tick::Sent {
        sequence: s2, slot, ..
    } = p.tick(T0 + 600, &f.read()).await
    else {
        panic!("not sent")
    };
    assert_eq!(slot, Slot::Change);
    assert!(s2 > s1);
    assert_eq!(open(&id, &edge.sent()[1]).sequence, s2);

    // A corrupt state starts over above the clock floor.
    std::fs::write(f.state_path(), b"{nope").unwrap();
    let mut p = f.poster(&edge, &id).await;
    assert_eq!(p.state().sequence, 0);
    let Tick::Sent { sequence: s3, .. } = p.tick(T0 + 1000, &f.read()).await else {
        panic!("not sent")
    };
    assert!(s3 > s2, "the clock floor keeps it above vali's last");
}

#[test]
fn the_sequence_only_grows_even_with_the_clock_behind() {
    let mut st = state::InventoryState {
        sequence: 5_000_000_000_000,
        ..Default::default()
    };
    assert_eq!(
        st.next_sequence(T0),
        5_000_000_000_001,
        "the clock floor is lower"
    );
    assert_eq!(st.next_sequence(-5), 5_000_000_000_002);
    let mut st = state::InventoryState::default();
    assert_eq!(st.next_sequence(T0), u64::try_from(T0).unwrap() * 1000);
    assert_eq!(st.next_sequence(T0), u64::try_from(T0).unwrap() * 1000 + 1);
}

#[tokio::test]
async fn the_sequence_is_consumed_before_the_send() {
    let f = Fixture::new();
    f.write_full_set(100);
    let edge = Arc::new(
        MockEdge {
            watch_state: Some(f.state_path()),
            ..MockEdge::default()
        }
        .then(Err(())),
    );
    let id = identity();
    let mut p = f.poster(&edge, &id).await;
    let Tick::Sent {
        sequence: s1,
        outcome,
        ..
    } = p.tick(T0, &f.read()).await
    else {
        panic!("not sent")
    };
    assert_eq!(outcome, Outcome::Transport);
    // On disk already while the request was in flight, the send stamped.
    assert_eq!(*edge.on_disk_at_post.lock().unwrap(), [(s1, Some(T0))]);
    // Persisted though no reply came: a restart never reuses it.
    assert_eq!(
        state::InventoryState::load(&f.state_path())
            .unwrap()
            .sequence,
        s1
    );
    // No digest advanced: the same report is due again.
    assert!(p.state().digests.is_empty());
}

// ─── reading ─────────────────────────────────────────────────────────

#[tokio::test]
async fn a_malformed_section_is_skipped_and_counted() {
    let f = Fixture::new();
    f.write_full_set(100);
    // Bad JSON, an unknown field, an invalid value, a file past the cap.
    f.write_raw("network", b"{not json");
    let mut sys = serde_json::to_value(system()).unwrap();
    sys["extra"] = serde_json::json!(1);
    f.write_raw("system", &serde_json::to_vec(&sys).unwrap());
    let mut sw = software(1);
    sw.kernel = Some("bad\nkernel".into());
    f.write("software", &sw);
    f.write_raw(
        "pci",
        &vec![b' '; (read::MAX_SECTION_FILE_BYTES + 1) as usize],
    );
    let read = f.read();
    assert_eq!(
        read.skipped
            .iter()
            .map(|(n, c)| (*n, *c))
            .collect::<Vec<_>>(),
        [
            ("network", "parse"),
            ("pci", "too-large"),
            ("software", "invalid"),
            ("system", "parse")
        ]
    );
    assert!(read.sections.network.is_none() && read.sections.system.is_none());

    // Without a full set, the counters slot goes with what is there.
    let edge = Arc::new(MockEdge::default());
    let id = identity();
    let mut p = f.poster(&edge, &id).await;
    let t = p.tick(T0, &read).await;
    assert!(
        sent(Slot::Counters, ReportKind::Counters, Outcome::Accepted)(&t),
        "{t:?}"
    );
    assert_eq!(names(&open(&id, &edge.sent()[0])), ["memory", "storage"]);
    assert_eq!(p.stats.skipped_sections, 4);
}

// ─── replies ─────────────────────────────────────────────────────────

/// The waits between sends for `replies`, starting at `T0`.
async fn waits(
    f: &Fixture,
    id: &Arc<MinerIdentity>,
    replies: Vec<Result<EdgeReply, ()>>,
) -> Vec<i64> {
    let n = replies.len();
    let mut edge = MockEdge::default();
    for r in replies {
        edge = edge.then(r);
    }
    let edge = Arc::new(edge);
    let mut p = f.fresh(&edge, id).await;
    let mut now = T0;
    let mut out = Vec::new();
    for _ in 0..n {
        assert!(matches!(p.tick(now, &f.read()).await, Tick::Sent { .. }));
        let until = p.backoff_until.unwrap();
        assert_eq!(p.tick(until - 1, &f.read()).await, Tick::Idle);
        out.push(until - now);
        now = until;
    }
    // Then delivered: every back-off resets.
    assert!(matches!(
        p.tick(now, &f.read()).await,
        Tick::Sent {
            outcome: Outcome::Accepted,
            ..
        }
    ));
    assert_eq!(p.backoff_until, None);
    assert_eq!(p.refused_streak, 0);
    assert_eq!(p.transport_backoff, TRANSPORT_BACKOFF_START_SECS);
    out
}

#[tokio::test]
async fn each_reply_class() {
    let f = Fixture::new();
    f.write_full_set(100);
    let id = identity();

    // The Edge's 429: its Retry-After, else 15 min.
    assert_eq!(
        waits(&f, &id, vec![reply(429, Some(1200)), reply(429, None)]).await,
        [1200, 900]
    );
    // 502 (vali refused or unavailable — every vali non-2xx looks like
    // this through the Edge), and the Edge's own 400 / 413: one growing
    // back-off, capped at 6 h.
    assert_eq!(
        waits(&f, &id, vec![reply(502, None); 7]).await,
        [900, 1800, 3600, 7200, 21600, 21600, 21600]
    );
    assert_eq!(
        waits(
            &f,
            &id,
            vec![reply(400, None), reply(413, None), reply(502, None)]
        )
        .await,
        [900, 1800, 3600]
    );
    // Transport: exponential from 60 s, never under the 5 min gap,
    // capped at an hour.
    assert_eq!(
        waits(&f, &id, vec![Err(()); 10]).await,
        [300, 300, 300, 480, 960, 1920, 3600, 3600, 3600, 3600]
    );
    // A refusal leaves the digests: the same report is due again.
    let edge = Arc::new(MockEdge::default().then(reply(502, None)));
    let mut p = f.fresh(&edge, &id).await;
    p.tick(T0, &f.read()).await;
    assert!(p.state().digests.is_empty());
}

#[tokio::test]
async fn a_repeated_refusal_is_logged_once_then_every_6_hours() {
    let f = Fixture::new();
    f.write_full_set(100);
    let id = identity();
    let mut edge = MockEdge::default();
    for _ in 0..7 {
        edge = edge.then(reply(502, None));
    }
    let edge = Arc::new(edge);
    let mut p = f.fresh(&edge, &id).await;
    let mut now = T0;
    let mut logged = Vec::new();
    for _ in 0..7 {
        let before = p.stats.status_lines;
        assert!(matches!(p.tick(now, &f.read()).await, Tick::Sent { .. }));
        logged.push((now - T0, p.stats.status_lines > before));
        now = p.backoff_until.unwrap();
    }
    // Sends at +0, +900, +2700, +6300, +13500, +35100, +56700: printed at
    // the first, then once 6 h have passed since the last line.
    assert_eq!(
        logged,
        [
            (0, true),
            (900, false),
            (2700, false),
            (6300, false),
            (13500, false),
            (35100, true),
            (56700, true)
        ]
    );
    // Delivered: printed, and a new refusal is printed again.
    let before = p.stats.status_lines;
    assert!(matches!(
        p.tick(now, &f.read()).await,
        Tick::Sent {
            outcome: Outcome::Accepted,
            ..
        }
    ));
    assert_eq!(p.stats.status_lines, before + 1);
}

// ─── restarts ────────────────────────────────────────────────────────

#[tokio::test]
async fn a_restart_skips_the_startup_full_after_a_recent_one() {
    let f = Fixture::new();
    f.write_full_set(100);
    let edge = Arc::new(MockEdge::default());
    let id = identity();
    let mut p = f.poster(&edge, &id).await;
    assert!(sent(Slot::Full, ReportKind::Change, Outcome::Accepted)(
        &p.tick(T0, &f.read()).await
    ));
    drop(p);

    // Within 6 h, nothing changed: nothing at all.
    let mut p = f.poster(&edge, &id).await;
    assert_eq!(p.tick(T0 + 3600, &f.read()).await, Tick::Idle);
    // Within 6 h, a section changed: only that change.
    f.write("software", &software(4000));
    let t = p.tick(T0 + 3700, &f.read()).await;
    assert!(
        sent(Slot::Change, ReportKind::Change, Outcome::Accepted)(&t),
        "{t:?}"
    );
    assert_eq!(names(&open(&id, edge.sent().last().unwrap())), ["software"]);
    drop(p);

    // Past 6 h: the startup full is sent.
    let mut p = f.poster(&edge, &id).await;
    let t = p.tick(T0 + RESTART_FULL_SKIP_SECS + 1, &f.read()).await;
    assert!(
        sent(Slot::Full, ReportKind::Change, Outcome::Accepted)(&t),
        "{t:?}"
    );
}

#[tokio::test]
async fn a_cancel_ends_a_hanging_post_at_once() {
    let f = Fixture::new();
    f.write_full_set(100);
    let edge = Arc::new(MockEdge {
        hang: true,
        ..MockEdge::default()
    });
    let poster = f.poster(&edge, &identity()).await;
    let cancel = CancellationToken::new();
    let task = tokio::spawn(run(poster, cancel.clone()));
    for _ in 0..200 {
        if !edge.sent().is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(edge.sent().len(), 1, "the post is in flight");
    cancel.cancel();
    tokio::time::timeout(Duration::from_secs(1), task)
        .await
        .expect("the drain returns promptly")
        .unwrap();
}

// ─── the envelope ────────────────────────────────────────────────────

#[tokio::test]
async fn the_envelope_verifies_and_decodes() {
    let f = Fixture::new();
    f.write_full_set(100);
    let edge = Arc::new(MockEdge::default());
    let id = identity();
    let mut p = f.poster(&edge, &id).await;
    p.tick(T0, &f.read()).await;
    let env = &edge.sent()[0];
    let body = open(&id, env);
    assert_eq!(body.domain, hippius_host_inventory::DOMAIN);
    assert_eq!(body.schema_version, hippius_host_inventory::SCHEMA_VERSION);
    // Another key does not verify it.
    let other = MinerIdentity::generate().unwrap();
    let decoded = SignedHostInventory::decode(env).unwrap();
    let sig = Signature::from_slice(&decoded.sig).unwrap();
    assert!(other.verifying_key().verify(&decoded.body, &sig).is_err());
}

#[tokio::test]
async fn a_large_inventory_is_fitted_under_the_cap() {
    let f = Fixture::new();
    f.write_full_set(100);
    f.write("storage", &storage(300));
    let edge = Arc::new(MockEdge::default());
    let id = identity();
    let mut p = f.poster(&edge, &id).await;
    let t = p.tick(T0, &f.read()).await;
    assert!(
        matches!(
            t,
            Tick::Sent {
                outcome: Outcome::Accepted,
                ..
            }
        ),
        "{t:?}"
    );
    let env = &edge.sent()[0];
    assert!(env.len() <= MAX_ENVELOPE_BYTES, "{}", env.len());
    let body = open(&id, env);
    let st = body.sections.storage.unwrap();
    assert!(st.devices_truncated);
    assert!(st.devices.len() < 300);
}

// ─── spawning ────────────────────────────────────────────────────────

const CONFIG: &str = r#"
[miner]
miner_id = "miner-a"

[edge]
endpoint = "https://edge.hippius.network:443"
ca_cert = "/var/lib/hippius-miner/edge-ca.crt"
order_signing_pubkey = "1111111111111111111111111111111111111111111111111111111111111111"

[identity]
key_path = "/var/lib/hippius-miner/identity.key"
pub_path = "/var/lib/hippius-miner/identity.pub"

[image]
cache_dir = "/var/lib/hippius-miner/images"
staging_dir = "/var/lib/hippius-miner/staging"
s3_endpoint = "https://s3.hippius.com"
s3_bucket = "hippius-compute-images"

[orders]
bind_addr = "100.64.0.10:9700"

[host]
cvm_cpu_budget = 8
cvm_memory_mb_budget = 16384
"#;

#[tokio::test]
async fn the_disabled_flag_spawns_nothing() {
    let f = Fixture::new();
    let mut config: Config = toml::from_str(CONFIG).unwrap();
    config.validate().unwrap();
    // Point everything at the fixture: never the real /run or /var/lib.
    config.inventory.dir = f.inv();
    config.storage.state_disk_root = f.dir.path().join("var/lib/hippius-miner");
    let edge = Arc::new(MockEdge::default());
    let cancel = CancellationToken::new();
    assert!(!config.inventory.enabled, "off by default");
    assert!(spawn_if_enabled(
        &config,
        identity(),
        Arc::clone(&edge) as Arc<dyn InventoryClient>,
        cancel.clone()
    )
    .is_none());
    assert!(!f.state_path().exists(), "nothing ran");

    // Enabled: it runs, sends the full set, and stops on cancel.
    f.write_full_set(100);
    config.inventory.enabled = true;
    let task = spawn_if_enabled(
        &config,
        identity(),
        Arc::clone(&edge) as Arc<dyn InventoryClient>,
        cancel.clone(),
    )
    .unwrap();
    for _ in 0..200 {
        if !edge.sent().is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(edge.sent().len(), 1);
    cancel.cancel();
    tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .unwrap()
        .unwrap();
    assert!(f.state_path().exists());
}

#[tokio::test]
async fn one_read_in_flight() {
    let f = Fixture::new();
    f.write_full_set(100);
    let inflight = Arc::new(AtomicBool::new(true));
    assert!(
        read_bounded(&f.inv(), &inflight).await.is_none(),
        "a read still running"
    );
    inflight.store(false, Ordering::Release);
    let read = read_bounded(&f.inv(), &inflight).await.unwrap();
    assert_eq!(read.digests.len(), 7);
    assert!(!inflight.load(Ordering::Acquire), "released after the read");
}
