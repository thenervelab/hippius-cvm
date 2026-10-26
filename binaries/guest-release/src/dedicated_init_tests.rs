//! Tests for `--dedicated-init-wipe` (see `dedicated_init.rs`).

use super::*;
use crate::dedicated::RecordEntry;

const U0: &str = "11111111-2222-4333-8444-555555555555";
const U1: &str = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";

#[test]
fn the_state_file_round_trips_and_junk_is_dropped() {
    let text = "# hippius-dedicated-disks state v1\nx0 attached 1000 vdb -\nx1 initializing 3500 vdc init-0\nbroken line\n";
    let lines = parse_state(text);
    assert_eq!(lines.len(), 2);
    assert_eq!(lines[1].reason, "init-0");
    assert_eq!(
        render_state(&lines),
        "# hippius-dedicated-disks state v1\nx0 attached 1000 vdb -\nx1 initializing 3500 vdc init-0\n"
    );
}

#[test]
fn a_dm_uuid_names_its_luks_volume_only_for_our_mapping() {
    let dm = "CRYPT-LUKS2-111111112222433384445555555555555-hippius-x0-init";
    // One hex digit too many: not a UUID.
    assert_eq!(luks_uuid_of_dm_uuid(dm, "hippius-x0-init"), None);
    let dm = "CRYPT-LUKS2-11111111222243338444555555555555-hippius-x0-init\n";
    assert_eq!(
        luks_uuid_of_dm_uuid(dm, "hippius-x0-init").as_deref(),
        Some(U0)
    );
    assert_eq!(luks_uuid_of_dm_uuid(dm, "hippius-x1-init"), None);
    assert_eq!(
        luks_uuid_of_dm_uuid("CRYPT-PLAIN-hippius-x0-init", "hippius-x0-init"),
        None
    );
    assert_eq!(
        luks_uuid_of_dm_uuid(
            "CRYPT-LUKS2-1111111122224333844455555555555g-hippius-x0-init",
            "hippius-x0-init"
        ),
        None
    );
}

#[test]
fn only_a_journal_less_integrity_table_is_switched_to_the_journal() {
    let d = "0 7086080 integrity 252:16 32768 32 D 4 block_size:4096 buffer_sectors:128 journal_sectors:65536 interleave_sectors:32768\n";
    assert_eq!(
        journaled_table(d).as_deref(),
        Some("0 7086080 integrity 252:16 32768 32 J 4 block_size:4096 buffer_sectors:128 journal_sectors:65536 interleave_sectors:32768")
    );
    let j = d.replace(" D ", " J ");
    assert_eq!(journaled_table(&j).as_deref(), Some(j.trim()));
    for bad in [
        d.replace(" D ", " B "),
        d.replace("integrity", "crypt"),
        format!("{d}{d}"),
        "0 10 integrity 252:16 0 32 D".into(),
        String::new(),
    ] {
        assert_eq!(journaled_table(&bad), None, "{bad}");
    }
}

#[test]
fn the_init_list_names_dedicated_slots_once_each() {
    assert_eq!(parse_list("x0\nx3\n").unwrap(), ["x0", "x3"]);
    assert_eq!(parse_list("").unwrap(), Vec::<String>::new());
    for bad in ["os\n", "x24\n", "x0\nx0\n", "x0 \n", "../x\n"] {
        assert!(parse_list(bad).is_err(), "{bad:?}");
    }
}

// ── the decisions, on a fake host ──────────────────────────────────

#[derive(Default)]
struct Fake {
    /// init mapping name → its LUKS UUID.
    mappings: Mutex<BTreeMap<String, String>>,
    record: Mutex<Option<Record>>,
    fail_wipe: Vec<String>,
    fail_record_write: bool,
    fail_journal: bool,
    fail_rename: bool,
    unreadable_record: bool,
    states: Mutex<Vec<Vec<StateLine>>>,
    log: Mutex<Vec<String>>,
    workers: Mutex<Vec<usize>>,
}

impl Fake {
    fn push(&self, s: String) {
        self.log.lock().unwrap().push(s);
    }
    fn log(&self) -> Vec<String> {
        self.log.lock().unwrap().clone()
    }
}

impl InitHost for Fake {
    fn mapping_uuid(&self, name: &str) -> Result<String, String> {
        self.mappings
            .lock()
            .unwrap()
            .get(name)
            .cloned()
            .ok_or_else(|| "absent".into())
    }
    fn wipe(
        &self,
        name: &str,
        workers: usize,
        progress: &(dyn Fn(u8) + Sync),
    ) -> Result<(), String> {
        self.push(format!("wipe {name}"));
        self.workers.lock().unwrap().push(workers);
        progress(50);
        if self.fail_wipe.iter().any(|n| n == name) {
            return Err("eio".into());
        }
        progress(100);
        Ok(())
    }
    fn load_record(&self) -> Result<Record, &'static str> {
        if self.unreadable_record {
            return Err("record-unreadable");
        }
        Ok(self.record.lock().unwrap().clone().unwrap_or_default())
    }
    fn write_record(&self, record: &Record) -> Result<(), String> {
        if self.fail_record_write {
            return Err("ro".into());
        }
        *self.record.lock().unwrap() = Some(record.clone());
        Ok(())
    }
    fn enable_journal(&self, name: &str) -> Result<(), String> {
        self.push(format!("journal {name}"));
        if self.fail_journal {
            return Err("reload".into());
        }
        Ok(())
    }
    fn rename(&self, from: &str, to: &str) -> Result<(), String> {
        self.push(format!("rename {from} {to}"));
        if self.fail_rename {
            return Err("busy".into());
        }
        let mut m = self.mappings.lock().unwrap();
        if let Some(u) = m.remove(from) {
            m.insert(to.into(), u);
        }
        Ok(())
    }
    fn close(&self, name: &str) -> bool {
        self.push(format!("close {name}"));
        self.mappings.lock().unwrap().remove(name);
        true
    }
    fn write_state(&self, lines: &[StateLine]) -> Result<(), String> {
        self.states.lock().unwrap().push(lines.to_vec());
        Ok(())
    }
}

fn entry(state: RecordState, uuid: &str, integrity: bool) -> RecordEntry {
    RecordEntry {
        state,
        uuid: uuid.into(),
        size_gib: 3500,
        integrity,
    }
}

fn line(slot: &str, state: &str, dev: &str, reason: &str) -> StateLine {
    StateLine {
        slot: slot.into(),
        state: state.into(),
        gib: "3500".into(),
        dev: dev.into(),
        reason: reason.into(),
    }
}

/// Two integrity slots handed over by the opener, plus a plain one.
fn two_slots() -> (Fake, Vec<String>, Vec<StateLine>) {
    let f = Fake::default();
    let mut r = Record::new();
    r.insert("x0".into(), entry(RecordState::Ready, U1, false));
    r.insert("x1".into(), entry(RecordState::Formatting, U0, true));
    r.insert("x2".into(), entry(RecordState::Formatting, U1, true));
    *f.record.lock().unwrap() = Some(r);
    f.mappings
        .lock()
        .unwrap()
        .insert("hippius-x1-init".into(), U0.into());
    f.mappings
        .lock()
        .unwrap()
        .insert("hippius-x2-init".into(), U1.into());
    let lines = vec![
        line("x0", "attached", "vdb", "-"),
        line("x1", "initializing", "vdc", "init-0"),
        line("x2", "initializing", "vdd", "init-0"),
    ];
    (f, vec!["x1".into(), "x2".into()], lines)
}

fn short(lines: &[StateLine]) -> Vec<(String, String, String)> {
    lines
        .iter()
        .map(|l| (l.slot.clone(), l.state.clone(), l.reason.clone()))
        .collect()
}

fn t(slot: &str, state: &str, reason: &str) -> (String, String, String) {
    (slot.into(), state.into(), reason.into())
}

#[test]
fn a_finished_wipe_records_ready_then_journals_renames_and_attaches() {
    let (f, slots, lines) = two_slots();
    let out = process(&f, &slots, lines);
    assert_eq!(
        short(&out),
        [
            t("x0", "attached", "-"),
            t("x1", "attached", "-"),
            t("x2", "attached", "-")
        ]
    );
    let rec = f.record.lock().unwrap().clone().unwrap();
    assert_eq!(rec["x1"], entry(RecordState::Ready, U0, true));
    assert_eq!(rec["x2"], entry(RecordState::Ready, U1, true));
    assert_eq!(rec["x0"], entry(RecordState::Ready, U1, false), "untouched");
    // Per slot: wipe, then journal, then rename — in that order.
    let l = f.log();
    for s in ["x1", "x2"] {
        let pos = |p: String| l.iter().position(|x| *x == p).unwrap();
        let w = pos(format!("wipe hippius-{s}-init"));
        let j = pos(format!("journal hippius-{s}-init"));
        let r = pos(format!("rename hippius-{s}-init hippius-{s}"));
        assert!(w < j && j < r, "{l:?}");
    }
    // The progress went out on the way (the receipts read it).
    let states = f.states.lock().unwrap().clone();
    assert!(states
        .iter()
        .any(|s| s.iter().any(|l| l.slot == "x1" && l.reason == "init-50")));
    // Two slots share the writers budget.
    assert_eq!(*f.workers.lock().unwrap(), [4, 4]);
}

#[test]
fn a_failed_wipe_closes_the_slot_and_leaves_it_formatting() {
    let (mut f, slots, lines) = two_slots();
    f.fail_wipe = vec!["hippius-x2-init".into()];
    let out = process(&f, &slots, lines);
    assert_eq!(
        short(&out)[1..],
        [t("x1", "attached", "-"), t("x2", "mismatch", "wipe-failed")]
    );
    let rec = f.record.lock().unwrap().clone().unwrap();
    assert_eq!(
        rec["x2"].state,
        RecordState::Formatting,
        "the next boot starts again"
    );
    assert!(f.log().contains(&"close hippius-x2-init".to_string()));
    assert!(!f.log().iter().any(|x| x.starts_with("rename hippius-x2")));
}

#[test]
fn a_slot_is_never_handed_over_before_ready_is_durable() {
    let (mut f, slots, lines) = two_slots();
    f.fail_record_write = true;
    let out = process(&f, &slots, lines);
    assert_eq!(
        short(&out)[1..],
        [
            t("x1", "mismatch", "record-write-failed"),
            t("x2", "mismatch", "record-write-failed")
        ]
    );
    let l = f.log();
    assert!(
        !l.iter()
            .any(|x| x.starts_with("rename") || x.starts_with("journal")),
        "{l:?}"
    );
    assert!(l.contains(&"close hippius-x1-init".to_string()));
}

#[test]
fn a_journal_or_rename_failure_still_attaches_and_says_so() {
    let (mut f, slots, lines) = two_slots();
    f.fail_journal = true;
    let out = process(&f, &slots, lines);
    assert_eq!(short(&out)[1], t("x1", "attached", "no-journal-this-boot"));
    let (mut g, slots, lines) = two_slots();
    g.fail_rename = true;
    let out = process(&g, &slots, lines);
    assert_eq!(short(&out)[1], t("x1", "attached", "init-name"));
    // Either way the record says ready: the next boot opens it normally.
    assert_eq!(
        g.record.lock().unwrap().clone().unwrap()["x1"].state,
        RecordState::Ready
    );
}

/// One way the world differs from what the opener handed over.
type Mutate = dyn Fn(&Fake, &mut Vec<StateLine>);

#[test]
fn only_a_slot_the_opener_handed_over_is_wiped() {
    // State not `initializing`, record not `formatting … integrity`, or a
    // mapping that is not the recorded volume: closed, never wiped.
    let cases: Vec<Box<Mutate>> = vec![
        Box::new(|_, l| l[1].state = "attached".into()),
        Box::new(|f, _| {
            f.record
                .lock()
                .unwrap()
                .as_mut()
                .unwrap()
                .get_mut("x1")
                .unwrap()
                .state = RecordState::Ready
        }),
        Box::new(|f, _| {
            f.record
                .lock()
                .unwrap()
                .as_mut()
                .unwrap()
                .get_mut("x1")
                .unwrap()
                .integrity = false
        }),
        Box::new(|f, _| {
            f.record.lock().unwrap().as_mut().unwrap().remove("x1");
        }),
        Box::new(|f, _| {
            f.mappings
                .lock()
                .unwrap()
                .insert("hippius-x1-init".into(), U1.into());
        }),
        Box::new(|f, _| {
            f.mappings.lock().unwrap().remove("hippius-x1-init");
        }),
    ];
    for (i, case) in cases.iter().enumerate() {
        let (f, slots, mut lines) = two_slots();
        case(&f, &mut lines);
        let out = process(&f, &slots, lines);
        assert_eq!(
            short(&out)[1],
            t("x1", "mismatch", "init-mismatch"),
            "case {i}"
        );
        assert_eq!(short(&out)[2], t("x2", "attached", "-"), "case {i}");
        assert!(
            !f.log().contains(&"wipe hippius-x1-init".to_string()),
            "case {i}"
        );
        // The other slot then has the whole writers budget.
        assert_eq!(*f.workers.lock().unwrap(), [8], "case {i}");
    }
}

#[test]
fn an_unreadable_record_initialises_nothing() {
    let (mut f, slots, lines) = two_slots();
    f.unreadable_record = true;
    let out = process(&f, &slots, lines);
    assert_eq!(
        short(&out)[1..],
        [
            t("x1", "mismatch", "record-unreadable"),
            t("x2", "mismatch", "record-unreadable")
        ]
    );
    assert!(!f.log().iter().any(|x| x.starts_with("wipe")));
}

#[test]
fn eight_slots_share_eight_writers() {
    let f = Fake::default();
    let mut r = Record::new();
    let mut lines = Vec::new();
    let mut slots = Vec::new();
    for i in 0..8 {
        let s = format!("x{i}");
        let u = format!("{:08x}-2222-4333-8444-555555555555", i);
        r.insert(s.clone(), entry(RecordState::Formatting, &u, true));
        f.mappings
            .lock()
            .unwrap()
            .insert(format!("hippius-{s}-init"), u);
        lines.push(line(&s, "initializing", "vdb", "init-0"));
        slots.push(s);
    }
    *f.record.lock().unwrap() = Some(r);
    let out = process(&f, &slots, lines);
    assert!(out.iter().all(|l| l.state == "attached"));
    assert_eq!(*f.workers.lock().unwrap(), [1; 8]);
    assert!(f
        .record
        .lock()
        .unwrap()
        .clone()
        .unwrap()
        .values()
        .all(|e| e.state == RecordState::Ready));
}
