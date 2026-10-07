//! Metering counters (spec §9.1-9.2).
//!
//! OpenResty's `log_by_lua` sends one JSON datagram per request to the
//! agent's Unix datagram socket. The agent classifies nothing itself:
//! OpenResty says whether the request was billable. The agent only adds
//! the record to monotonic totals keyed by `(zone, client_region)`.
//!
//! Counters live in the agent, never in OpenResty shared memory, which
//! can evict. They are persisted atomically every few seconds.
//!
//! The socket is reachable from the internet-facing OpenResty workers, so
//! a record is never trusted further than it must be: a zone the feed has
//! not applied is counted as `unattributed` (never billed to anyone), and
//! a record claiming more bytes than one response can carry is dropped.
//!
//! **Epochs.** Every agent start opens a fresh random 128-bit
//! `counter_epoch` with totals at zero. The previous run's epoch is not
//! continued: its persisted totals are turned into one final report
//! (`seq` one above anything it can have sent, since every report is
//! persisted before it is queued), then the new epoch starts. Continuity
//! across a crash, a reboot or a restored volume therefore never has to
//! be proven, and nothing counted is lost:
//! - a crash loses at most the last persist interval;
//! - a corrupt or missing file just means there is no final report;
//! - a restored (older) file yields a final report whose `seq` the
//!   backend has already seen, so it is skipped as a replay.

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::io::ErrorKind;
use std::os::unix::fs::MetadataExt;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixDatagram;
use std::path::Path;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};

use crate::config::is_valid_id;
use crate::error::{CdnError, Result};
use crate::hooks::RecordSink;
use crate::persist;
use crate::shutdown::ShutdownWatch;
use crate::wire::{CounterSet, UsageReport};

/// Counter file format version.
const COUNTERS_FORMAT: u32 = 1;
/// Distinct `(zone, client_region)` keys held in one epoch. Past this,
/// records go to `unattributed` rather than growing memory without
/// bound (a buggy or hostile sender cannot exhaust the agent).
const MAX_KEYS: usize = 100_000;
/// One response cannot write more than this (the largest cached object
/// is 10 GB, spec §10.1); a record above it is refused.
const MAX_RECORD_BYTES: u64 = 1 << 34;
/// A persisted `seq` above this is treated as a corrupt file.
const MAX_SEQ: u64 = 1 << 62;
/// Largest metering datagram.
const MAX_DATAGRAM: usize = 2_048;
const MAX_COUNTERS_FILE: u64 = 256 * 1024 * 1024;

/// `$upstream_cache_status`, lower-cased.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum CacheStatus {
    Hit,
    Miss,
    Bypass,
    Expired,
    Stale,
    Updating,
    Revalidated,
}

/// One request, as `log_by_lua` reports it. Closed field set.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RequestRecord {
    /// `None` when no zone matched (unknown host).
    #[serde(default)]
    pub zone: Option<String>,
    /// Client billing region (ISO 3166 alpha-2, like vali's region
    /// codes) from the baked GeoIP database; `XX` when unknown.
    pub client_region: String,
    /// OpenResty's billable/non-billable classification (spec §9.1).
    pub billable: bool,
    /// Bytes actually written to the client, headers + body.
    pub bytes_out: u64,
    #[serde(default)]
    pub cache: Option<CacheStatus>,
    #[serde(default)]
    pub bytes_from_origin: u64,
    #[serde(default)]
    pub bytes_from_shield: u64,
    pub status: u16,
}

impl RequestRecord {
    /// Decode and validate one datagram.
    pub fn parse(datagram: &[u8]) -> Result<Self> {
        let rec: Self =
            serde_json::from_slice(datagram).map_err(|_| CdnError::Counters("record-decode"))?;
        let region_ok = rec.client_region.len() == 2
            && rec.client_region.bytes().all(|b| b.is_ascii_uppercase());
        if !region_ok {
            return Err(CdnError::Counters("record-region"));
        }
        if rec.zone.as_deref().is_some_and(|z| !is_valid_id(z)) {
            return Err(CdnError::Counters("record-zone"));
        }
        if !(100..=599).contains(&rec.status) {
            return Err(CdnError::Counters("record-status"));
        }
        if rec.bytes_out > MAX_RECORD_BYTES
            || rec.bytes_from_origin > MAX_RECORD_BYTES
            || rec.bytes_from_shield > MAX_RECORD_BYTES
        {
            return Err(CdnError::Counters("record-bytes"));
        }
        Ok(rec)
    }
}

/// Totals of the current epoch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counters {
    format: u32,
    epoch: String,
    seq: u64,
    zones: BTreeMap<String, BTreeMap<String, CounterSet>>,
    unattributed: CounterSet,
    #[serde(skip)]
    keys: usize,
}

/// What [`Counters::start`] found from the previous run.
#[derive(Debug, PartialEq, Eq)]
pub enum Previous {
    /// No counter file: first boot.
    None,
    /// A corrupt file: its totals are unrecoverable.
    Corrupt,
    /// A valid file: here is its final report body source.
    Final(Box<Counters>),
}

impl Counters {
    /// A fresh epoch with zero totals.
    pub fn fresh() -> Self {
        let mut epoch = [0u8; 16];
        OsRng.fill_bytes(&mut epoch);
        Self {
            format: COUNTERS_FORMAT,
            epoch: hex::encode(epoch),
            seq: 0,
            zones: BTreeMap::new(),
            unattributed: CounterSet::default(),
            keys: 0,
        }
    }

    /// Read the previous run's file at `path` (see module docs), then
    /// return a fresh epoch and what was found.
    pub fn start(path: &Path) -> Result<(Self, Previous)> {
        let previous = match persist::read_optional(path, MAX_COUNTERS_FILE) {
            Ok(None) => Previous::None,
            Ok(Some(bytes)) => match Self::decode(&bytes) {
                Some(c) => Previous::Final(Box::new(c)),
                None => Previous::Corrupt,
            },
            Err(CdnError::Io("state-file-too-large")) => Previous::Corrupt,
            Err(e) => return Err(e),
        };
        Ok((Self::fresh(), previous))
    }

    fn decode(bytes: &[u8]) -> Option<Self> {
        let mut c: Self = serde_json::from_slice(bytes).ok()?;
        let epoch_ok = c.epoch.len() == 32 && c.epoch.bytes().all(|b| b.is_ascii_hexdigit());
        if c.format != COUNTERS_FORMAT || !epoch_ok || c.seq > MAX_SEQ {
            return None;
        }
        c.keys = c.zones.values().map(BTreeMap::len).sum();
        Some(c)
    }

    pub fn epoch(&self) -> &str {
        &self.epoch
    }

    pub fn seq(&self) -> u64 {
        self.seq
    }

    /// Add one request. `zone_known` says whether the record's zone is
    /// in the applied feed; an unknown zone counts as unattributed.
    /// Totals saturate rather than wrap.
    pub fn record(&mut self, rec: &RequestRecord, zone_known: bool) {
        let slot = match rec.zone.as_deref() {
            Some(_) if !zone_known => &mut self.unattributed,
            None => &mut self.unattributed,
            Some(zone) => {
                let known = self
                    .zones
                    .get(zone)
                    .is_some_and(|r| r.contains_key(&rec.client_region));
                if !known && self.keys >= MAX_KEYS {
                    &mut self.unattributed
                } else {
                    if !known {
                        self.keys += 1;
                    }
                    self.zones
                        .entry(zone.to_string())
                        .or_default()
                        .entry(rec.client_region.clone())
                        .or_default()
                }
            }
        };
        add(slot, rec);
    }

    /// Persist the current totals (atomic).
    pub fn persist(&self, path: &Path) -> Result<()> {
        let bytes = serde_json::to_vec(self).map_err(|_| CdnError::Counters("encode"))?;
        persist::atomic_write(path, &bytes)
    }

    /// Advance `seq`, persist, and return the report. If the persist
    /// fails, `seq` is rolled back and nothing may be sent: a report is
    /// only ever sent after the totals it carries are on disk.
    pub fn checkpoint(
        &mut self,
        path: &Path,
        node: &str,
        at: String,
        applied_revision: u64,
        geoip_db: &str,
    ) -> Result<UsageReport> {
        self.seq = self.seq.saturating_add(1);
        if let Err(e) = self.persist(path) {
            self.seq = self.seq.saturating_sub(1);
            return Err(e);
        }
        Ok(self.report(node, at, applied_revision, geoip_db))
    }

    /// Advance `seq` and return a snapshot to persist outside the lock.
    /// If persisting the snapshot fails, call [`abort_checkpoint`]
    /// (Self::abort_checkpoint) and send nothing.
    pub fn begin_checkpoint(&mut self) -> Self {
        self.seq = self.seq.saturating_add(1);
        self.clone()
    }

    /// Undo [`begin_checkpoint`](Self::begin_checkpoint).
    pub fn abort_checkpoint(&mut self) {
        self.seq = self.seq.saturating_sub(1);
    }

    /// The final report of a previous epoch (`seq` + 1, never persisted
    /// again: the epoch is closed).
    pub fn final_report(
        mut self,
        node: &str,
        at: String,
        applied_revision: u64,
        geoip_db: &str,
    ) -> UsageReport {
        self.seq = self.seq.saturating_add(1);
        self.report(node, at, applied_revision, geoip_db)
    }

    /// The report for the current totals and `seq`.
    pub fn report(
        &self,
        node: &str,
        at: String,
        applied_revision: u64,
        geoip_db: &str,
    ) -> UsageReport {
        UsageReport {
            node: node.to_string(),
            counter_epoch: self.epoch.clone(),
            seq: self.seq,
            at,
            applied_revision,
            geoip_db: geoip_db.to_string(),
            zones: self.zones.clone(),
            unattributed: self.unattributed,
        }
    }
}

fn add(c: &mut CounterSet, r: &RequestRecord) {
    let inc = |v: &mut u64, by: u64| *v = v.saturating_add(by);
    if r.billable {
        inc(&mut c.billable_bytes_out, r.bytes_out);
        inc(&mut c.billable_requests, 1);
    } else {
        inc(&mut c.rejected_bytes_out, r.bytes_out);
        inc(&mut c.rejected_requests, 1);
    }
    match r.cache {
        Some(
            CacheStatus::Hit
            | CacheStatus::Stale
            | CacheStatus::Updating
            | CacheStatus::Revalidated,
        ) => inc(&mut c.hits, 1),
        Some(CacheStatus::Miss | CacheStatus::Expired) => inc(&mut c.misses, 1),
        Some(CacheStatus::Bypass) | None => {}
    }
    inc(&mut c.bytes_from_origin, r.bytes_from_origin);
    inc(&mut c.bytes_from_shield, r.bytes_from_shield);
    match r.status {
        200..=299 => inc(&mut c.status_2xx, 1),
        300..=399 => inc(&mut c.status_3xx, 1),
        400..=499 => inc(&mut c.status_4xx, 1),
        500..=599 => inc(&mut c.status_5xx, 1),
        _ => {}
    }
}

/// Zone ids of the applied feed, shared between the feed worker (writer)
/// and the receiver.
pub type KnownZones = Arc<RwLock<BTreeSet<String>>>;

/// Bind the metering socket, replacing a stale one. Mode 0660: the
/// OpenResty user writes through the shared group the image sets up.
///
/// The socket's directory must belong to the agent alone (no group or
/// other write), so nobody else can swap the path between `bind` and
/// `chmod`. It is therefore not OpenResty's control-socket directory.
/// `agent_uid` is the agent's own uid (the owner of a directory it
/// created), since a 0755 directory owned by another user would let that
/// user swap the path.
pub fn bind_meter_socket(path: &Path, agent_uid: u32) -> Result<UnixDatagram> {
    let dir = path.parent().ok_or(CdnError::Counters("socket-dir"))?;
    let meta = std::fs::symlink_metadata(dir).map_err(|_| CdnError::Counters("socket-dir"))?;
    if !meta.is_dir() || meta.mode() & 0o022 != 0 || meta.uid() != agent_uid {
        return Err(CdnError::Counters("socket-dir-writable-by-others"));
    }
    match std::fs::remove_file(path) {
        Ok(()) => {}
        Err(e) if e.kind() == ErrorKind::NotFound => {}
        Err(_) => return Err(CdnError::Counters("socket-unlink")),
    }
    let sock = UnixDatagram::bind(path).map_err(|_| CdnError::Counters("socket-bind"))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660))
        .map_err(|_| CdnError::Counters("socket-chmod"))?;
    sock.set_read_timeout(Some(Duration::from_secs(1)))
        .map_err(|_| CdnError::Counters("socket-timeout"))?;
    Ok(sock)
}

/// Receive records until `shutdown`. Bad datagrams are counted and
/// dropped; their content is never logged.
pub fn run_receiver(
    sock: &UnixDatagram,
    counters: &Arc<Mutex<Counters>>,
    known_zones: &KnownZones,
    sink: Option<&dyn RecordSink>,
    shutdown: &dyn ShutdownWatch,
) -> Result<u64> {
    let mut buf = [0u8; MAX_DATAGRAM + 1];
    let mut rejected: u64 = 0;
    while !shutdown.is_pending() {
        let n = match sock.recv(&mut buf) {
            Ok(n) => n,
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => continue,
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(_) => return Err(CdnError::Counters("socket-recv")),
        };
        let parsed = if n > MAX_DATAGRAM {
            Err(CdnError::Counters("record-too-large"))
        } else {
            RequestRecord::parse(&buf[..n])
        };
        match parsed {
            Ok(rec) => {
                let zone_known = match rec.zone.as_deref() {
                    Some(z) => known_zones
                        .read()
                        .map_err(|_| CdnError::Counters("lock-poisoned"))?
                        .contains(z),
                    None => false,
                };
                counters
                    .lock()
                    .map_err(|_| CdnError::Counters("lock-poisoned"))?
                    .record(&rec, zone_known);
                if let Some(s) = sink {
                    s.on_record(&rec);
                }
            }
            Err(e) => {
                rejected += 1;
                if rejected.is_power_of_two() {
                    eprintln!(
                        "hippius-cdn-agent: metering record rejected ({}), total {rejected}",
                        e.class()
                    );
                }
            }
        }
    }
    Ok(rejected)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn rec(zone: Option<&str>, billable: bool, bytes: u64, status: u16) -> RequestRecord {
        RequestRecord {
            zone: zone.map(str::to_string),
            client_region: "FR".into(),
            billable,
            bytes_out: bytes,
            cache: Some(CacheStatus::Hit),
            bytes_from_origin: 0,
            bytes_from_shield: 0,
            status,
        }
    }

    #[test]
    fn records_are_validated() {
        let ok = br#"{"zone":"z1","client_region":"FR","billable":true,"bytes_out":10,"status":200,"cache":"miss"}"#;
        assert_eq!(
            RequestRecord::parse(ok).unwrap().cache,
            Some(CacheStatus::Miss)
        );
        for (bad, want) in [
            (&br#"{"zone":"z1","client_region":"FR","billable":true,"bytes_out":1,"status":200,"x":1}"#[..], "record-decode"),
            (br#"{"zone":"z/1","client_region":"FR","billable":true,"bytes_out":1,"status":200}"#, "record-zone"),
            (br#"{"client_region":"fr","billable":true,"bytes_out":1,"status":200}"#, "record-region"),
            (br#"{"client_region":"EU1","billable":true,"bytes_out":1,"status":200}"#, "record-region"),
            (br#"{"client_region":"F1","billable":true,"bytes_out":1,"status":200}"#, "record-region"),
            (br#"{"client_region":"FR","billable":true,"bytes_out":1,"status":99}"#, "record-status"),
            (br#"{"client_region":"FR","billable":true,"bytes_out":-1,"status":200}"#, "record-decode"),
            (br#"{"zone":"z1","client_region":"FR","billable":true,"bytes_out":18446744073709551615,"status":200}"#, "record-bytes"),
            (br#"{"zone":"z1","client_region":"FR","billable":true,"bytes_out":1,"bytes_from_origin":17179869185,"status":200}"#, "record-bytes"),
        ] {
            assert_eq!(RequestRecord::parse(bad).unwrap_err().class(), want);
        }
    }

    #[test]
    fn classification_follows_the_billable_flag() {
        let mut c = Counters::fresh();
        c.record(&rec(Some("z1"), true, 100, 200), true);
        c.record(&rec(Some("z1"), false, 7, 429), true);
        c.record(&rec(None, false, 3, 421), false);
        // A zone the feed never applied is never billed to anyone.
        c.record(&rec(Some("ghost"), true, 1_000, 200), false);
        assert!(!c.zones.contains_key("ghost"));
        assert_eq!(c.unattributed.billable_bytes_out, 1_000);
        let z = c.zones["z1"]["FR"];
        assert_eq!((z.billable_bytes_out, z.billable_requests), (100, 1));
        assert_eq!((z.rejected_bytes_out, z.rejected_requests), (7, 1));
        assert_eq!((z.status_2xx, z.status_4xx, z.hits), (1, 1, 2));
        assert_eq!(c.unattributed.rejected_requests, 1);
    }

    #[test]
    fn a_new_start_closes_the_old_epoch_with_a_final_report() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("counters.json");

        let (mut c, prev) = Counters::start(&p).unwrap();
        assert_eq!(prev, Previous::None);
        c.record(&rec(Some("z1"), true, 100, 200), true);
        let r1 = c.checkpoint(&p, "n", "t1".into(), 1, "db").unwrap();
        assert_eq!(r1.seq, 1);
        c.record(&rec(Some("z1"), true, 50, 200), true);
        c.persist(&p).unwrap();
        let old_epoch = c.epoch().to_string();

        let (c2, prev) = Counters::start(&p).unwrap();
        assert_ne!(c2.epoch(), old_epoch);
        assert_eq!(c2.seq(), 0);
        let Previous::Final(old) = prev else {
            panic!("expected final")
        };
        let fin = old.final_report("n", "t2".into(), 1, "db");
        assert_eq!(fin.counter_epoch, old_epoch);
        assert_eq!(fin.seq, 2, "above every sent seq");
        assert_eq!(
            fin.zones["z1"]["FR"].billable_bytes_out, 150,
            "nothing lost"
        );
    }

    #[test]
    fn a_corrupt_file_is_a_fresh_epoch_without_a_final_report() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("counters.json");
        std::fs::write(&p, b"{\"format\":1,\"epoch\":\"short\"").unwrap();
        assert_eq!(Counters::start(&p).unwrap().1, Previous::Corrupt);
        std::fs::write(
            &p,
            br#"{"format":1,"epoch":"zz","seq":1,"zones":{},"unattributed":{"billable_bytes_out":0,"billable_requests":0,"rejected_bytes_out":0,"rejected_requests":0,"hits":0,"misses":0,"bytes_from_origin":0,"bytes_from_shield":0,"status_2xx":0,"status_3xx":0,"status_4xx":0,"status_5xx":0}}"#,
        )
        .unwrap();
        assert_eq!(Counters::start(&p).unwrap().1, Previous::Corrupt);
    }

    #[test]
    fn checkpoint_rolls_back_seq_when_the_persist_fails() {
        let mut c = Counters::fresh();
        let bad = Path::new("/nonexistent-dir/counters.json");
        assert!(c.checkpoint(bad, "n", "t".into(), 0, "db").is_err());
        assert_eq!(c.seq(), 0);
    }

    #[test]
    fn totals_saturate_and_keys_are_bounded() {
        let mut c = Counters::fresh();
        c.record(&rec(Some("z1"), true, u64::MAX, 200), true);
        c.record(&rec(Some("z1"), true, 5, 200), true);
        assert_eq!(c.zones["z1"]["FR"].billable_bytes_out, u64::MAX);

        c.keys = MAX_KEYS;
        c.record(&rec(Some("z2"), true, 9, 200), true);
        assert!(!c.zones.contains_key("z2"));
        assert_eq!(c.unattributed.billable_bytes_out, 9);
        // An existing key still counts at the cap.
        c.record(&rec(Some("z1"), false, 1, 403), true);
        assert_eq!(c.zones["z1"]["FR"].rejected_requests, 1);
    }

    #[test]
    fn receiver_counts_datagrams() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let p = dir.path().join("meter.sock");
        let uid = std::fs::metadata(dir.path()).unwrap().uid();
        let sock = bind_meter_socket(&p, uid).unwrap();
        let counters = Arc::new(Mutex::new(Counters::fresh()));
        let known: KnownZones = Arc::new(RwLock::new(BTreeSet::from(["z1".to_string()])));
        let stop = crate::shutdown::Shutdown::new_for_tests();

        let tx = UnixDatagram::unbound().unwrap();
        tx.send_to(
            br#"{"zone":"z1","client_region":"FR","billable":true,"bytes_out":10,"status":200}"#,
            &p,
        )
        .unwrap();
        tx.send_to(
            br#"{"zone":"zz","client_region":"FR","billable":true,"bytes_out":7,"status":200}"#,
            &p,
        )
        .unwrap();
        tx.send_to(b"garbage", &p).unwrap();
        tx.send_to(&[b' '; MAX_DATAGRAM + 1], &p).unwrap();

        let c2 = Arc::clone(&counters);
        let s2 = stop.clone();
        let k2 = Arc::clone(&known);
        let h = std::thread::spawn(move || run_receiver(&sock, &c2, &k2, None, &s2).unwrap());
        for _ in 0..50 {
            if counters.lock().unwrap().zones.contains_key("z1") {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        std::thread::sleep(Duration::from_millis(100));
        stop.trigger();
        assert_eq!(h.join().unwrap(), 2);
        let c = counters.lock().unwrap();
        assert_eq!(c.zones["z1"]["FR"].billable_bytes_out, 10);
        assert!(!c.zones.contains_key("zz"));
        assert_eq!(c.unattributed.billable_bytes_out, 7);
    }

    #[test]
    fn meter_socket_refuses_a_shared_directory() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o777)).unwrap();
        assert_eq!(
            bind_meter_socket(
                &dir.path().join("m.sock"),
                std::fs::metadata(dir.path()).unwrap().uid()
            )
            .unwrap_err()
            .class(),
            "socket-dir-writable-by-others"
        );
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        let other = std::fs::metadata(dir.path()).unwrap().uid().wrapping_add(1);
        assert_eq!(
            bind_meter_socket(&dir.path().join("m.sock"), other)
                .unwrap_err()
                .class(),
            "socket-dir-writable-by-others"
        );
    }

    #[test]
    fn an_absurd_persisted_seq_is_corrupt() {
        let mut c = Counters::fresh();
        c.seq = MAX_SEQ + 1;
        let bytes = serde_json::to_vec(&c).unwrap();
        assert!(Counters::decode(&bytes).is_none());
    }
}
