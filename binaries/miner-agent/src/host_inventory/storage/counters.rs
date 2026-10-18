//! The storage collector's memory across runs, next to its output
//! (`<out-dir>/.storage-counters.json`): each subject's SMART counters (a
//! "rising" signal compares with the previous run) and when each
//! advisory was first seen. The collector is otherwise stateless; on
//! `/run` the file goes with a reboot, and a run without it (the first)
//! raises nothing "rising" and dates every advisory from now.

use std::collections::BTreeMap;
use std::path::Path;

use hippius_host_inventory::Advisory;
use serde::{Deserialize, Serialize};

/// The state file is at most this many bytes (a few hundred subjects).
pub const MAX_COUNTERS_BYTES: usize = 64 * 1024;

/// `<out-dir>/<COUNTERS_NAME>.json`.
pub const COUNTERS_NAME: &str = ".storage-counters";

/// One subject's counters by name (`reallocated`, `udma_crc`,
/// `media_errors`).
pub type CounterMap = BTreeMap<String, u64>;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Counters {
    /// By subject counter key (a by-id name, `kernel:<name>`, a
    /// controller subject).
    #[serde(default)]
    pub devices: BTreeMap<String, CounterMap>,
    /// By advisory key ([`advisory_key`]): its `first_seen_unix`.
    #[serde(default)]
    pub first_seen: BTreeMap<String, i64>,
}

/// An advisory's identity across runs: its list key.
pub fn advisory_key(a: &Advisory) -> String {
    let (kind, subject, code) = a.key();
    format!("{kind}/{code}/{subject}")
}

impl Counters {
    /// The previous run's state in `dir`. Missing or unreadable is a
    /// first run (the state only ever adds "rising" and older
    /// `first_seen`s; losing it is never unsafe).
    /// Past [`MAX_COUNTERS_BYTES`] it is not read.
    pub fn load(dir: &Path) -> Self {
        use std::io::Read;
        let Ok(file) = std::fs::File::open(dir.join(format!("{COUNTERS_NAME}.json"))) else {
            return Self::default();
        };
        let mut bytes = Vec::new();
        let cap = u64::try_from(MAX_COUNTERS_BYTES).unwrap_or(u64::MAX);
        if file.take(cap + 1).read_to_end(&mut bytes).is_err() || bytes.len() > MAX_COUNTERS_BYTES {
            return Self::default();
        }
        serde_json::from_slice(&bytes).unwrap_or_default()
    }

    /// Write it to `dir` atomically.
    /// Within [`MAX_COUNTERS_BYTES`] (what [`Self::load`] reads): past
    /// it, the last `first_seen` entries, then the last subjects' counters
    /// are left out (those advisories date from their next run).
    pub fn save(&self, dir: &Path) -> std::io::Result<()> {
        let mut kept = self.clone();
        let mut bytes = serde_json::to_vec(&kept).map_err(std::io::Error::other)?;
        while bytes.len() > MAX_COUNTERS_BYTES {
            // Drop about the excess at once (an entry is at least its key
            // plus a few bytes of framing), then measure again.
            let mut excess = bytes.len() - MAX_COUNTERS_BYTES;
            while excess > 0 {
                let freed = if let Some((k, _)) = kept.first_seen.pop_last() {
                    k.len() + 8
                } else if let Some((k, c)) = kept.devices.pop_last() {
                    k.len() + 8 + c.keys().map(|n| n.len() + 8).sum::<usize>()
                } else {
                    break;
                };
                excess = excess.saturating_sub(freed);
            }
            bytes = serde_json::to_vec(&kept).map_err(std::io::Error::other)?;
        }
        super::super::save_json(dir, COUNTERS_NAME, &bytes)
    }

    /// Date `advisories` from `previous` (`first_seen` kept while the
    /// advisory stays raised, `last_seen` = `now`), and record them here.
    /// An advisory not raised this run is forgotten: raised again, it is
    /// new.
    pub fn stamp(&mut self, advisories: &mut [Advisory], previous: &Counters, now_unix: i64) {
        for a in advisories {
            let key = advisory_key(a);
            let first = previous
                .first_seen
                .get(&key)
                .copied()
                .filter(|t| *t <= now_unix)
                .unwrap_or(now_unix);
            a.first_seen_unix = first;
            a.last_seen_unix = now_unix;
            self.first_seen.insert(key, first);
        }
    }
}
