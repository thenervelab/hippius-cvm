//! Which report a tick sends, if any (§18.10.1 cadence). Pure: the time
//! and the state are inputs, so the cadence is tested without a clock.
//!
//! - `full`: once a full set of sections exists, at agent start and then
//!   every `full_interval` ± `full_jitter`, with every section present.
//! - `counters`: every `counters_interval`, with the counter sections
//!   present (memory, storage, sensors, software).
//! - `change`: a section whose digest differs from the one vali last
//!   accepted, alone with the others that changed.
//! - Never two reports within `min_gap` of each other (the change
//!   debounce, and vali's per-hour budget).
//!
//! **The full slot.** The crate refuses a `full` report missing any of
//! the eight sections. The collector writes all eight (sensors since
//! HW5b), so the slot is a real `full`; when an older collector (or a
//! section skipped as malformed) leaves one out, the slot is sent as a
//! `change` report carrying every section present — the honest kind:
//! vali merges a section as a whole whatever the kind, a section absent
//! is "unchanged", and a report never claims a completeness it does not
//! have. The slot fires once [`FULL_SET`] exists.

use std::collections::{BTreeMap, BTreeSet};

use hippius_host_inventory::ReportKind;

/// Every section the wire format knows, in its order.
pub const SECTIONS: [&str; 8] = [
    "system", "cpu", "memory", "storage", "network", "pci", "sensors", "software",
];

/// What fires the full slot: every section but `sensors`, which a
/// collector may lack (no hwmon, an older collector); with it too the
/// slot is a real `full`.
pub const FULL_SET: [&str; 7] = [
    "system", "cpu", "memory", "storage", "network", "pci", "software",
];

/// The sections a `counters` report refreshes.
pub const COUNTER_SECTIONS: [&str; 4] = ["memory", "storage", "sensors", "software"];

/// The cadence, seconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cadence {
    pub full_interval: i64,
    pub full_jitter: i64,
    pub counters_interval: i64,
    pub min_gap: i64,
}

/// Which cadence slot a report fills.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Slot {
    Full,
    Counters,
    Change,
}

/// One report to send.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    pub slot: Slot,
    /// The wire kind: `full` only when all eight sections exist (see the
    /// module doc), else `change` for the full slot.
    pub kind: ReportKind,
    pub sections: BTreeSet<&'static str>,
}

/// What the planner reads of the poster's state.
#[derive(Debug, Clone, Default)]
pub struct Clocks<'a> {
    pub sent_digests: Option<&'a BTreeMap<String, String>>,
    pub next_full_unix: Option<i64>,
    pub last_counters_unix: Option<i64>,
    pub last_sent_unix: Option<i64>,
    /// No `full` accepted since the agent started (and none accepted
    /// recently enough to skip the startup one).
    pub full_pending_since_start: bool,
}

/// The report due at `now`, given the sections present and their
/// digests (`present`).
pub fn plan(
    now: i64,
    present: &BTreeMap<&'static str, String>,
    clocks: &Clocks<'_>,
    cadence: &Cadence,
) -> Option<Plan> {
    if clocks
        .last_sent_unix
        .is_some_and(|t| now.saturating_sub(t) < cadence.min_gap)
    {
        return None;
    }
    let full_set = FULL_SET.iter().all(|s| present.contains_key(s));
    let full_due =
        clocks.full_pending_since_start || clocks.next_full_unix.is_none_or(|t| now >= t);
    if full_set && full_due {
        let all = SECTIONS.iter().all(|s| present.contains_key(s));
        return Some(Plan {
            slot: Slot::Full,
            kind: if all {
                ReportKind::Full
            } else {
                ReportKind::Change
            },
            sections: present.keys().copied().collect(),
        });
    }
    let counters_due = clocks
        .last_counters_unix
        .is_none_or(|t| now.saturating_sub(t) >= cadence.counters_interval);
    let counters: BTreeSet<&'static str> = COUNTER_SECTIONS
        .iter()
        .copied()
        .filter(|s| present.contains_key(s))
        .collect();
    if counters_due && !counters.is_empty() {
        return Some(Plan {
            slot: Slot::Counters,
            kind: ReportKind::Counters,
            sections: counters,
        });
    }
    let changed: BTreeSet<&'static str> = present
        .iter()
        .filter(|(name, digest)| {
            clocks
                .sent_digests
                .and_then(|d| d.get(**name))
                .is_none_or(|sent| sent != *digest)
        })
        .map(|(name, _)| *name)
        .collect();
    (!changed.is_empty()).then_some(Plan {
        slot: Slot::Change,
        kind: ReportKind::Change,
        sections: changed,
    })
}

/// When the full after one at `now` is due: `full_interval` plus a jitter
/// in `[-full_jitter, +full_jitter]`, drawn uniformly from `jitter_draw`
/// (any random `u64`).
pub fn next_full(now: i64, cadence: &Cadence, jitter_draw: u64) -> i64 {
    let span = u64::try_from(cadence.full_jitter.max(0))
        .unwrap_or(0)
        .saturating_mul(2)
        .saturating_add(1);
    let offset = i64::try_from(jitter_draw % span).unwrap_or(0) - cadence.full_jitter.max(0);
    now.saturating_add(cadence.full_interval)
        .saturating_add(offset)
}
