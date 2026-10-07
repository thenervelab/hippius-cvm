//! Readiness bits for `/__hippius/health` (spec §7.3).
//!
//! The agent computes every bit it can know and pushes them to
//! OpenResty; the health location returns 200 only when the agent says
//! `ready` **and** its own canary object is served from the cache, a
//! check that belongs to the data plane.
//!
//! The feed rule distinguishes two failures:
//! - the backend is reachable and serving revision R, and the node has
//!   failed to apply R for longer than `feed_stale_after_s` (5 min):
//!   **not ready**;
//! - the backend is unreachable: the node keeps serving its last-known-
//!   good config and stays ready for up to `lkg_max_age_s` (24 h) after
//!   it last knew it was current. A control-plane outage must not take
//!   the fleet down.

use std::os::unix::fs::MetadataExt;
use std::path::Path;

use serde::Serialize;

use crate::config::TimingConfig;

/// What the other agent loops have observed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Observed {
    /// The revision OpenResty holds (0 = nothing yet).
    pub applied_revision: u64,
    /// Last time the node knew it was current: a revision applied, a
    /// `304`, a stale delta, or (at boot) the LKG's save time.
    pub confirmed_at: u64,
    /// Since when the backend has served a revision the node could not
    /// apply.
    pub pending_since: Option<u64>,
    /// The certificate store loaded and holds the fleet wildcard.
    pub cert_store_loaded: bool,
    /// The node holds the active fleet key version (and its public half
    /// matches the backend's, when the backend sends it).
    pub fleet_key_ok: bool,
    pub draining: bool,
    pub quota_guard: bool,
    /// OpenResty asked for a full re-push (409 on a control push).
    pub resync_needed: bool,
}

/// The health document pushed to OpenResty.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Health {
    pub ready: bool,
    pub volume_mounted: bool,
    pub fleet_key: bool,
    pub cert_store: bool,
    pub not_draining: bool,
    pub quota_ok: bool,
    pub feed_fresh: bool,
    pub applied_revision: u64,
    pub at: u64,
}

/// Evaluate the bits at `now`.
pub fn evaluate(o: &Observed, volume_mounted: bool, now: u64, t: &TimingConfig) -> Health {
    let not_stuck = o
        .pending_since
        .is_none_or(|since| now.saturating_sub(since) <= t.feed_stale_after_s);
    let recent = o.confirmed_at != 0 && now.saturating_sub(o.confirmed_at) <= t.lkg_max_age_s;
    let feed_fresh = o.applied_revision > 0 && not_stuck && recent;
    let h = Health {
        ready: false,
        volume_mounted,
        fleet_key: o.fleet_key_ok,
        cert_store: o.cert_store_loaded,
        not_draining: !o.draining,
        quota_ok: !o.quota_guard,
        feed_fresh,
        applied_revision: o.applied_revision,
        at: now,
    };
    Health {
        ready: h.volume_mounted
            && h.fleet_key
            && h.cert_store
            && h.not_draining
            && h.quota_ok
            && h.feed_fresh,
        ..h
    }
}

/// Whether `mount` is a mount point: it exists, and its device differs
/// from its parent's (systemd's `ConditionPathIsMountPoint` guards the
/// start; this catches a volume that disappears later).
pub fn volume_mounted(mount: &Path) -> bool {
    let Some(parent) = mount.parent() else {
        return false;
    };
    match (std::fs::metadata(mount), std::fs::metadata(parent)) {
        (Ok(m), Ok(p)) => m.is_dir() && m.dev() != p.dev(),
        _ => false,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn timing() -> TimingConfig {
        TimingConfig {
            usage_interval_s: 60,
            persist_interval_s: 10,
            health_interval_s: 5,
            feed_stale_after_s: 300,
            lkg_max_age_s: 86_400,
            resync_interval_s: 300,
        }
    }

    fn good() -> Observed {
        Observed {
            applied_revision: 9,
            confirmed_at: 1_000,
            pending_since: None,
            cert_store_loaded: true,
            fleet_key_ok: true,
            draining: false,
            quota_guard: false,
            resync_needed: false,
        }
    }

    #[test]
    fn health_table() {
        let t = timing();
        type Case = (&'static str, fn(&mut Observed), bool, u64, bool);
        let cases: &[Case] = &[
            ("all good", |_| {}, true, 1_010, true),
            ("volume gone", |_| {}, false, 1_010, false),
            (
                "no fleet key",
                |o| o.fleet_key_ok = false,
                true,
                1_010,
                false,
            ),
            (
                "no certs",
                |o| o.cert_store_loaded = false,
                true,
                1_010,
                false,
            ),
            ("draining", |o| o.draining = true, true, 1_010, false),
            ("quota guard", |o| o.quota_guard = true, true, 1_010, false),
            (
                "nothing applied",
                |o| o.applied_revision = 0,
                true,
                1_010,
                false,
            ),
            (
                "stuck 299 s",
                |o| o.pending_since = Some(1_000),
                true,
                1_299,
                true,
            ),
            (
                "stuck 301 s",
                |o| o.pending_since = Some(1_000),
                true,
                1_301,
                false,
            ),
            ("backend down 23 h", |_| {}, true, 1_000 + 23 * 3_600, true),
            ("backend down 25 h", |_| {}, true, 1_000 + 25 * 3_600, false),
            (
                "never confirmed",
                |o| o.confirmed_at = 0,
                true,
                1_010,
                false,
            ),
        ];
        for (name, mutate, vol, now, want) in cases {
            let mut o = good();
            mutate(&mut o);
            let h = evaluate(&o, *vol, *now, &t);
            assert_eq!(h.ready, *want, "{name}: {h:?}");
        }
    }

    #[test]
    fn mount_detection() {
        assert!(volume_mounted(Path::new("/proc")));
        let dir = tempfile::tempdir().unwrap();
        assert!(!volume_mounted(dir.path()));
        assert!(!volume_mounted(&dir.path().join("absent")));
        assert!(!volume_mounted(Path::new("/")));
    }
}
