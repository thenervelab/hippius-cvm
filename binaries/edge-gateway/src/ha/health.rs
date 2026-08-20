//! HA peer liveness tracking (PR-H5, §5 HA pair).
//!
//! ## What this is — and what it deliberately is NOT
//!
//! PR-H5 runs the Edge as an **active/active** pair: two instances
//! serve miner traffic in parallel, picked by NetBird DNS round-robin.
//! There is **no leader election, no Raft, no promotion** — the relay
//! is stateless by the PR-H1 invariant, so two instances never need to
//! agree on anything. The peer link exists purely so each instance can
//! *observe* the other.
//!
//! [`HealthMonitor`] is that observer. It tracks one fact — "when did
//! the last health beat arrive from the peer" — and derives a
//! [`PeerState`] from it. When the peer goes silent past the down
//! threshold the watchdog logs it and bumps a metric. That is the
//! entire reaction. The local instance does not change a single byte
//! of its own behaviour: it keeps serving miner traffic exactly as
//! before, peer up or down. Robustness comes from *symmetry* — both
//! instances run identical code — not from one taking over for the
//! other.
//!
//! This is enforced structurally: `HealthMonitor` exposes no method
//! that returns or sets a leadership role. A compile-fail doc-test on
//! the type pins that there is no `promote` / `become_leader` surface.
//!
//! ## Down detection
//!
//! - Before the first beat ever arrives the reference clock is the
//!   monitor's construction instant — so a peer that never comes up is
//!   reported [`PeerState::Down`] just like one that came up and then
//!   vanished. Both are observable; neither triggers promotion.
//! - The `edge_ha_peer_down_total` counter increments **once per
//!   transition into `Down`**, not once per watchdog tick — a peer
//!   that stays down does not inflate the counter.

use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Observed state of the sister Edge instance, derived from the
/// health-beat stream. Pure observation — no variant implies the
/// local instance should behave differently (see the module docs:
/// active/active, no promotion).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerState {
    /// No beat has been observed yet — the peer link has not
    /// completed a first exchange this process lifetime.
    Unknown,
    /// A beat arrived within the down threshold. The peer is live.
    Up,
    /// No beat for longer than the down threshold (or the peer never
    /// came up). Observation only — the local instance does NOT
    /// promote, does NOT change behaviour, does NOT exit.
    Down,
}

impl PeerState {
    /// Stable static classifier for structured logs. Same
    /// `&'static str`-only discipline as `EdgeError::class`.
    pub fn as_class_str(self) -> &'static str {
        match self {
            PeerState::Unknown => "unknown",
            PeerState::Up => "up",
            PeerState::Down => "down",
        }
    }
}

/// Tracks the liveness of the HA peer from its health-beat stream.
///
/// `HealthMonitor` holds NO shared state with the peer and NO
/// reference to the local relay pipeline — it is a pure observer.
/// Cloning is via `Arc` at the call site (the listener feeds beats in,
/// the watchdog polls); the type itself is intentionally not `Clone`.
///
/// There is deliberately no promotion path — this does not compile:
///
/// ```compile_fail
/// # use hippius_edge_gateway::ha::HealthMonitor;
/// # use std::time::Duration;
/// let monitor = HealthMonitor::new(Duration::from_secs(30));
/// // PR-H5 is active/active: no leader election, no takeover.
/// monitor.become_leader();
/// ```
pub struct HealthMonitor {
    inner: Mutex<MonitorState>,
    /// Silence past this horizon flips the peer to [`PeerState::Down`].
    down_threshold: Duration,
}

#[derive(Debug)]
struct MonitorState {
    /// Most recent beat arrival, or `None` until the first beat.
    last_beat: Option<Instant>,
    /// Monitor construction instant — the down-detection reference
    /// before any beat has been seen.
    started: Instant,
    /// Last computed [`PeerState`]. Held so the watchdog and the
    /// beat reader can detect *transitions* (and so the metric
    /// increments once per down edge, not once per poll).
    state: PeerState,
}

impl HealthMonitor {
    /// Build a monitor that flips the peer to [`PeerState::Down`]
    /// after `down_threshold` of silence. Production uses
    /// [`crate::ha::PEER_DOWN_THRESHOLD`] (30 s); tests pass a short
    /// duration for determinism.
    pub fn new(down_threshold: Duration) -> Self {
        Self {
            inner: Mutex::new(MonitorState {
                last_beat: None,
                started: Instant::now(),
                state: PeerState::Unknown,
            }),
            down_threshold,
        }
    }

    /// Record that a health beat just arrived from the peer. Returns
    /// `true` iff this beat transitioned the peer **into**
    /// [`PeerState::Up`] (i.e. a recovery or first contact) — the
    /// caller logs the recovery + sets the `peer_up` gauge on a
    /// `true` return.
    pub fn record_beat(&self) -> bool {
        self.record_beat_at(Instant::now())
    }

    fn record_beat_at(&self, now: Instant) -> bool {
        // Poison-deny, same posture as `PerSourceRateLimiter`: a
        // poisoned lock means a prior holder panicked mid-update —
        // skip the update rather than risk a corrupted view.
        let Ok(mut st) = self.inner.lock() else {
            return false;
        };
        st.last_beat = Some(now);
        if st.state != PeerState::Up {
            st.state = PeerState::Up;
            true
        } else {
            false
        }
    }

    /// Re-evaluate the peer state against the wall clock. Returns
    /// `true` iff this call transitioned the peer **into**
    /// [`PeerState::Down`] — the watchdog increments
    /// `edge_ha_peer_down_total` exactly on a `true` return, so a
    /// peer that stays down does not inflate the counter.
    ///
    /// This NEVER does anything but update its own observed view: no
    /// promotion, no pipeline change, no process exit.
    pub fn poll(&self) -> bool {
        self.poll_at(Instant::now())
    }

    fn poll_at(&self, now: Instant) -> bool {
        let Ok(mut st) = self.inner.lock() else {
            return false;
        };
        // Before the first beat, measure silence from construction —
        // a peer that never came up is `Down`, not forever `Unknown`.
        let reference = st.last_beat.unwrap_or(st.started);
        let silent = now.saturating_duration_since(reference);
        if silent > self.down_threshold && st.state != PeerState::Down {
            st.state = PeerState::Down;
            true
        } else {
            false
        }
    }

    /// Current observed [`PeerState`]. A lock-free-ish hint — callers
    /// (tests, the /metrics renderer) must not build correctness on
    /// its exact timing.
    pub fn peer_state(&self) -> PeerState {
        self.inner
            .lock()
            .map(|s| s.state)
            .unwrap_or(PeerState::Unknown)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn starts_unknown_before_any_beat() {
        let m = HealthMonitor::new(Duration::from_secs(30));
        assert_eq!(m.peer_state(), PeerState::Unknown);
    }

    #[test]
    fn first_beat_transitions_to_up() {
        let m = HealthMonitor::new(Duration::from_secs(30));
        let t0 = Instant::now();
        // First beat returns `true` (transition Unknown → Up).
        assert!(m.record_beat_at(t0));
        assert_eq!(m.peer_state(), PeerState::Up);
        // A second beat while already Up returns `false`.
        assert!(!m.record_beat_at(t0 + Duration::from_secs(1)));
        assert_eq!(m.peer_state(), PeerState::Up);
    }

    #[test]
    fn poll_flips_to_down_after_threshold_of_silence() {
        let m = HealthMonitor::new(Duration::from_secs(30));
        let t0 = Instant::now();
        assert!(m.record_beat_at(t0));
        // Still within threshold → no transition.
        assert!(!m.poll_at(t0 + Duration::from_secs(20)));
        assert_eq!(m.peer_state(), PeerState::Up);
        // Past threshold → transition to Down, returns `true` once.
        assert!(m.poll_at(t0 + Duration::from_secs(31)));
        assert_eq!(m.peer_state(), PeerState::Down);
    }

    #[test]
    fn down_transition_fires_exactly_once() {
        // `edge_ha_peer_down_total` must increment once per down edge,
        // not once per watchdog tick.
        let m = HealthMonitor::new(Duration::from_secs(30));
        let t0 = Instant::now();
        assert!(m.record_beat_at(t0));
        assert!(m.poll_at(t0 + Duration::from_secs(31)));
        // Subsequent polls while still down → no further transitions.
        assert!(!m.poll_at(t0 + Duration::from_secs(40)));
        assert!(!m.poll_at(t0 + Duration::from_secs(999)));
    }

    #[test]
    fn peer_that_never_comes_up_is_reported_down() {
        // A peer that never sends a beat must still become `Down`
        // (measured from construction) — not stay `Unknown` forever.
        let m = HealthMonitor::new(Duration::from_secs(30));
        let started = {
            let st = m.inner.lock().unwrap();
            st.started
        };
        assert!(m.poll_at(started + Duration::from_secs(31)));
        assert_eq!(m.peer_state(), PeerState::Down);
    }

    #[test]
    fn beat_after_down_recovers_to_up() {
        let m = HealthMonitor::new(Duration::from_secs(30));
        let t0 = Instant::now();
        assert!(m.record_beat_at(t0));
        assert!(m.poll_at(t0 + Duration::from_secs(31)));
        assert_eq!(m.peer_state(), PeerState::Down);
        // A fresh beat recovers — returns `true` (transition → Up).
        assert!(m.record_beat_at(t0 + Duration::from_secs(35)));
        assert_eq!(m.peer_state(), PeerState::Up);
    }

    #[test]
    fn peer_state_class_strings_are_stable() {
        assert_eq!(PeerState::Unknown.as_class_str(), "unknown");
        assert_eq!(PeerState::Up.as_class_str(), "up");
        assert_eq!(PeerState::Down.as_class_str(), "down");
    }
}
