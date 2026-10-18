//! The §18.10 host-inventory poster (HW6): read the collector's sections,
//! sign them with the node identity, post them to the Edge.
//!
//! A task of `serve`, spawned only when `[inventory] enabled`. Every
//! `poll_secs` it reads `<dir>/<section>.json` (off the runtime, one read
//! in flight, bounded), plans the report due ([`plan`]), builds it
//! (`normalize` then `canonical_fitted`: the storage inventory is trimmed
//! to the body cap), signs it with the SAME Ed25519 identity as the
//! heartbeats and graceful exit (domain `HIPPIUS_MINER_HOST_INVENTORY_V1`
//! is in the body), and POSTs the `SignedHostInventory` to
//! `/v1/edge/host-inventory` (mTLS, `application/cbor`).
//!
//! The sequence is drawn, the send stamped (`last_sent_unix`, for the
//! min gap) and the state persisted BEFORE the send: a lost response, a
//! cancel or a crash never reuses a sequence nor undercuts the gap. The
//! sequence's clock floor ([`InventoryState::next_sequence`]) is the
//! replay protection. The digests advance only on a 2xx.
//!
//! **What the agent sees of a reply.** The Edge relays vali's 2xx with
//! its body; EVERY non-2xx from vali (its 403, 404 when the ingest is
//! off, 409 replay, 429 budget, 5xx) reaches the agent as a bare `502`,
//! and only the Edge's own `400` (wire gate), `413` (body cap) and `429`
//! (per-peer limiter) come through as themselves. So the poster has two
//! reply paths besides success ([`Poster::on_reply`]):
//! - `429`: the Edge's limiter — its `Retry-After` if present, else
//!   15 min;
//! - anything else (`502`, `400`, `413`, an unexpected status): a growing
//!   back-off, 15 min → 30 min → 1 h → 2 h → 6 h (cap), reset by a 2xx.
//!   With vali's flag off this settles at one attempt per 6 h.
//!
//! Transport errors back off exponentially (60 s → 1 h), never under the
//! min gap. Relaying vali's status and body for this route is an Edge
//! follow-up; until then the category branches it would enable do not
//! exist here.
//!
//! Logging: section names, sizes, the sequence and the status, never a
//! body nor a field of one; a repeated failure is logged once, then at
//! most every 6 h.

pub mod plan;
pub mod read;
pub mod state;

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use hippius_host_inventory::{
    HostInventory, ReportKind, SignedHostInventory, DOMAIN, MAX_ENVELOPE_BYTES, SCHEMA_VERSION,
};
use tokio_util::sync::CancellationToken;

use crate::config::Config;
use crate::edge_client::{EdgeClient, EdgeReply, EnvelopeKind};
use crate::identity::MinerIdentity;

use plan::{Cadence, Clocks, Plan, Slot};
use read::ReadOutcome;
use state::InventoryState;

/// How long one read of the collector's directory may take before the
/// tick gives up on it (the read finishes, or not, on its own thread).
pub const READ_TIMEOUT: Duration = Duration::from_secs(20);

/// The Edge's `429` without a `Retry-After`.
pub const RATE_LIMITED_DEFAULT_SECS: i64 = 15 * 60;
/// A `Retry-After` is honoured within these bounds.
const RETRY_AFTER_BOUNDS: (i64, i64) = (60, 3600);
/// Every other non-2xx: these waits, one step per consecutive refusal,
/// the last one repeated.
pub const REFUSED_BACKOFF_SECS: [i64; 5] = [15 * 60, 30 * 60, 3600, 2 * 3600, 6 * 3600];
/// Transport errors: exponential from here, capped; never under the min
/// gap.
pub const TRANSPORT_BACKOFF_START_SECS: i64 = 60;
pub const TRANSPORT_BACKOFF_CAP_SECS: i64 = 3600;
/// A repeated failure is logged at most this often.
pub const QUIET_LOG_SECS: i64 = 6 * 3600;
/// A restart skips its startup `full` when the last accepted one is
/// younger than this (a crash-looping agent sends no full per restart).
pub const RESTART_FULL_SKIP_SECS: i64 = 6 * 3600;

/// Where the poster delivers. Production is the Edge client; tests
/// inject a mock.
#[async_trait]
pub trait InventoryClient: Send + Sync {
    /// POST one `SignedHostInventory`. `Err` = no reply (transport).
    async fn post(&self, envelope: &[u8]) -> Result<EdgeReply, ()>;
}

#[async_trait]
impl InventoryClient for EdgeClient {
    async fn post(&self, envelope: &[u8]) -> Result<EdgeReply, ()> {
        self.post_for_reply(EnvelopeKind::HostInventory, envelope)
            .await
            .map_err(|_| ())
    }
}

/// What the poster is configured with.
#[derive(Debug, Clone)]
pub struct PosterConfig {
    pub miner_id: String,
    pub dir: PathBuf,
    pub state_path: PathBuf,
    pub cadence: Cadence,
    pub poll: Duration,
}

impl PosterConfig {
    pub fn from_config(config: &Config) -> Self {
        let inv = &config.inventory;
        let secs = |s: u64| i64::try_from(s).unwrap_or(i64::MAX);
        Self {
            miner_id: config.miner.miner_id.clone(),
            dir: inv.dir.clone(),
            state_path: config.storage.state_disk_root.join(state::STATE_FILE),
            cadence: Cadence {
                full_interval: secs(inv.full_interval_secs),
                full_jitter: secs(inv.full_jitter_secs),
                counters_interval: secs(inv.counters_interval_secs),
                min_gap: secs(inv.min_gap_secs),
            },
            poll: Duration::from_secs(inv.poll_secs),
        }
    }
}

/// How a send ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Outcome {
    Accepted,
    /// The Edge's `429`.
    RateLimited,
    /// Any other non-2xx (`502` = vali refused or unavailable).
    Refused,
    Transport,
}

/// What one tick did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Tick {
    /// Nothing due (or backing off).
    Idle,
    Sent {
        slot: Slot,
        kind: ReportKind,
        sequence: u64,
        outcome: Outcome,
    },
    /// The report could not be built, signed or its sequence persisted.
    Failed(&'static str),
}

/// Running totals, reported on every status line.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Stats {
    pub sent: u64,
    pub accepted: u64,
    pub refused: u64,
    pub transport: u64,
    pub skipped_sections: u64,
    pub build_failed: u64,
    /// Status lines printed (a repeated failure is quieted).
    pub status_lines: u64,
}

/// The poster's state between ticks.
pub struct Poster {
    cfg: PosterConfig,
    identity: Arc<MinerIdentity>,
    client: Arc<dyn InventoryClient>,
    state: InventoryState,
    full_pending_since_start: bool,
    backoff_until: Option<i64>,
    transport_backoff: i64,
    /// Consecutive non-2xx refusals (the back-off step).
    refused_streak: usize,
    /// The last status line printed: `(outcome, status, when)`.
    last_logged: Option<(Outcome, u16, i64)>,
    last_skipped: std::collections::BTreeMap<&'static str, &'static str>,
    jitter: Box<dyn FnMut() -> u64 + Send + Sync>,
    pub stats: Stats,
}

fn log(line: &str) {
    eprintln!("hippius-miner-agent: inventory: {line}");
}

impl Poster {
    /// A poster resuming from its state file, read off the runtime. An
    /// unreadable state starts over: the digests are re-sent, and the
    /// sequence's clock floor keeps it above vali's.
    pub async fn open(
        cfg: PosterConfig,
        identity: Arc<MinerIdentity>,
        client: Arc<dyn InventoryClient>,
    ) -> Self {
        let path = cfg.state_path.clone();
        let loaded = tokio::task::spawn_blocking(move || InventoryState::load(&path)).await;
        let state = match loaded {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => {
                log(&format!(
                    "state {} ({}); starting over above the clock floor",
                    cfg.state_path.display(),
                    e.class()
                ));
                InventoryState::default()
            }
            Err(_) => {
                log("state read failed; starting over above the clock floor");
                InventoryState::default()
            }
        };
        Self::with_state(cfg, identity, client, state)
    }

    /// A poster on `state` (no I/O).
    pub fn with_state(
        cfg: PosterConfig,
        identity: Arc<MinerIdentity>,
        client: Arc<dyn InventoryClient>,
        state: InventoryState,
    ) -> Self {
        Self {
            cfg,
            identity,
            client,
            state,
            full_pending_since_start: true,
            backoff_until: None,
            transport_backoff: TRANSPORT_BACKOFF_START_SECS,
            refused_streak: 0,
            last_logged: None,
            last_skipped: Default::default(),
            jitter: Box::new(|| {
                use rand_core::{OsRng, RngCore};
                OsRng.next_u64()
            }),
            stats: Stats::default(),
        }
    }

    /// Replace the jitter source (tests).
    pub fn with_jitter(mut self, jitter: Box<dyn FnMut() -> u64 + Send + Sync>) -> Self {
        self.jitter = jitter;
        self
    }

    pub fn state(&self) -> &InventoryState {
        &self.state
    }

    /// Persist the state off the runtime.
    async fn persist(&self) -> bool {
        let state = self.state.clone();
        let path = self.cfg.state_path.clone();
        matches!(
            tokio::task::spawn_blocking(move || state.save(&path)).await,
            Ok(Ok(()))
        )
    }

    /// One tick at `now_unix` over what was `read`.
    pub async fn tick(&mut self, now_unix: i64, read: &ReadOutcome) -> Tick {
        self.note_skipped(read);
        if self.backoff_until.is_some_and(|t| now_unix < t) {
            return Tick::Idle;
        }
        // A restart within 6 h of an accepted full sends no startup full
        // (only what changed since).
        let recent_full = self
            .state
            .last_full_unix
            .is_some_and(|t| now_unix.saturating_sub(t) < RESTART_FULL_SKIP_SECS);
        if self.full_pending_since_start && recent_full {
            self.full_pending_since_start = false;
        }
        let clocks = Clocks {
            sent_digests: Some(&self.state.digests),
            next_full_unix: self.state.next_full_unix,
            last_counters_unix: self.state.last_counters_unix,
            last_sent_unix: self.state.last_sent_unix,
            full_pending_since_start: self.full_pending_since_start,
        };
        let Some(plan) = plan::plan(now_unix, &read.digests, &clocks, &self.cfg.cadence) else {
            return Tick::Idle;
        };
        // Consumed, stamped and persisted before the send.
        let sequence = self.state.next_sequence(now_unix);
        self.state.last_sent_unix = Some(now_unix);
        if !self.persist().await {
            self.stats.build_failed += 1;
            self.backoff_until = Some(now_unix.saturating_add(self.cfg.cadence.min_gap));
            log("state not persisted; report held back");
            return Tick::Failed("state-write");
        }
        let envelope = match self.build(&plan, &read.sections, now_unix, sequence) {
            Ok(e) => e,
            Err(class) => {
                self.stats.build_failed += 1;
                self.backoff_until = Some(now_unix.saturating_add(self.cfg.cadence.min_gap));
                log(&format!("report not built ({class})"));
                return Tick::Failed(class);
            }
        };
        self.stats.sent += 1;
        let reply = self.client.post(&envelope).await;
        let status = reply.as_ref().map_or(0, |r| r.status);
        let outcome = self.on_reply(reply, &plan, read, now_unix);
        if self.should_log(outcome, status, now_unix) {
            self.stats.status_lines += 1;
            let names: Vec<&str> = plan.sections.iter().copied().collect();
            log(&format!(
                "kind={} sections={} seq={sequence} bytes={} status={status} outcome={outcome:?} \
                 (sent={} accepted={} refused={} transport={} skipped_sections={})",
                kind_name(plan.kind),
                names.join(","),
                envelope.len(),
                self.stats.sent,
                self.stats.accepted,
                self.stats.refused,
                self.stats.transport,
                self.stats.skipped_sections,
            ));
        }
        if !self.persist().await {
            log("state not persisted after the send");
        }
        Tick::Sent {
            slot: plan.slot,
            kind: plan.kind,
            sequence,
            outcome,
        }
    }

    /// Print a status line for an accepted report, a new outcome, or a
    /// repeated one at most every [`QUIET_LOG_SECS`].
    fn should_log(&mut self, outcome: Outcome, status: u16, now: i64) -> bool {
        let log = match self.last_logged {
            _ if outcome == Outcome::Accepted => true,
            Some((o, s, at)) if o == outcome && s == status => {
                now.saturating_sub(at) >= QUIET_LOG_SECS
            }
            _ => true,
        };
        if log {
            self.last_logged = Some((outcome, status, now));
        }
        log
    }

    /// The `SignedHostInventory` bytes of `plan`.
    fn build(
        &self,
        plan: &Plan,
        sections: &hippius_host_inventory::Sections,
        now_unix: i64,
        sequence: u64,
    ) -> Result<Vec<u8>, &'static str> {
        let mut body = HostInventory {
            schema_version: SCHEMA_VERSION,
            domain: DOMAIN.to_string(),
            miner_id: self.cfg.miner_id.clone(),
            timestamp_unix: now_unix,
            sequence,
            report: plan.kind,
            sections: read::select(sections, &plan.sections),
        };
        body.normalize();
        let bytes = body.canonical_fitted()?;
        let sig = self.identity.sign(&bytes).to_bytes().to_vec();
        let envelope = SignedHostInventory { body: bytes, sig }.canonical()?;
        if envelope.len() > MAX_ENVELOPE_BYTES {
            return Err("host-inventory-envelope-too-large");
        }
        Ok(envelope)
    }

    /// Advance the state for a reply.
    fn on_reply(
        &mut self,
        reply: Result<EdgeReply, ()>,
        plan: &Plan,
        read: &ReadOutcome,
        now: i64,
    ) -> Outcome {
        let min_gap = self.cfg.cadence.min_gap;
        let reply = match reply {
            Ok(r) => r,
            Err(()) => {
                self.stats.transport += 1;
                let wait = self.transport_backoff.max(min_gap);
                self.backoff_until = Some(now.saturating_add(wait));
                self.transport_backoff = self
                    .transport_backoff
                    .saturating_mul(2)
                    .min(TRANSPORT_BACKOFF_CAP_SECS);
                return Outcome::Transport;
            }
        };
        match reply.status {
            200..=299 => {
                self.stats.accepted += 1;
                self.backoff_until = None;
                self.transport_backoff = TRANSPORT_BACKOFF_START_SECS;
                self.refused_streak = 0;
                for name in &plan.sections {
                    if let Some(d) = read.digests.get(name) {
                        self.state.digests.insert((*name).to_string(), d.clone());
                    }
                }
                match plan.slot {
                    Slot::Full => {
                        self.full_pending_since_start = false;
                        self.state.last_full_unix = Some(now);
                        self.state.next_full_unix =
                            Some(plan::next_full(now, &self.cfg.cadence, (self.jitter)()));
                        // It carried every counter section too.
                        self.state.last_counters_unix = Some(now);
                    }
                    Slot::Counters => self.state.last_counters_unix = Some(now),
                    Slot::Change => {}
                }
                Outcome::Accepted
            }
            429 => {
                self.stats.refused += 1;
                let wait = reply
                    .retry_after
                    .and_then(|s| i64::try_from(s).ok())
                    .unwrap_or(RATE_LIMITED_DEFAULT_SECS)
                    .clamp(RETRY_AFTER_BOUNDS.0, RETRY_AFTER_BOUNDS.1);
                self.backoff_until = Some(now.saturating_add(wait.max(min_gap)));
                Outcome::RateLimited
            }
            _ => {
                // `502` (vali refused or unavailable), the Edge's `400`
                // / `413`, anything unexpected: a growing back-off.
                self.stats.refused += 1;
                let step = self.refused_streak.min(REFUSED_BACKOFF_SECS.len() - 1);
                self.refused_streak = self.refused_streak.saturating_add(1);
                self.backoff_until = Some(now.saturating_add(REFUSED_BACKOFF_SECS[step]));
                Outcome::Refused
            }
        }
    }

    /// Count the sections skipped, logging a class only when the set
    /// changes (never a body).
    fn note_skipped(&mut self, read: &ReadOutcome) {
        self.stats.skipped_sections += read.skipped.len() as u64;
        if read.skipped != self.last_skipped {
            for (name, class) in &read.skipped {
                log(&format!("section {name} skipped ({class})"));
            }
            self.last_skipped = read.skipped.clone();
        }
    }
}

fn kind_name(kind: ReportKind) -> &'static str {
    match kind {
        ReportKind::Full => "full",
        ReportKind::Change => "change",
        ReportKind::Counters => "counters",
    }
}

/// Read `dir` off the runtime, bounded by [`READ_TIMEOUT`], one read in
/// flight (`inflight`): `None` when the previous one is still running or
/// this one timed out.
pub async fn read_bounded(dir: &Path, inflight: &Arc<AtomicBool>) -> Option<ReadOutcome> {
    if inflight.swap(true, Ordering::AcqRel) {
        log("previous read still running; tick skipped");
        return None;
    }
    struct Guard(Arc<AtomicBool>);
    impl Drop for Guard {
        fn drop(&mut self) {
            self.0.store(false, Ordering::Release);
        }
    }
    let guard = Guard(Arc::clone(inflight));
    let dir = dir.to_path_buf();
    let task = tokio::task::spawn_blocking(move || {
        let _guard = guard;
        read::read_sections(&dir)
    });
    match tokio::time::timeout(READ_TIMEOUT, task).await {
        Ok(Ok(read)) => Some(read),
        Ok(Err(_)) => None,
        Err(_) => {
            log("read timed out; tick skipped");
            None
        }
    }
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

/// The poster loop: a tick at once, then every `poll`, until `cancel`.
pub async fn run(mut poster: Poster, cancel: CancellationToken) {
    let inflight = Arc::new(AtomicBool::new(false));
    let poll = poster.cfg.poll;
    let dir = poster.cfg.dir.clone();
    loop {
        // A shutdown also ends an in-flight read or post (the sequence
        // is persisted before a send, so a dropped one is never reused).
        tokio::select! {
            () = cancel.cancelled() => return,
            () = async {
                if let Some(read) = read_bounded(&dir, &inflight).await {
                    poster.tick(now_unix(), &read).await;
                }
            } => {}
        }
        tokio::select! {
            () = cancel.cancelled() => return,
            () = tokio::time::sleep(poll) => {}
        }
    }
}

/// Spawn the poster when `[inventory] enabled`; `None` otherwise (nothing
/// runs, nothing is read). The state is loaded inside the task.
pub fn spawn_if_enabled(
    config: &Config,
    identity: Arc<MinerIdentity>,
    client: Arc<dyn InventoryClient>,
    cancel: CancellationToken,
) -> Option<tokio::task::JoinHandle<()>> {
    if !config.inventory.enabled {
        return None;
    }
    let cfg = PosterConfig::from_config(config);
    Some(tokio::spawn(async move {
        let poster = Poster::open(cfg, identity, client).await;
        run(poster, cancel).await;
    }))
}

#[cfg(test)]
mod tests;
