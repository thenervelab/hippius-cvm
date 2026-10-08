//! Agent orchestration.
//!
//! Three threads:
//! - the **feed worker** (main thread) owns every secret: the node key,
//!   the fleet keyring, the session token. It bootstraps and renews the
//!   node certificate, registers, long-polls the feed, applies and
//!   pushes it to OpenResty, persists the LKG, and flushes queued usage
//!   reports;
//! - the **meter receiver** adds OpenResty's per-request datagrams to
//!   the counters;
//! - the **local ticker** persists the counters, checkpoints a usage
//!   report into the disk queue every interval, and pushes the health
//!   bits. It never touches the network, so metering and health keep
//!   working while the backend is down.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use rand_core::{OsRng, RngCore};

use crate::attestation::{self, SnpReportProvider};
use crate::backend::{BackendClient, FeedPoll};
use crate::certstore;
use crate::clock::{format_rfc3339, parse_rfc3339, unix_now};
use crate::config::Config;
use crate::control::{self, ControlChannel, RESYNC_REQUIRED};
use crate::counters::{self, Counters, KnownZones, Previous};
use crate::error::{CdnError, Result};
use crate::feed::{self, Applied, FeedState};
use crate::health::{self, Observed};
use crate::hooks::{FeedListener, OriginPolicy, S3OnlyPolicy};
use crate::identity::{verify_node_cert, NodeCert, NodeKey};
use crate::issuer::Issuer;
use crate::persist;
use crate::render;
use crate::reqsign::{valid_session_id, NodeAuth, NO_SESSION_ID};
use crate::shutdown::{Shutdown, ShutdownWatch};
use crate::unseal::FleetKeyring;
use crate::usage::{UsageQueue, DEFAULT_MAX_QUEUED};
use crate::wire::{FeedResponse, RegisterRequest, SessionToken};

/// Renew the node certificate when less than this remains.
const CERT_RENEW_BEFORE_S: u64 = 2 * 86_400;
/// How often to ask the backend for a fresher certificate meanwhile.
const CERT_FETCH_INTERVAL_S: u64 = 3_600;
/// Spacing after a feed response that changed something (catch up fast).
const MIN_LOOP_PERIOD: Duration = Duration::from_secs(1);
/// Floor between polls after a 304 or an error: the backend answers at
/// once (no long-poll), so without it the agent would poll every second.
const IDLE_POLL_S: u64 = 5;
/// Ceiling of the exponential backoff on errors (a server Retry-After may
/// ask for longer, up to `backend::MAX_RETRY_AFTER_S`).
const MAX_BACKOFF_S: u64 = 60;
/// ±20 % jitter, in permille.
const JITTER_PERMILLE: u32 = 200;
const CHALLENGE_MIN_LEN: usize = 16;
const CHALLENGE_MAX_LEN: usize = 1_024;
const CONTROL_TIMEOUT: Duration = Duration::from_secs(10);
const LOG: &str = "hippius-cdn-agent";

/// What one feed round did, for pacing the next one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Poll {
    /// A new revision was applied: poll again soon.
    Updated,
    /// Nothing changed (304 or an unchanged snapshot).
    Idle { retry_after: Option<u64> },
}

/// How long to wait before the next feed poll.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pace {
    AfterUpdate,
    Idle {
        retry_after: Option<u64>,
    },
    Error {
        failures: u32,
        retry_after: Option<u64>,
    },
}

/// The delay for `pace`, with `jitter_permille` in [-200, 200] applied to
/// idle and error waits. A server `Retry-After` is a floor the jitter
/// never goes under.
pub fn poll_delay(pace: Pace, jitter_permille: i32) -> Duration {
    let (base_s, retry_after) = match pace {
        Pace::AfterUpdate => return MIN_LOOP_PERIOD,
        Pace::Idle { retry_after } => (IDLE_POLL_S, retry_after),
        Pace::Error {
            failures,
            retry_after,
        } => {
            let exp = IDLE_POLL_S.saturating_mul(1u64 << failures.saturating_sub(1).min(6));
            (exp.min(MAX_BACKOFF_S), retry_after)
        }
    };
    let jitter = i64::from(jitter_permille.clamp(-200, 200));
    let ms = i64::try_from(base_s * 1_000).unwrap_or(i64::MAX);
    let jittered = u64::try_from(ms + ms * jitter / 1_000).unwrap_or(0);
    let floor = retry_after.unwrap_or(0).saturating_mul(1_000);
    Duration::from_millis(jittered.max(floor))
}

fn jitter_permille() -> i32 {
    let span = 2 * JITTER_PERMILLE + 1;
    i32::try_from(OsRng.next_u32() % span).unwrap_or(0)
        - i32::try_from(JITTER_PERMILLE).unwrap_or(0)
}

/// State files under `paths.state_dir`.
pub struct StatePaths {
    pub lkg: PathBuf,
    pub counters: PathBuf,
    pub usage_queue: PathBuf,
}

impl StatePaths {
    pub fn new(state_dir: &Path) -> Self {
        Self {
            lkg: state_dir.join("feed.json"),
            counters: state_dir.join("counters.json"),
            usage_queue: state_dir.join("usage-queue"),
        }
    }
}

struct Session {
    token: SessionToken,
    /// Signed into every request (§C.0).
    session_id: String,
    refresh_at: u64,
}

/// The feed worker (see module docs).
pub struct FeedWorker {
    cfg: Config,
    key: NodeKey,
    keyring: FleetKeyring,
    policy: Box<dyn OriginPolicy>,
    control: Arc<dyn ControlChannel>,
    observed: Arc<Mutex<Observed>>,
    known_zones: KnownZones,
    queue: UsageQueue,
    lkg_path: PathBuf,
    listeners: Vec<Box<dyn FeedListener>>,
    attest: Option<Box<dyn SnpReportProvider>>,

    client: BackendClient,
    issuer: Issuer,
    cert: Option<NodeCert>,
    next_cert_fetch_at: u64,
    session: Option<Session>,

    state: FeedState,
    etag: Option<String>,
    want_snapshot: bool,
    dirty: bool,
    last_push_at: u64,
    attested_spki: Option<[u8; 32]>,
}

impl FeedWorker {
    pub fn new(
        cfg: Config,
        key: NodeKey,
        keyring: FleetKeyring,
        control: Arc<dyn ControlChannel>,
        observed: Arc<Mutex<Observed>>,
        known_zones: KnownZones,
        paths: &StatePaths,
    ) -> Result<Self> {
        let client = BackendClient::new(&cfg.backend)?;
        let issuer = Issuer::new(
            cfg.acme.clone(),
            &cfg.identity.fleet_wildcard_hostname,
            &cfg.node.region,
        )?;
        if cfg.backend.request_signatures {
            // The backend checks the signed host against its own setting:
            // a mismatch only shows once it enforces signatures.
            eprintln!(
                "{LOG}: signing requests for host {}",
                cfg.backend.url.signed_host()
            );
        }
        let queue = UsageQueue::open(paths.usage_queue.clone(), DEFAULT_MAX_QUEUED)?;
        Ok(Self {
            cfg,
            key,
            keyring,
            policy: Box::new(S3OnlyPolicy),
            control,
            observed,
            known_zones,
            queue,
            lkg_path: paths.lkg.clone(),
            listeners: Vec::new(),
            attest: None,
            client,
            issuer,
            cert: None,
            next_cert_fetch_at: 0,
            session: None,
            state: FeedState::default(),
            etag: None,
            want_snapshot: true,
            dirty: false,
            last_push_at: 0,
            attested_spki: None,
        })
    }

    /// I6 swaps the origin policy.
    pub fn set_origin_policy(&mut self, policy: Box<dyn OriginPolicy>) {
        self.policy = policy;
    }

    /// I4/I5 register here.
    pub fn add_listener(&mut self, listener: Box<dyn FeedListener>) {
        self.listeners.push(listener);
    }

    pub fn set_attestation(&mut self, provider: Option<Box<dyn SnpReportProvider>>) {
        self.attest = provider;
    }

    pub fn applied_revision(&self) -> u64 {
        self.state.revision
    }

    /// Adopt the LKG snapshot at boot. It is pushed on the first step so
    /// OpenResty has a config, but it does not make the node ready: the
    /// guest clock and the data volume are under the host's control, so
    /// an old snapshot plus a blocked backend must not pass for current.
    /// The node turns ready at its first successful backend round, and
    /// only then does the 24 h outage allowance start.
    pub fn adopt_lkg(&mut self, state: FeedState) {
        self.state = state;
        self.dirty = true;
    }

    /// Loop until shutdown.
    pub fn run(&mut self, shutdown: &Shutdown) {
        let mut failures: u32 = 0;
        while !shutdown.is_pending() {
            let started = std::time::Instant::now();
            let pace = match self.step(unix_now()) {
                Ok(Poll::Updated) => {
                    failures = 0;
                    Pace::AfterUpdate
                }
                Ok(Poll::Idle { retry_after }) => {
                    failures = 0;
                    Pace::Idle { retry_after }
                }
                Err(e) => {
                    failures = failures.saturating_add(1);
                    eprintln!("{LOG}: feed loop: {} (attempt {failures})", e.class());
                    let retry_after = match e {
                        CdnError::Throttled { retry_after_s, .. } => Some(retry_after_s),
                        _ => None,
                    };
                    Pace::Error {
                        failures,
                        retry_after,
                    }
                }
            };
            let wait = poll_delay(pace, jitter_permille());
            if let Some(rest) = wait.checked_sub(started.elapsed()) {
                if !shutdown.sleep(rest) {
                    break;
                }
            }
        }
    }

    /// One iteration: re-push local state if needed, one backend round,
    /// then a usage flush. Returns the feed round's outcome.
    pub fn step(&mut self, now: u64) -> Result<Poll> {
        if self.push_due(now) {
            if let Err(e) = self.push_all(now) {
                eprintln!("{LOG}: data-plane push: {}", e.class());
            }
        }
        let round = self.backend_round(now);
        // A usage flush failure is retried on the next round; it does not
        // slow the feed down (the queue keeps the reports). Except a 401:
        // it dropped the session, and re-registering every round would
        // loop, so it counts as a failed round and backs off.
        if let Err(e) = self.flush_usage() {
            eprintln!("{LOG}: usage flush: {}", e.class());
            if matches!(e, CdnError::Unauthorized) && round.is_ok() {
                return Err(e);
            }
        }
        self.issue();
        round
    }

    fn push_due(&self, now: u64) -> bool {
        let resync = self
            .observed
            .lock()
            .map(|o| o.resync_needed)
            .unwrap_or(true);
        !self.state.is_empty()
            && (self.dirty
                || resync
                || now.saturating_sub(self.last_push_at) >= self.cfg.timing.resync_interval_s)
    }

    fn backend_round(&mut self, now: u64) -> Result<Poll> {
        self.ensure_cert(now)?;
        self.ensure_session()?;
        let Some(session) = &self.session else {
            return Err(CdnError::Backend("no-session"));
        };
        let auth = NodeAuth {
            token: &session.token,
            session_id: &session.session_id,
            node_id: &self.cfg.node.vm_id,
            key: &self.key,
            sign: self.cfg.backend.request_signatures,
        };
        let since = (!self.want_snapshot && !self.state.is_empty()).then_some(self.state.revision);
        let etag = since.and(self.etag.as_deref());
        match self.client.feed(&auth, since, etag) {
            Ok(FeedPoll::NotModified { retry_after }) => {
                self.confirm(now);
                Ok(Poll::Idle { retry_after })
            }
            Ok(FeedPoll::Updated { resp, etag }) => self.handle_feed(*resp, etag, now),
            Err(CdnError::Unauthorized) => {
                self.session = None;
                Err(CdnError::Unauthorized)
            }
            Err(e) => Err(e),
        }
    }

    fn handle_feed(&mut self, resp: FeedResponse, etag: Option<String>, now: u64) -> Result<Poll> {
        if let Some(pem) = resp.self_state.cert_pem.clone() {
            self.consider_cert(&pem, now);
        }
        match self.state.apply(resp) {
            Ok(Applied::Stale) => {
                self.confirm(now);
                Ok(Poll::Idle { retry_after: None })
            }
            Ok(Applied::New(next)) => {
                self.state = *next;
                self.etag = etag;
                self.want_snapshot = false;
                self.dirty = true;
                if let Err(e) = feed::save_lkg(&self.lkg_path, &self.state, now) {
                    eprintln!("{LOG}: lkg save: {}", e.class());
                }
                match self.push_all(now) {
                    Ok(()) => {
                        self.confirm(now);
                        Ok(Poll::Updated)
                    }
                    Err(e) => {
                        self.mark_pending(now);
                        Err(e)
                    }
                }
            }
            Err(e) => {
                // Ask for a snapshot next time: a bad delta would only be
                // served again.
                self.mark_pending(now);
                self.want_snapshot = true;
                self.etag = None;
                Err(e)
            }
        }
    }

    /// Render and push config, secrets, certificates and attestation.
    fn push_all(&mut self, now: u64) -> Result<()> {
        let result = self.push_documents(now);
        if let Err(CdnError::Control(RESYNC_REQUIRED)) = &result {
            // OpenResty restarted mid-push: everything goes again.
            self.attested_spki = None;
        }
        result
    }

    fn push_documents(&mut self, now: u64) -> Result<()> {
        let wildcard = self.cfg.identity.fleet_wildcard_hostname.clone();
        let rendered = render::render(
            &self.state,
            &self.keyring,
            self.policy.as_ref(),
            &self.cfg.data_plane,
            &wildcard,
        )?;
        let store = certstore::build(&self.state, &self.keyring, &wildcard, now)?;
        // Secrets and certificates first, so a new zone in the config
        // never runs without them.
        self.control.put(control::PATH_SECRETS, &rendered.secrets)?;
        self.control.put(control::PATH_CERTS, &store.body)?;
        self.control.put(control::PATH_CONFIG, &rendered.config)?;
        log_skipped("zone not serving", &rendered.refused);
        log_skipped("certificate skipped", &store.skipped);
        self.refresh_attestation(store.default_spki_sha256);

        let fleet_key_ok = self.fleet_key_ok();
        {
            let mut o = self
                .observed
                .lock()
                .map_err(|_| CdnError::Control("lock-poisoned"))?;
            o.applied_revision = self.state.revision;
            o.feed_applied = !self.state.is_empty();
            o.cert_store_loaded = store.default_spki_sha256.is_some();
            o.fleet_key_ok = fleet_key_ok;
            o.draining = self.state.self_state.draining;
            o.quota_guard = self.state.self_state.quota_guard;
            o.resync_needed = false;
        }
        // Bill only zones that are active and actually served: a record
        // for a paused, suspended or refused zone is never billable.
        if let Ok(mut zones) = self.known_zones.write() {
            *zones = self
                .state
                .zones
                .iter()
                .filter(|(id, z)| {
                    z.state == crate::wire::ZoneState::Active
                        && !rendered.refused.iter().any(|(r, _)| r == *id)
                })
                .map(|(id, _)| id.clone())
                .collect();
        }
        self.dirty = false;
        self.last_push_at = now;
        for l in &mut self.listeners {
            l.on_applied(&self.state, &self.keyring);
        }
        Ok(())
    }

    fn refresh_attestation(&mut self, spki: Option<[u8; 32]>) {
        if !self.cfg.data_plane.attestation || spki == self.attested_spki {
            return;
        }
        let (Some(spki), Some(provider)) = (spki, self.attest.as_ref()) else {
            return;
        };
        let doc = provider
            .get_report(&attestation::report_data(&spki))
            .and_then(|report| attestation::document(&spki, &report))
            .and_then(|doc| self.control.put(control::PATH_ATTESTATION, &doc));
        match doc {
            Ok(()) => self.attested_spki = Some(spki),
            Err(e) => eprintln!("{LOG}: attestation: {}", e.class()),
        }
    }

    /// Hold the active version, and match its public half when the
    /// backend publishes it.
    fn fleet_key_ok(&self) -> bool {
        let Some(active) = self.state.active_fleet_version() else {
            return false;
        };
        let Some(ours) = self.keyring.public_key(active) else {
            return false;
        };
        self.state
            .fleet_key_versions
            .iter()
            .find(|v| v.version == active)
            .and_then(|v| v.x25519_public_b64.as_deref())
            .is_none_or(|theirs| B64.decode(theirs).is_ok_and(|t| t == ours))
    }

    fn confirm(&self, now: u64) {
        if let Ok(mut o) = self.observed.lock() {
            if o.applied_revision == self.state.revision {
                o.confirmed_at = now;
                o.pending_since = None;
            }
        }
    }

    fn mark_pending(&self, now: u64) {
        if let Ok(mut o) = self.observed.lock() {
            o.pending_since.get_or_insert(now);
        }
    }

    // ── Node certificate, client, session ──────────────────────────

    fn ensure_cert(&mut self, now: u64) -> Result<()> {
        if self.cert.as_ref().is_some_and(|c| c.not_after <= now) {
            self.drop_cert();
        }
        let renewing = self
            .cert
            .as_ref()
            .is_none_or(|c| c.not_after - now < CERT_RENEW_BEFORE_S);
        if renewing && now >= self.next_cert_fetch_at {
            let fetched = self
                .client
                .node_cert(&self.cfg.node.vm_id)
                .and_then(|pem| self.verify_cert(&pem, now));
            match fetched {
                Ok(cert) => {
                    self.install_cert(cert);
                    self.next_cert_fetch_at = now + CERT_FETCH_INTERVAL_S;
                }
                Err(e) if self.cert.is_some() => {
                    eprintln!("{LOG}: node cert renewal: {}", e.class());
                    self.next_cert_fetch_at = now + CERT_FETCH_INTERVAL_S;
                }
                Err(e) => return Err(e),
            }
        }
        if self.cert.is_none() {
            return Err(CdnError::Identity("node-cert-unavailable"));
        }
        Ok(())
    }

    /// A certificate relayed in the feed's `self.cert_pem`.
    fn consider_cert(&mut self, pem: &str, now: u64) {
        if self.cert.as_ref().is_some_and(|c| c.pem == pem) {
            return;
        }
        match self.verify_cert(pem, now) {
            Ok(cert) => self.install_cert(cert),
            Err(e) => eprintln!("{LOG}: feed node cert refused: {}", e.class()),
        }
    }

    fn verify_cert(&self, pem: &str, now: u64) -> Result<NodeCert> {
        verify_node_cert(
            pem,
            &self.key.public_bytes(),
            &self.cfg.node,
            &self.cfg.identity.trust_domain,
            now,
        )
    }

    /// Adopt a different, verified certificate (the backend relays vali's
    /// current one, so a re-issue replaces the old even if it expires
    /// sooner). A new certificate means a fresh registration.
    fn install_cert(&mut self, cert: NodeCert) {
        if self
            .cert
            .as_ref()
            .is_some_and(|c| cert.generation < c.generation)
        {
            eprintln!("{LOG}: node certificate of an older generation refused");
            return;
        }
        if self.cert.as_ref().is_none_or(|c| c.pem != cert.pem) {
            eprintln!(
                "{LOG}: node certificate g{} valid until {}",
                cert.generation,
                format_rfc3339(cert.not_after)
            );
            self.cert = Some(cert);
            self.session = None;
        }
    }

    fn drop_cert(&mut self) {
        self.cert = None;
        self.session = None;
    }

    /// Register when there is no session or it is due for renewal. Session
    /// times are on the backend's clock, not the guest's.
    fn ensure_session(&mut self) -> Result<()> {
        let client = &self.client;
        if self
            .session
            .as_ref()
            .is_some_and(|s| client.server_now() < s.refresh_at)
        {
            return Ok(());
        }
        let cert = self
            .cert
            .as_ref()
            .ok_or(CdnError::Identity("node-cert-unavailable"))?;
        let vm_id = self.cfg.node.vm_id.as_str();
        let ch = client.challenge(vm_id)?;
        let challenge = B64
            .decode(&ch.challenge_b64)
            .map_err(|_| CdnError::Backend("challenge-not-base64"))?;
        if !(CHALLENGE_MIN_LEN..=CHALLENGE_MAX_LEN).contains(&challenge.len()) {
            return Err(CdnError::Backend("challenge-length"));
        }
        let msg = crate::wire::register_message(vm_id, cert.generation, &challenge);
        let req = RegisterRequest {
            vm_id,
            generation: cert.generation,
            cert_pem: &cert.pem,
            challenge_b64: &ch.challenge_b64,
            signature_b64: B64.encode(self.key.sign(&msg)),
        };
        let resp = match client.register(&req) {
            Ok(r) => r,
            Err(CdnError::BackendStatus(503)) => {
                // `cert-auth-disabled` (registration is off at the backend)
                // or a transient outage: the feed loop backs off and retries.
                eprintln!("{LOG}: registration unavailable (503), retrying with back-off");
                return Err(CdnError::BackendStatus(503));
            }
            Err(e) => return Err(e),
        };
        let expires = parse_rfc3339(&resp.expires_at)?;
        let now = client.server_now();
        if expires <= now {
            return Err(CdnError::Backend("session-already-expired"));
        }
        let session_id = match resp.session_token_id.or(resp.session_id) {
            Some(id) if valid_session_id(&id) => id,
            Some(_) => return Err(CdnError::Backend("session-id-invalid")),
            None => NO_SESSION_ID.to_string(),
        };
        self.session = Some(Session {
            token: resp.session_token,
            session_id,
            refresh_at: now + (expires - now) * 3 / 4,
        });
        eprintln!(
            "{LOG}: registered, session until {}",
            format_rfc3339(expires)
        );
        Ok(())
    }

    /// One step of certificate issuance (I4), on the backend's clock.
    fn issue(&mut self) {
        let Some(session) = &self.session else {
            return;
        };
        let auth = NodeAuth {
            token: &session.token,
            session_id: &session.session_id,
            node_id: &self.cfg.node.vm_id,
            key: &self.key,
            sign: self.cfg.backend.request_signatures,
        };
        self.issuer.tick(
            self.client.server_now(),
            &self.client,
            &auth,
            &self.state,
            &self.keyring,
        );
    }

    fn flush_usage(&mut self) -> Result<()> {
        let Some(session) = &self.session else {
            return Ok(());
        };
        let auth = NodeAuth {
            token: &session.token,
            session_id: &session.session_id,
            node_id: &self.cfg.node.vm_id,
            key: &self.key,
            sign: self.cfg.backend.request_signatures,
        };
        match self.queue.flush(&self.client, &auth) {
            Ok(_) => Ok(()),
            Err(CdnError::Unauthorized) => {
                self.session = None;
                Err(CdnError::Unauthorized)
            }
            Err(e) => Err(e),
        }
    }
}

fn log_skipped(what: &str, items: &[(String, &'static str)]) {
    if items.is_empty() {
        return;
    }
    let shown: Vec<String> = items
        .iter()
        .take(5)
        .map(|(id, class)| format!("{id}={class}"))
        .collect();
    eprintln!("{LOG}: {} {what}: {}", items.len(), shown.join(" "));
}

/// The network-free loop (see module docs).
pub struct LocalTicker {
    pub cfg: Config,
    pub counters: Arc<Mutex<Counters>>,
    pub counters_path: PathBuf,
    pub queue: UsageQueue,
    pub control: Arc<dyn ControlChannel>,
    pub observed: Arc<Mutex<Observed>>,
    pub geoip_db: String,
    next_persist: u64,
    next_usage: u64,
    next_health: u64,
}

impl LocalTicker {
    pub fn new(
        cfg: Config,
        counters: Arc<Mutex<Counters>>,
        paths: &StatePaths,
        control: Arc<dyn ControlChannel>,
        observed: Arc<Mutex<Observed>>,
        geoip_db: String,
        now: u64,
    ) -> Result<Self> {
        let queue = UsageQueue::open(paths.usage_queue.clone(), DEFAULT_MAX_QUEUED)?;
        Ok(Self {
            next_persist: now + cfg.timing.persist_interval_s,
            next_usage: now + cfg.timing.usage_interval_s,
            next_health: now,
            cfg,
            counters,
            counters_path: paths.counters.clone(),
            queue,
            control,
            observed,
            geoip_db,
        })
    }

    pub fn run(&mut self, shutdown: &Shutdown) -> Result<()> {
        while shutdown.sleep(Duration::from_secs(1)) {
            self.tick(unix_now())?;
        }
        Ok(())
    }

    /// Do whatever is due at `now`. Only a poisoned lock is fatal.
    pub fn tick(&mut self, now: u64) -> Result<()> {
        if now >= self.next_usage {
            self.next_usage = now + self.cfg.timing.usage_interval_s;
            self.next_persist = now + self.cfg.timing.persist_interval_s;
            if let Err(e) = self.checkpoint(now) {
                eprintln!("{LOG}: usage checkpoint: {}", e.class());
            }
        } else if now >= self.next_persist {
            self.next_persist = now + self.cfg.timing.persist_interval_s;
            let snap = self.lock_counters()?.clone();
            if let Err(e) = snap.persist(&self.counters_path) {
                eprintln!("{LOG}: counters persist: {}", e.class());
            }
        }
        if now >= self.next_health {
            self.next_health = now + self.cfg.timing.health_interval_s;
            self.push_health(now)?;
        }
        Ok(())
    }

    /// Persist-then-queue: the report's totals are on disk before it can
    /// be sent, so the next start's final report is never below it.
    fn checkpoint(&mut self, now: u64) -> Result<()> {
        let snap = self.lock_counters()?.begin_checkpoint();
        if let Err(e) = snap.persist(&self.counters_path) {
            self.lock_counters()?.abort_checkpoint();
            return Err(e);
        }
        let applied = self
            .observed
            .lock()
            .map(|o| o.applied_revision)
            .map_err(|_| CdnError::Counters("lock-poisoned"))?;
        let report = snap.report(
            &self.cfg.node.vm_id,
            format_rfc3339(now),
            applied,
            &self.geoip_db,
        );
        self.queue.enqueue(&report)
    }

    fn push_health(&mut self, now: u64) -> Result<()> {
        let observed = self
            .observed
            .lock()
            .map_err(|_| CdnError::Control("lock-poisoned"))?
            .clone();
        let mounted = health::volume_mounted(&self.cfg.paths.data_mount);
        let h = health::evaluate(&observed, mounted, now, &self.cfg.timing);
        let body = serde_json::to_vec(&h).map_err(|_| CdnError::Control("health-encode"))?;
        match self.control.put(control::PATH_HEALTH, &body) {
            Ok(()) => {}
            Err(CdnError::Control(RESYNC_REQUIRED)) => {
                if let Ok(mut o) = self.observed.lock() {
                    o.resync_needed = true;
                }
            }
            Err(e) => eprintln!("{LOG}: health push: {}", e.class()),
        }
        Ok(())
    }

    fn lock_counters(&self) -> Result<std::sync::MutexGuard<'_, Counters>> {
        self.counters
            .lock()
            .map_err(|_| CdnError::Counters("lock-poisoned"))
    }
}

/// Read the baked GeoIP database version (reported with every sample).
pub fn read_geoip_version(path: Option<&Path>) -> String {
    let Some(path) = path else {
        return "none".to_string();
    };
    match std::fs::read_to_string(path) {
        Ok(s) => {
            let v = s.trim();
            if !v.is_empty()
                && v.len() <= 64
                && v.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
            {
                v.to_string()
            } else {
                "invalid".to_string()
            }
        }
        Err(_) => "missing".to_string(),
    }
}

/// Run the agent until shutdown.
pub fn run(cfg: Config, shutdown: Shutdown) -> Result<()> {
    let key = NodeKey::from_lifecycle_file(&cfg.identity.lifecycle_key)?;
    let keyring = FleetKeyring::load_dir(&cfg.identity.fleet_key_dir)?;
    eprintln!(
        "{LOG}: node {} region {}: node key derived, fleet versions {:?}",
        cfg.node.vm_id,
        cfg.node.region,
        keyring.versions()
    );

    persist::ensure_private_dir(&cfg.paths.state_dir)?;
    let paths = StatePaths::new(&cfg.paths.state_dir);
    let now = unix_now();
    let geoip_db = read_geoip_version(cfg.paths.geoip_version_file.as_deref());

    let lkg = match feed::load_lkg(&paths.lkg, now, cfg.timing.lkg_max_age_s) {
        Ok(found) => found,
        Err(e) => {
            eprintln!("{LOG}: lkg ignored: {}", e.class());
            None
        }
    };
    let lkg_revision = lkg.as_ref().map_or(0, |(s, _)| s.revision);

    // Close the previous run's epoch before opening a new one.
    let (fresh, previous) = Counters::start(&paths.counters)?;
    let mut start_queue = UsageQueue::open(paths.usage_queue.clone(), DEFAULT_MAX_QUEUED)?;
    match previous {
        Previous::Final(old) => {
            let report = old.final_report(
                &cfg.node.vm_id,
                format_rfc3339(now),
                lkg_revision,
                &geoip_db,
            );
            start_queue.enqueue(&report)?;
            eprintln!(
                "{LOG}: closed counter epoch {} at seq {}",
                report.counter_epoch, report.seq
            );
        }
        Previous::Corrupt => eprintln!("{LOG}: counter file corrupt, new epoch"),
        Previous::None => eprintln!("{LOG}: no counter file, new epoch"),
    }
    fresh.persist(&paths.counters)?;
    eprintln!("{LOG}: counter epoch {}", fresh.epoch());
    let counters = Arc::new(Mutex::new(fresh));

    let control: Arc<dyn ControlChannel> = Arc::new(control::UnixControl::new(
        cfg.paths.control_socket.clone(),
        cfg.paths.control_socket_uid,
        CONTROL_TIMEOUT,
    ));
    let known_zones: KnownZones = Arc::default();
    let observed = Arc::new(Mutex::new(Observed::default()));
    // The agent created state_dir, so its owner is the agent's uid.
    let agent_uid = std::os::unix::fs::MetadataExt::uid(
        &std::fs::metadata(&cfg.paths.state_dir).map_err(|_| CdnError::Io("state-dir-stat"))?,
    );
    let meter = counters::bind_meter_socket(&cfg.paths.metering_socket, agent_uid)?;

    let mut worker = FeedWorker::new(
        cfg.clone(),
        key,
        keyring,
        Arc::clone(&control),
        Arc::clone(&observed),
        Arc::clone(&known_zones),
        &paths,
    )?;
    if cfg.data_plane.attestation {
        worker.set_attestation(attestation::platform_provider());
    }
    if let Some((state, _saved_at)) = lkg {
        eprintln!("{LOG}: loaded last-known-good revision {}", state.revision);
        worker.adopt_lkg(state);
    }

    let mut ticker = LocalTicker::new(
        cfg.clone(),
        Arc::clone(&counters),
        &paths,
        Arc::clone(&control),
        Arc::clone(&observed),
        geoip_db,
        now,
    )?;

    let rx_counters = Arc::clone(&counters);
    let rx_stop = shutdown.clone();
    let receiver = std::thread::Builder::new()
        .name("meter".into())
        .spawn(move || {
            let r = counters::run_receiver(&meter, &rx_counters, &known_zones, None, &rx_stop);
            rx_stop.trigger();
            r.map(|_| ())
        })
        .map_err(|_| CdnError::Io("thread-spawn"))?;
    let tick_stop = shutdown.clone();
    let ticking = std::thread::Builder::new()
        .name("ticker".into())
        .spawn(move || {
            let r = ticker.run(&tick_stop);
            tick_stop.trigger();
            r
        })
        .map_err(|_| CdnError::Io("thread-spawn"))?;

    worker.run(&shutdown);
    shutdown.trigger();

    let rx = receiver
        .join()
        .map_err(|_| CdnError::Io("thread-panicked"))?;
    let tk = ticking
        .join()
        .map_err(|_| CdnError::Io("thread-panicked"))?;
    // Final persist: the next start closes this epoch from it.
    let persisted = counters
        .lock()
        .map_err(|_| CdnError::Counters("lock-poisoned"))?
        .persist(&paths.counters);
    drop(worker);
    rx.and(tk).and(persisted)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::certstore::tests::sealed_cert;
    use crate::config::BackendUrl;
    use crate::control::RecordingControl;
    use crate::feed::tests::snapshot;
    use crate::identity::tests::node_cert_pem;
    use crate::test_support::{MockBackend, Reply, Request};
    use crate::wire::UsageReport;
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    use serde_json::json;
    use std::sync::atomic::{AtomicU64, Ordering};

    const NODE: &str =
        r#"{"node_id":"cdn-fr-7k2m","region":"FR","backend_url":"https://api.example.test"}"#;
    const SAN: &str = "spiffe://hippius.network/cdn/FR/cdn-fr-7k2m/g3";

    struct Rig {
        dir: tempfile::TempDir,
        worker: FeedWorker,
        control: Arc<RecordingControl>,
        observed: Arc<Mutex<Observed>>,
        known: KnownZones,
        paths: StatePaths,
    }

    fn rig(mock: &MockBackend) -> Rig {
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = Config::from_strs(
            &format!(
                "[backend]\nrequest_signatures = true\n{}",
                crate::config::tests::UID
            ),
            NODE,
        )
        .unwrap();
        cfg.backend.url = BackendUrl::loopback_for_tests(mock.addr());
        cfg.backend.feed_poll_s = 1;
        cfg.paths.state_dir = dir.path().to_path_buf();
        let paths = StatePaths::new(dir.path());
        let control = Arc::new(RecordingControl::default());
        let observed = Arc::new(Mutex::new(Observed::default()));
        let known: KnownZones = Arc::default();
        let worker = FeedWorker::new(
            cfg,
            NodeKey::derive(&[7u8; 32]),
            FleetKeyring::from_secrets([(1, [9u8; 32])]),
            control.clone(),
            Arc::clone(&observed),
            Arc::clone(&known),
            &paths,
        )
        .unwrap();
        Rig {
            dir,
            worker,
            control,
            observed,
            known,
            paths,
        }
    }

    fn fleet_public() -> [u8; 32] {
        FleetKeyring::from_secrets([(1, [9u8; 32])])
            .public_key(1)
            .unwrap()
    }

    /// A snapshot carrying the fleet wildcard certificate.
    fn snapshot_with_wildcard(rev: u64) -> serde_json::Value {
        let mut s = snapshot(rev);
        let wc = sealed_cert(
            "fleet",
            "*.c.hipcdn.net",
            &["*.c.hipcdn.net"],
            &fleet_public(),
            1,
            30,
        );
        s["certs"] = json!([serde_json::to_value(&wc).unwrap()]);
        s["fleet_key_versions"] = json!([{"version": 1, "state": "active",
            "x25519_public_b64": B64.encode(fleet_public())}]);
        s
    }

    /// A backend that serves registration, one snapshot, then 304s.
    fn happy_backend(cert_pem: String, feed: serde_json::Value) -> MockBackend {
        happy_backend_until(cert_pem, feed, Arc::default())
    }

    /// [`happy_backend`] that answers 503 to everything once `down` is set.
    fn happy_backend_until(
        cert_pem: String,
        feed: serde_json::Value,
        down: Arc<std::sync::atomic::AtomicBool>,
    ) -> MockBackend {
        let feed = feed.to_string();
        MockBackend::start(move |req: &Request| {
            match req.target.as_str() {
            _ if down.load(Ordering::SeqCst) => Reply::status(503),
            t if t.starts_with("/api/cdn/node/cert/") => {
                Reply::json(200, &json!({"cert_pem": cert_pem}).to_string())
            }
            "/api/cdn/node/register/challenge/" => Reply::json(
                200,
                &json!({"challenge_b64": B64.encode([5u8; 32]), "expires_at": "2099-01-01T00:00:00Z"})
                    .to_string(),
            ),
            "/api/cdn/node/register/" => Reply::json(
                200,
                &json!({"session_token": "sess-1", "session_token_id": "cns_1", "session_id": "cns_old", "expires_at": format_rfc3339(unix_now() + 3600)})
                    .to_string(),
            ),
            "/api/cdn/node/feed/" => Reply::json(200, &feed).with_header("ETag", "\"r10\""),
            t if t.starts_with("/api/cdn/node/feed/?since=") => Reply::status(304),
            "/api/cdn/node/usage/" => Reply::status(204),
            _ => Reply::status(404),
        }
        })
    }

    #[test]
    fn a_snapshot_at_revision_0_is_pushed_and_counts_as_applied() {
        let key = NodeKey::derive(&[7u8; 32]);
        let mock = happy_backend(node_cert_pem(&key, SAN, 7), snapshot_with_wildcard(0));
        let mut r = rig(&mock);
        let now = unix_now();
        r.worker.step(now).unwrap();
        assert_eq!(r.control.last("/v1/config").unwrap()["revision"], 0);
        let o = r.observed.lock().unwrap().clone();
        assert!(o.feed_applied && o.applied_revision == 0);
        assert!(crate::health::evaluate(&o, true, now, &r.worker.cfg.timing).feed_fresh);
        // The next poll asks from revision 0 instead of another snapshot.
        r.worker.step(now + 1).unwrap();
        let feeds = mock.requests_to("/api/cdn/node/feed/?since=0");
        assert_eq!(
            feeds.len(),
            1,
            "{:?}",
            mock.requests()
                .iter()
                .map(|r| r.target.clone())
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn full_round_registers_applies_pushes_and_flushes_usage() {
        let key = NodeKey::derive(&[7u8; 32]);
        let mock = happy_backend(node_cert_pem(&key, SAN, 7), snapshot_with_wildcard(10));
        let mut r = rig(&mock);
        // A queued report from the ticker.
        let mut q = UsageQueue::open(r.paths.usage_queue.clone(), 10).unwrap();
        q.enqueue(&Counters::fresh().final_report("cdn-fr-7k2m", "t".into(), 0, "db"))
            .unwrap();

        let now = unix_now();
        r.worker.step(now).unwrap();

        // Registration: challenge signed under the register domain with the
        // certificate's generation.
        let reg = &mock.requests_to("/api/cdn/node/register/")[1];
        let body = reg.json();
        assert_eq!(body["vm_id"], "cdn-fr-7k2m");
        assert_eq!(body["generation"], 3);
        let sig: [u8; 64] = B64
            .decode(body["signature_b64"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        VerifyingKey::from_bytes(&key.public_bytes())
            .unwrap()
            .verify(
                &crate::wire::register_message("cdn-fr-7k2m", 3, &[5u8; 32]),
                &Signature::from_bytes(&sig),
            )
            .unwrap();

        // The feed was a snapshot request with the session token.
        let feed = &mock.requests_to("/api/cdn/node/feed/")[0];
        assert_eq!(feed.target, "/api/cdn/node/feed/");
        assert_eq!(feed.header("authorization"), Some("Bearer sess-1"));
        // … signed with the node key over the registered session id (§C.0).
        let ts: u64 = feed
            .header("x-hippius-node-timestamp")
            .unwrap()
            .parse()
            .unwrap();
        let req_sig = B64
            .decode(feed.header("x-hippius-node-signature").unwrap())
            .unwrap();
        VerifyingKey::from_bytes(&key.public_bytes())
            .unwrap()
            .verify(
                &crate::reqsign::request_message(
                    "cdn-fr-7k2m",
                    "GET",
                    &mock.addr().to_string(),
                    "/api/cdn/node/feed/",
                    ts,
                    b"",
                    "cns_1",
                ),
                &Signature::from_slice(&req_sig).unwrap(),
            )
            .unwrap();

        // Pushed in order: secrets, certs, config.
        let order: Vec<String> = r
            .control
            .pushes
            .lock()
            .unwrap()
            .iter()
            .map(|(p, _)| p.clone())
            .collect();
        assert_eq!(order, vec!["/v1/secrets", "/v1/certs", "/v1/config"]);
        assert_eq!(r.control.last("/v1/config").unwrap()["revision"], 10);
        assert_eq!(
            r.control.last("/v1/certs").unwrap()["default"],
            "*.c.hipcdn.net"
        );

        let o = r.observed.lock().unwrap().clone();
        assert_eq!(o.applied_revision, 10);
        assert!(o.cert_store_loaded && o.fleet_key_ok);
        assert_eq!(o.confirmed_at, now);
        // Metering bills only the active zone, not the paused z2.
        assert_eq!(
            *r.known.read().unwrap(),
            std::collections::BTreeSet::from(["z1".to_string()])
        );

        // LKG on disk holds ciphertext only.
        let lkg = std::fs::read_to_string(&r.paths.lkg).unwrap();
        assert!(lkg.contains("sealed_blob_b64"));
        assert!(!lkg.contains("PRIVATE KEY"));

        // The queued report went out, signed.
        let usage = &mock.requests_to("/api/cdn/node/usage/")[0];
        assert!(usage.header("x-hippius-cdn-signature").is_some());
        let _: UsageReport = serde_json::from_slice(&usage.body).unwrap();

        // Next round: incremental poll with ETag, 304 confirms.
        r.worker.step(now + 30).unwrap();
        let polls = mock.requests_to("/api/cdn/node/feed/");
        assert_eq!(polls[1].target, "/api/cdn/node/feed/?since=10");
        assert_eq!(polls[1].header("if-none-match"), Some("\"r10\""));
        assert_eq!(r.observed.lock().unwrap().confirmed_at, now + 30);
        // No re-registration while the session is fresh.
        assert_eq!(mock.requests_to("/api/cdn/node/register/").len(), 2);
        drop(r.dir);
    }

    #[test]
    fn an_older_generation_cert_is_never_adopted() {
        let key = NodeKey::derive(&[7u8; 32]);
        let mock = MockBackend::start(|_| Reply::status(503));
        let mut r = rig(&mock);
        let now = unix_now();
        let g3 = r
            .worker
            .verify_cert(&node_cert_pem(&key, SAN, 7), now)
            .unwrap();
        let g2_pem = node_cert_pem(&key, "spiffe://hippius.network/cdn/FR/cdn-fr-7k2m/g2", 7);
        r.worker.install_cert(g3);
        r.worker.consider_cert(&g2_pem, now);
        assert_eq!(r.worker.cert.as_ref().unwrap().generation, 3);
    }

    #[test]
    fn a_cert_for_another_key_is_never_registered() {
        let other = NodeKey::derive(&[8u8; 32]);
        let mock = happy_backend(node_cert_pem(&other, SAN, 7), snapshot(10));
        let mut r = rig(&mock);
        assert_eq!(
            r.worker.step(unix_now()).unwrap_err().class(),
            "node-cert-key-mismatch"
        );
        assert!(mock.requests_to("/api/cdn/node/register/").is_empty());
    }

    #[test]
    fn a_running_node_survives_a_backend_outage_for_the_lkg_window() {
        let key = NodeKey::derive(&[7u8; 32]);
        let down = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let mock = happy_backend_until(
            node_cert_pem(&key, SAN, 7),
            snapshot_with_wildcard(10),
            Arc::clone(&down),
        );
        let mut r = rig(&mock);
        let now = unix_now();
        r.worker.step(now).unwrap();
        down.store(true, Ordering::SeqCst);
        assert!(r.worker.step(now + 60).is_err());

        let o = r.observed.lock().unwrap().clone();
        assert_eq!(
            (o.applied_revision, o.confirmed_at, o.pending_since),
            (10, now, None)
        );
        let t = Config::from_strs(crate::config::tests::UID, NODE)
            .unwrap()
            .timing;
        assert!(health::evaluate(&o, true, now + 23 * 3_600, &t).feed_fresh);
        assert!(!health::evaluate(&o, true, now + 25 * 3_600, &t).feed_fresh);
    }

    #[test]
    fn a_booting_node_serves_its_lkg_but_is_not_ready_until_the_backend_answers() {
        let key = NodeKey::derive(&[7u8; 32]);
        let mock = happy_backend(node_cert_pem(&key, SAN, 7), snapshot_with_wildcard(10));
        let mut r = rig(&mock);
        let now = unix_now();
        r.worker.step(now).unwrap();
        let lkg = std::fs::read(&r.paths.lkg).unwrap();

        let dead = MockBackend::start(|_| Reply::status(503));
        let mut r2 = rig(&dead);
        std::fs::write(&r2.paths.lkg, &lkg).unwrap();
        let (state, _) = feed::load_lkg(&r2.paths.lkg, now + 60, 86_400)
            .unwrap()
            .unwrap();
        r2.worker.adopt_lkg(state);
        assert!(r2.worker.step(now + 60).is_err());
        assert_eq!(r2.control.last("/v1/config").unwrap()["revision"], 10);
        let o = r2.observed.lock().unwrap().clone();
        assert_eq!(o.applied_revision, 10);
        let t = Config::from_strs(crate::config::tests::UID, NODE)
            .unwrap()
            .timing;
        assert!(!health::evaluate(&o, true, now + 61, &t).feed_fresh);
    }

    #[test]
    fn a_bad_delta_marks_pending_and_asks_for_a_snapshot() {
        let key = NodeKey::derive(&[7u8; 32]);
        let cert = node_cert_pem(&key, SAN, 7);
        let polls = Arc::new(AtomicU64::new(0));
        let p2 = Arc::clone(&polls);
        let snap = snapshot_with_wildcard(10).to_string();
        let mock = MockBackend::start(move |req: &Request| match req.target.as_str() {
            t if t.starts_with("/api/cdn/node/cert/") => {
                Reply::json(200, &json!({"cert_pem": cert}).to_string())
            }
            "/api/cdn/node/register/challenge/" => Reply::json(
                200,
                &json!({"challenge_b64": B64.encode([5u8; 32]), "expires_at": "x"}).to_string(),
            ),
            "/api/cdn/node/register/" => Reply::json(
                200,
                &json!({"session_token": "s", "expires_at": format_rfc3339(unix_now() + 3600)})
                    .to_string(),
            ),
            t if t.starts_with("/api/cdn/node/feed/") => {
                if p2.fetch_add(1, Ordering::SeqCst) == 1 {
                    Reply::json(
                        200,
                        r#"{"revision":11,"mode":"delta","self":{},
                            "hostnames":[{"hostname_id":"hx","hostname":"x.example.com","zone_id":"ghost"}]}"#,
                    )
                } else {
                    Reply::json(200, &snap)
                }
            }
            _ => Reply::status(204),
        });
        let mut r = rig(&mock);
        let now = unix_now();
        r.worker.step(now).unwrap();
        assert_eq!(
            r.worker.step(now + 1).unwrap_err().class(),
            "hostname-zone-unknown"
        );
        assert_eq!(r.observed.lock().unwrap().pending_since, Some(now + 1));
        assert_eq!(r.worker.applied_revision(), 10, "nothing half-applied");
        r.worker.step(now + 2).unwrap();
        let feeds = mock.requests_to("/api/cdn/node/feed/");
        assert_eq!(feeds[2].target, "/api/cdn/node/feed/", "snapshot requested");
        assert!(feeds[2].header("if-none-match").is_none());
    }

    #[test]
    fn unauthorized_drops_the_session_and_re_registers() {
        let key = NodeKey::derive(&[7u8; 32]);
        let cert = node_cert_pem(&key, SAN, 7);
        let feeds = Arc::new(AtomicU64::new(0));
        let f2 = Arc::clone(&feeds);
        let snap = snapshot_with_wildcard(10).to_string();
        let mock = MockBackend::start(move |req: &Request| match req.target.as_str() {
            t if t.starts_with("/api/cdn/node/cert/") => {
                Reply::json(200, &json!({"cert_pem": cert}).to_string())
            }
            "/api/cdn/node/register/challenge/" => Reply::json(
                200,
                &json!({"challenge_b64": B64.encode([5u8; 32]), "expires_at": "x"}).to_string(),
            ),
            "/api/cdn/node/register/" => Reply::json(
                200,
                &json!({"session_token": "s", "expires_at": format_rfc3339(unix_now() + 3600)})
                    .to_string(),
            ),
            t if t.starts_with("/api/cdn/node/feed/") => {
                if f2.fetch_add(1, Ordering::SeqCst) == 0 {
                    Reply::json(401, r#"{"code":"session-expired"}"#)
                } else {
                    Reply::json(200, &snap)
                }
            }
            _ => Reply::status(204),
        });
        let mut r = rig(&mock);
        let now = unix_now();
        assert!(matches!(
            r.worker.step(now).unwrap_err(),
            CdnError::Unauthorized
        ));
        r.worker.step(now + 1).unwrap();
        assert_eq!(
            mock.requests_to("/api/cdn/node/register/challenge/").len(),
            2
        );
        assert_eq!(r.worker.applied_revision(), 10);
    }

    #[test]
    fn registration_disabled_at_the_backend_is_retried_not_fatal() {
        let key = NodeKey::derive(&[7u8; 32]);
        let cert = node_cert_pem(&key, SAN, 7);
        let snap = snapshot_with_wildcard(10).to_string();
        let enabled = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let e2 = Arc::clone(&enabled);
        let mock = MockBackend::start(move |req: &Request| {
            match req.target.as_str() {
            t if t.starts_with("/api/cdn/node/cert/") => {
                Reply::json(200, &json!({"cert_pem": cert}).to_string())
            }
            "/api/cdn/node/register/challenge/" => Reply::json(
                200,
                &json!({"challenge_b64": B64.encode([5u8; 32]), "expires_at": "x"}).to_string(),
            ),
            "/api/cdn/node/register/" if !e2.load(Ordering::SeqCst) => {
                Reply::json(503, r#"{"code":"cert-auth-disabled"}"#)
            }
            "/api/cdn/node/register/" => Reply::json(
                200,
                &json!({"session_token": "s", "session_token_id": "sess_1", "expires_at": format_rfc3339(unix_now() + 3600)})
                    .to_string(),
            ),
            t if t.starts_with("/api/cdn/node/feed/") => Reply::json(200, &snap),
            _ => Reply::status(404),
        }
        });
        let mut r = rig(&mock);
        let now = unix_now();
        assert!(matches!(
            r.worker.step(now).unwrap_err(),
            CdnError::BackendStatus(503)
        ));
        enabled.store(true, Ordering::SeqCst);
        r.worker.step(now + 60).unwrap();
        assert_eq!(r.worker.applied_revision(), 10);
        assert_eq!(
            mock.requests_to("/api/cdn/node/register/challenge/").len(),
            2
        );
    }

    #[test]
    fn a_refused_usage_post_fails_the_round_so_it_backs_off() {
        let key = NodeKey::derive(&[7u8; 32]);
        let cert = node_cert_pem(&key, SAN, 7);
        let snap = snapshot_with_wildcard(10).to_string();
        let mock = MockBackend::start(move |req: &Request| match req.target.as_str() {
            t if t.starts_with("/api/cdn/node/cert/") => {
                Reply::json(200, &json!({"cert_pem": cert}).to_string())
            }
            "/api/cdn/node/register/challenge/" => Reply::json(
                200,
                &json!({"challenge_b64": B64.encode([5u8; 32]), "expires_at": "x"}).to_string(),
            ),
            "/api/cdn/node/register/" => Reply::json(
                200,
                &json!({"session_token": "s", "expires_at": format_rfc3339(unix_now() + 3600)})
                    .to_string(),
            ),
            t if t.starts_with("/api/cdn/node/feed/") => Reply::json(200, &snap),
            "/api/cdn/node/usage/" => Reply::json(401, r#"{"code":"node-signature-invalid"}"#),
            _ => Reply::status(404),
        });
        let mut r = rig(&mock);
        let mut q = UsageQueue::open(r.paths.usage_queue.clone(), 10).unwrap();
        q.enqueue(&Counters::fresh().final_report("cdn-fr-7k2m", "t".into(), 0, "db"))
            .unwrap();
        // The feed round succeeded, but the 401 on usage dropped the
        // session: the step reports the failure (the loop backs off).
        assert!(matches!(
            r.worker.step(unix_now()).unwrap_err(),
            CdnError::Unauthorized
        ));
        assert_eq!(r.worker.applied_revision(), 10);
        assert_eq!(mock.requests_to("/api/cdn/node/usage/").len(), 1);
    }

    #[test]
    fn ticker_checkpoints_persist_then_queue_and_pushes_health() {
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = Config::from_strs(crate::config::tests::UID, NODE).unwrap();
        cfg.paths.state_dir = dir.path().to_path_buf();
        cfg.paths.data_mount = PathBuf::from("/proc");
        let paths = StatePaths::new(dir.path());
        let counters = Arc::new(Mutex::new(Counters::fresh()));
        let control = Arc::new(RecordingControl::default());
        let observed = Arc::new(Mutex::new(Observed {
            applied_revision: 4,
            ..Observed::default()
        }));
        let mut t = LocalTicker::new(
            cfg,
            Arc::clone(&counters),
            &paths,
            control.clone(),
            Arc::clone(&observed),
            "dbip-test".into(),
            1_000,
        )
        .unwrap();

        t.tick(1_000).unwrap();
        let h = control.last("/v1/health").unwrap();
        assert_eq!(h["volume_mounted"], true);
        assert_eq!(h["ready"], false);
        assert!(!paths.counters.exists(), "nothing due yet");

        t.tick(1_010).unwrap();
        assert!(paths.counters.exists());

        t.tick(1_060).unwrap();
        let queued = t.queue.pending().unwrap();
        assert_eq!(queued.len(), 1);
        let report: UsageReport =
            serde_json::from_slice(&std::fs::read(&queued[0]).unwrap()).unwrap();
        assert_eq!(report.seq, 1);
        assert_eq!(report.applied_revision, 4);
        assert_eq!(report.geoip_db, "dbip-test");
        // The persisted counters already carry seq 1.
        let on_disk: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&paths.counters).unwrap()).unwrap();
        assert_eq!(on_disk["seq"], 1);

        // A 409 on the health push asks the feed worker to resync.
        *control.fail_with.lock().unwrap() = Some(RESYNC_REQUIRED);
        t.tick(1_070).unwrap();
        assert!(observed.lock().unwrap().resync_needed);
    }

    #[test]
    fn poll_pacing() {
        let s = Duration::from_secs;
        assert_eq!(poll_delay(Pace::AfterUpdate, 200), s(1));
        // 304: 5 s ± 20 %.
        assert_eq!(poll_delay(Pace::Idle { retry_after: None }, 0), s(5));
        assert_eq!(poll_delay(Pace::Idle { retry_after: None }, -200), s(4));
        assert_eq!(poll_delay(Pace::Idle { retry_after: None }, 200), s(6));
        assert_eq!(
            poll_delay(Pace::Idle { retry_after: None }, 9_999),
            s(6),
            "jitter is clamped"
        );
        // A server Retry-After is a floor, never cut by jitter.
        assert_eq!(
            poll_delay(
                Pace::Idle {
                    retry_after: Some(30)
                },
                -200
            ),
            s(30)
        );
        assert_eq!(
            poll_delay(
                Pace::Idle {
                    retry_after: Some(2)
                },
                0
            ),
            s(5)
        );
        // Errors: 5, 10, 20, 40, 60, 60 … (± jitter), Retry-After wins above.
        let err = |n, ra| {
            poll_delay(
                Pace::Error {
                    failures: n,
                    retry_after: ra,
                },
                0,
            )
        };
        let got: Vec<u64> = (1..=7).map(|n| err(n, None).as_secs()).collect();
        assert_eq!(got, vec![5, 10, 20, 40, 60, 60, 60]);
        assert_eq!(err(1, Some(120)), s(120));
        assert_eq!(err(40, None), s(60));
        for _ in 0..200 {
            let j = jitter_permille();
            assert!((-200..=200).contains(&j));
        }
    }

    #[test]
    fn a_304_paces_as_idle_and_an_update_as_updated() {
        let key = NodeKey::derive(&[7u8; 32]);
        let mock = happy_backend(node_cert_pem(&key, SAN, 7), snapshot_with_wildcard(10));
        let mut r = rig(&mock);
        let now = unix_now();
        assert_eq!(r.worker.step(now).unwrap(), Poll::Updated);
        assert_eq!(
            r.worker.step(now + 5).unwrap(),
            Poll::Idle { retry_after: None }
        );
    }

    #[test]
    fn geoip_version_is_sanitised() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("v");
        std::fs::write(&p, "dbip-country-lite-2026-10\n").unwrap();
        assert_eq!(read_geoip_version(Some(&p)), "dbip-country-lite-2026-10");
        std::fs::write(&p, "bad value; rm").unwrap();
        assert_eq!(read_geoip_version(Some(&p)), "invalid");
        assert_eq!(read_geoip_version(None), "none");
        assert_eq!(read_geoip_version(Some(&dir.path().join("x"))), "missing");
    }
}
