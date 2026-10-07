//! Certificate issuance and renewal (CDN plan I4, spec §8.4, contract
//! §C.6).
//!
//! **What needs a certificate:** the fleet wildcard (`hostname_id`
//! `fleet`, which also covers `health.<domain>` for the backend's probe)
//! and every served custom hostname the wildcard does not cover. One is
//! due when the feed carries no valid certificate for it, or when two
//! thirds of its lifetime have passed (plus a per-certificate jitter).
//!
//! **Who issues:** any node may try; the backend's 10-minute lease makes
//! one node at a time the issuer of a name, and a refused lease backs off
//! (the certificate then arrives through the feed). A custom hostname is
//! tried first by nodes of its zone's shield region; the others step in
//! only when it is missing for a while or overdue. Just before finalizing,
//! the feed is checked again: a certificate that appeared meanwhile (from
//! another node) ends the job without ordering a duplicate.
//!
//! **How:** an ACME order with DNS-01. The backend writes the TXT value
//! (`acme/dns01/`, re-posted until INSYNC), then the CA validates, the
//! order is finalized with a fresh P-256 key generated in RAM, and the
//! chain is checked (exactly the name, the key's own) before the key is
//! sealed to the active fleet key and uploaded (`certs/`). The fleet key
//! sealed to is the one this node holds from the KBS, never a public key
//! taken from the feed alone. A certificate issued but not uploaded is
//! kept (in RAM) and uploaded again later instead of being ordered again:
//! CAs limit duplicate certificates per name and week, across accounts.
//! An abandoned order gives its pending authorization back to the CA.
//!
//! **Keys:** neither the account key nor a certificate key leaves the
//! agent unsealed or is ever written to disk. The PKCS#8 copies are wiped
//! on drop; `ring` keeps its own copy of the scalar, which it does not
//! wipe.
//!
//! **One exchange per tick:** [`Issuer::tick`] runs on the feed thread
//! and makes at most one CA exchange (account creation: three) plus the
//! lease renewal, with short timeouts, so issuance never stalls the feed
//! loop for long.
//!
//! **CAs:** Let's Encrypt first. After a CA rate limit, or two CA-side
//! failures in a row, the next attempt goes to Google Trust Services (only
//! with the external account binding from the node identity), and the one
//! after that back to Let's Encrypt: a broken fallback never pins a name.
//! An external account binding registers one account, so it must be
//! minted per node (nodes do not survive a reboot). Each CA's account
//! lives in RAM for the agent's lifetime, re-registered if the CA forgets
//! it.

use std::collections::BTreeMap;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};

use crate::acme::{AcmeClient, Order, Refusal, RATE_LIMITED};
use crate::backend::BackendClient;
use crate::certstore::check_leaf;
use crate::clock::format_rfc3339;
use crate::config::AcmeConfig;
use crate::csr::CertKey;
use crate::error::{CdnError, Result};
use crate::feed::FeedState;
use crate::hostname::{is_valid_hostname, san_covers};
use crate::reqsign::NodeAuth;
use crate::unseal::FleetKeyring;
use crate::wire::{CertUpload, Dns01Request, FleetKeyState};

const LOG: &str = "hippius-cdn-agent";
/// The fleet wildcard's `hostname_id` (contract §C.6).
pub const FLEET_ID: &str = "fleet";
/// The backend lease lasts 10 minutes; a job that has not finished in
/// this long is abandoned.
const JOB_DEADLINE_S: u64 = 9 * 60;
/// Re-ask the lease (which renews it) this often while a job runs.
const LEASE_RENEW_S: u64 = 4 * 60;
/// After a successful upload, wait this long for the feed to carry the
/// certificate before considering the name again.
const AFTER_UPLOAD_S: u64 = 15 * 60;
/// Another node holds the lease: look again after this (± jitter).
const LEASE_HELD_S: u64 = 3 * 60;
/// The backend's DNS-01 writes are off (503 `dns01-disabled`). Long: every
/// attempt costs the CA an order.
const DNS01_DISABLED_S: u64 = 60 * 60;
/// Non-shield nodes wait this long for a missing certificate.
const NON_SHIELD_GRACE_S: u64 = 30 * 60;
/// Failure back-off: 1 min doubling to 1 h.
const BACKOFF_MIN_S: u64 = 60;
const BACKOFF_MAX_S: u64 = 3600;
/// CA-side failures in a row before an attempt goes to the fallback.
const FALLBACK_AFTER: u32 = 2;

/// A name to certify.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Target {
    hostname_id: String,
    /// The order's identifier (`*.cdn.hippius.com` for the fleet).
    name: String,
    /// The one DNS-01 name the lease allows.
    dns01_name: String,
}

/// A certificate this node obtained: its key (RAM only) and chain.
struct Issued {
    key: CertKey,
    chain: String,
    not_before: u64,
    not_after: u64,
}

impl Issued {
    /// Still worth uploading: valid, and before its own renewal point.
    fn useful(&self, now: u64) -> bool {
        let lifetime = self.not_after.saturating_sub(self.not_before);
        now >= self.not_before && now < self.not_before + lifetime * 2 / 3
    }
}

#[derive(Default)]
struct Plan {
    /// Do not start a job before this.
    not_before: u64,
    /// CA-side failures in a row (they decide the fallback).
    ca_failures: u32,
    /// Backend or upload failures in a row.
    other_failures: u32,
    /// The last CA failure was a rate limit.
    rate_limited: bool,
    /// The CA of the last attempt.
    last_ca: usize,
    /// When this node first saw the name without a certificate.
    missing_since: Option<u64>,
    /// The renewal jitter chosen for the certificate expiring at `.0`.
    jitter: Option<(u64, i64)>,
    /// Issued, not yet uploaded.
    issued: Option<Issued>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stage {
    Lease,
    Account,
    Order,
    Authz,
    Dns01,
    Validate,
    AwaitReady,
    Finalize,
    AwaitValid,
    Download,
    Upload,
}

struct Job {
    target: Target,
    ca: usize,
    stage: Stage,
    started_at: u64,
    /// The feed certificate's `not_after` when the job started.
    feed_not_after: Option<u64>,
    lease_id: Option<String>,
    lease_at: u64,
    order_url: Option<String>,
    order: Option<Order>,
    authz_url: Option<String>,
    challenge_url: Option<String>,
    dns01_value: Option<String>,
    key: Option<CertKey>,
    issued: Option<Issued>,
    /// The job reached the CA (past the account stage).
    ca_used: bool,
}

/// Why a job ended without an upload.
enum Abort {
    /// The CA refused or failed: counts toward the fallback.
    Ca(&'static str),
    /// The backend, the upload or a local check failed.
    Other(&'static str),
    /// Retry after exactly this long (another node, the backend gate, a
    /// certificate that arrived meanwhile).
    Wait(u64, &'static str),
}

/// The issuer (see module docs).
pub struct Issuer {
    cfg: AcmeConfig,
    fleet_wildcard: String,
    domain: String,
    region: String,
    /// `[primary, fallback]`, created on first use.
    cas: Vec<Option<AcmeClient>>,
    /// The last CA refusal (account creation included).
    last_refusal: Option<Refusal>,
    plans: BTreeMap<String, Plan>,
    job: Option<Job>,
}

impl Issuer {
    /// `fleet_wildcard` is `*.<domain>`; `region` this node's region.
    pub fn new(mut cfg: AcmeConfig, fleet_wildcard: &str, region: &str) -> Result<Self> {
        let domain = fleet_wildcard
            .strip_prefix("*.")
            .filter(|d| is_valid_hostname(d))
            .map(str::to_string);
        let domain = match (domain, cfg.enabled) {
            (Some(d), _) => d,
            (None, true) => return Err(CdnError::Config("fleet-wildcard-not-a-wildcard")),
            (None, false) => String::new(),
        };
        if domain.is_empty() {
            cfg.enabled = false;
        }
        if cfg.enabled && cfg.fallback_eab.is_none() {
            // Without its binding the fallback CA cannot register: every
            // attempt stays on the primary, with the normal back-off.
            eprintln!("{LOG}: acme: no fallback CA binding, primary CA only");
        }
        Ok(Self {
            cfg,
            fleet_wildcard: fleet_wildcard.to_string(),
            domain,
            region: region.to_string(),
            cas: vec![None, None],
            last_refusal: None,
            plans: BTreeMap::new(),
            job: None,
        })
    }

    /// The `hostname_id` being issued, if any.
    pub fn busy_with(&self) -> Option<&str> {
        self.job.as_ref().map(|j| j.target.hostname_id.as_str())
    }

    /// Advance issuance by at most one exchange. `now` is the backend's
    /// clock; `keyring` the KBS-released fleet keys.
    pub fn tick(
        &mut self,
        now: u64,
        client: &BackendClient,
        auth: &NodeAuth<'_>,
        state: &FeedState,
        keyring: &FleetKeyring,
    ) {
        // A draining node is being replaced: it leaves issuance to others.
        if !self.cfg.enabled || state.is_empty() || state.self_state.draining {
            return;
        }
        if self.job.is_none() {
            let Some(target) = self.next_due(now, state) else {
                return;
            };
            self.job = Some(self.start(target, now, state));
        }
        let Some(mut job) = self.job.take() else {
            return;
        };
        if now.saturating_sub(job.started_at) > JOB_DEADLINE_S {
            self.finish(job, Err(Abort::Other("job-deadline")), now);
            return;
        }
        match self.step(&mut job, now, client, auth, state, keyring) {
            Ok(true) => self.finish(job, Ok(()), now),
            Ok(false) => self.job = Some(job),
            Err(abort) => self.finish(job, Err(abort), now),
        }
    }

    fn start(&mut self, target: Target, now: u64, state: &FeedState) -> Job {
        self.last_refusal = None;
        let plan = self.plans.entry(target.hostname_id.clone()).or_default();
        let issued = plan.issued.take().filter(|i| i.useful(now));
        let fallback_ok = self.cfg.fallback_eab.is_some();
        let ca = usize::from(
            fallback_ok
                && plan.last_ca == 0
                && (plan.rate_limited || plan.ca_failures >= FALLBACK_AFTER),
        );
        if issued.is_some() {
            eprintln!("{LOG}: acme: uploading again for {}", target.hostname_id);
        } else {
            eprintln!(
                "{LOG}: acme: issuing for {} ({})",
                target.hostname_id,
                if ca == 0 { "primary CA" } else { "fallback CA" }
            );
        }
        let feed_not_after = feed_cert(state, &target, now).map(|(_, na)| na);
        Job {
            target,
            ca,
            stage: Stage::Lease,
            started_at: now,
            feed_not_after,
            lease_id: None,
            lease_at: 0,
            order_url: None,
            order: None,
            authz_url: None,
            challenge_url: None,
            dns01_value: None,
            key: None,
            issued,
            ca_used: false,
        }
    }

    fn finish(&mut self, mut job: Job, outcome: std::result::Result<(), Abort>, now: u64) {
        // An order abandoned with its authorization pending gives it back,
        // so failed attempts never pile up at the CA.
        if outcome.is_err() && matches!(job.stage, Stage::Authz | Stage::Dns01 | Stage::Validate) {
            if let (Some(url), Some(Some(ca))) = (&job.authz_url, self.cas.get_mut(job.ca)) {
                if ca.deactivate(url).is_err() {
                    eprintln!("{LOG}: acme: could not deactivate an abandoned authorization");
                }
            }
        }
        let rate_limited = self
            .last_refusal
            .as_ref()
            .is_some_and(|r| r.problem.as_deref() == Some(RATE_LIMITED));
        let plan = self
            .plans
            .entry(job.target.hostname_id.clone())
            .or_default();
        // Only an attempt that reached the CA decides the next CA.
        if job.ca_used {
            plan.last_ca = job.ca;
        }
        let id = &job.target.hostname_id;
        match outcome {
            Ok(()) => {
                eprintln!("{LOG}: acme: certificate uploaded for {id}");
                plan.ca_failures = 0;
                plan.other_failures = 0;
                plan.rate_limited = false;
                plan.issued = None;
                plan.not_before = now + AFTER_UPLOAD_S;
                return;
            }
            Err(Abort::Wait(s, why)) => {
                eprintln!("{LOG}: acme: {id} waits: {why}");
                plan.not_before = now + jittered(s);
            }
            Err(Abort::Ca(why)) => {
                plan.ca_failures = plan.ca_failures.saturating_add(1);
                plan.rate_limited = rate_limited;
                plan.not_before = now + jittered(backoff(plan));
                eprintln!(
                    "{LOG}: acme: {id}: CA failure ({why}), attempt {}",
                    plan.ca_failures
                );
            }
            Err(Abort::Other(why)) => {
                plan.other_failures = plan.other_failures.saturating_add(1);
                plan.not_before = now + jittered(backoff(plan));
                eprintln!(
                    "{LOG}: acme: {id}: failed ({why}), attempt {}",
                    plan.other_failures
                );
            }
        }
        // Keep a certificate that was issued but not uploaded.
        if let Some(issued) = job.issued.take() {
            plan.issued = Some(issued);
        }
        // `job` drops here: an unused certificate key is wiped.
    }

    /// Every name this node should certify, in order: the fleet first.
    fn targets(&self, state: &FeedState) -> Vec<(Target, Option<String>)> {
        let mut out = vec![(
            Target {
                hostname_id: FLEET_ID.to_string(),
                name: self.fleet_wildcard.clone(),
                dns01_name: format!("_acme-challenge.{}", self.domain),
            },
            None,
        )];
        for h in state.hostnames.values() {
            if h.hostname_id == FLEET_ID
                || !is_valid_hostname(&h.hostname)
                || san_covers(&self.fleet_wildcard, &h.hostname)
                || h.hostname == self.domain
            {
                continue;
            }
            let shield = state
                .zones
                .get(&h.zone_id)
                .and_then(|z| z.shield_region.clone());
            out.push((
                Target {
                    hostname_id: h.hostname_id.clone(),
                    name: h.hostname.clone(),
                    dns01_name: format!("{}.dcv.{}", dcv_label(&h.hostname), self.domain),
                },
                shield,
            ));
        }
        out
    }

    fn next_due(&mut self, now: u64, state: &FeedState) -> Option<Target> {
        let targets = self.targets(state);
        // Forget names that left the feed.
        let live: std::collections::BTreeSet<&str> = targets
            .iter()
            .map(|(t, _)| t.hostname_id.as_str())
            .collect();
        self.plans.retain(|id, _| live.contains(id.as_str()));
        for (target, shield) in targets {
            let ours = shield.as_deref().is_none_or(|r| r == self.region);
            let held = feed_cert(state, &target, now);
            let plan = self.plans.entry(target.hostname_id.clone()).or_default();
            if now < plan.not_before {
                continue;
            }
            // A certificate in the feed newer than the one waiting for
            // upload makes the latter pointless.
            if let (Some(i), Some((_, na))) = (&plan.issued, held) {
                if na >= i.not_after {
                    plan.issued = None;
                }
            }
            if plan.issued.as_ref().is_some_and(|i| i.useful(now)) {
                return Some(target);
            }
            if is_due(plan, held, ours, now) {
                return Some(target);
            }
        }
        None
    }

    /// Run `f` on CA `idx` (registering the account first if needed). A
    /// failure records the refusal; an account the CA no longer knows is
    /// dropped so the next attempt registers a new one.
    fn with_ca<T>(
        &mut self,
        idx: usize,
        f: impl FnOnce(&mut AcmeClient) -> Result<T>,
    ) -> std::result::Result<T, Abort> {
        let Some(Some(ca)) = self.cas.get_mut(idx) else {
            return Err(Abort::Other("no-account"));
        };
        let (class, refusal, unusable) = match f(ca) {
            Ok(v) => {
                self.last_refusal = None;
                return Ok(v);
            }
            Err(e) => (e.class(), ca.last_refusal.clone(), ca.account_unusable()),
        };
        self.last_refusal = refusal;
        if unusable {
            self.cas[idx] = None;
        }
        Err(Abort::Ca(class))
    }

    /// [`Self::with_ca`] for the polling and download stages: a failure
    /// with no CA answer (transport, timeout) or a 5xx is `Ok(None)`, to be
    /// retried next tick within the job's deadline. Aborting there would
    /// throw away an order (after finalize: an issued certificate).
    fn poll_ca<T>(
        &mut self,
        idx: usize,
        f: impl FnOnce(&mut AcmeClient) -> Result<T>,
    ) -> std::result::Result<Option<T>, Abort> {
        match self.with_ca(idx, f) {
            Ok(v) => Ok(Some(v)),
            Err(Abort::Ca(class)) => {
                let transient = self.last_refusal.as_ref().is_none_or(|r| r.status >= 500);
                if transient && self.cas.get(idx).is_some_and(Option::is_some) {
                    eprintln!("{LOG}: acme: transient CA failure ({class}), retrying");
                    Ok(None)
                } else {
                    Err(Abort::Ca(class))
                }
            }
            Err(other) => Err(other),
        }
    }

    fn ensure_account(&mut self, idx: usize) -> std::result::Result<(), Abort> {
        if self.cas.get(idx).is_some_and(Option::is_some) {
            return Ok(());
        }
        let (dir, eab) = if idx == 0 {
            (self.cfg.directory.clone(), None)
        } else {
            (
                self.cfg.fallback_directory.clone(),
                self.cfg.fallback_eab.clone(),
            )
        };
        let mut c = AcmeClient::new(&dir).map_err(|e| Abort::Other(e.class()))?;
        if let Err(e) = c.ensure_account(self.cfg.contact.as_deref(), eab.as_ref()) {
            self.last_refusal = c.last_refusal.clone();
            return Err(Abort::Ca(e.class()));
        }
        eprintln!(
            "{LOG}: acme: account {} at {dir}",
            c.account_url().unwrap_or("-")
        );
        self.cas[idx] = Some(c);
        Ok(())
    }

    /// One exchange. `Ok(true)`: uploaded.
    fn step(
        &mut self,
        job: &mut Job,
        now: u64,
        client: &BackendClient,
        auth: &NodeAuth<'_>,
        state: &FeedState,
        keyring: &FleetKeyring,
    ) -> std::result::Result<bool, Abort> {
        let renew_lease =
            job.lease_id.is_some() && now.saturating_sub(job.lease_at) >= LEASE_RENEW_S;
        if job.stage == Stage::Lease || renew_lease {
            match client.acme_lease(auth, &job.target.hostname_id) {
                Ok(l) => {
                    job.lease_id = Some(l.lease_id);
                    job.lease_at = now;
                    if job.stage == Stage::Lease {
                        job.stage = if job.issued.is_some() {
                            Stage::Upload
                        } else {
                            Stage::Account
                        };
                    }
                    return Ok(false);
                }
                Err(CdnError::BackendStatus(409)) => {
                    return Err(Abort::Wait(LEASE_HELD_S, "lease held by another node"))
                }
                Err(CdnError::BackendStatus(404)) => {
                    return Err(Abort::Wait(BACKOFF_MAX_S, "unknown hostname"))
                }
                Err(e) => return Err(Abort::Other(e.class())),
            }
        }
        match job.stage {
            Stage::Lease => Ok(false),
            Stage::Account => {
                job.ca_used = true;
                self.ensure_account(job.ca)?;
                job.stage = Stage::Order;
                Ok(false)
            }
            Stage::Order => {
                let name = job.target.name.clone();
                let (url, order) = self.with_ca(job.ca, |ca| ca.new_order(&[&name]))?;
                if order.status == "valid" {
                    // An existing order, finalized with a key we lack.
                    return Err(Abort::Ca("order-valid-without-our-key"));
                }
                job.authz_url = Some(
                    order
                        .authorizations
                        .first()
                        .cloned()
                        .ok_or(Abort::Ca("order-no-authorization"))?,
                );
                job.order_url = Some(url);
                job.order = Some(order);
                job.stage = Stage::Authz;
                Ok(false)
            }
            Stage::Authz => {
                let url = job.authz_url.clone().ok_or(Abort::Other("job-state"))?;
                let authz = self.with_ca(job.ca, |ca| ca.authorization(&url))?;
                match authz.status.as_str() {
                    "valid" => job.stage = Stage::AwaitReady,
                    "pending" => {
                        let ch = authz
                            .challenges
                            .iter()
                            .find(|c| c.kind == "dns-01")
                            .ok_or(Abort::Ca("no-dns01-challenge"))?;
                        let token = ch.token.clone().ok_or(Abort::Ca("no-token"))?;
                        if token.is_empty()
                            || token.len() > 128
                            || !token
                                .bytes()
                                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
                        {
                            return Err(Abort::Ca("bad-token"));
                        }
                        let value = self.with_ca(job.ca, |ca| Ok(ca.dns01_value(&token)))?;
                        job.dns01_value = Some(value);
                        job.challenge_url = Some(ch.url.clone());
                        job.stage = Stage::Dns01;
                    }
                    _ => return Err(Abort::Ca("authorization-not-pending")),
                }
                Ok(false)
            }
            Stage::Dns01 => {
                let (Some(lease_id), Some(value)) = (&job.lease_id, &job.dns01_value) else {
                    return Err(Abort::Other("job-state"));
                };
                let req = Dns01Request {
                    lease_id,
                    name: &job.target.dns01_name,
                    value,
                };
                match client.acme_dns01(auth, &req) {
                    Ok(r) if r.insync => {
                        let url = job.challenge_url.clone().ok_or(Abort::Other("job-state"))?;
                        self.with_ca(job.ca, |ca| ca.respond(&url))?;
                        job.stage = Stage::Validate;
                        Ok(false)
                    }
                    Ok(_) => Ok(false),
                    Err(CdnError::BackendStatus(503)) => {
                        Err(Abort::Wait(DNS01_DISABLED_S, "DNS-01 writes are off"))
                    }
                    Err(CdnError::BackendStatus(409)) => Err(Abort::Other("lease-not-held")),
                    Err(e) => Err(Abort::Other(e.class())),
                }
            }
            Stage::Validate => {
                let url = job.authz_url.clone().ok_or(Abort::Other("job-state"))?;
                let Some(authz) = self.poll_ca(job.ca, |ca| ca.authorization(&url))? else {
                    return Ok(false);
                };
                match authz.status.as_str() {
                    "valid" => job.stage = Stage::AwaitReady,
                    "pending" | "processing" => {}
                    _ => return Err(Abort::Ca("authorization-invalid")),
                }
                Ok(false)
            }
            Stage::AwaitReady => {
                let url = job.order_url.clone().ok_or(Abort::Other("job-state"))?;
                let Some(order) = self.poll_ca(job.ca, |ca| ca.order(&url))? else {
                    return Ok(false);
                };
                match order.status.as_str() {
                    "ready" => job.stage = Stage::Finalize,
                    "pending" | "processing" => {}
                    "valid" => return Err(Abort::Ca("order-valid-without-our-key")),
                    _ => return Err(Abort::Ca("order-invalid")),
                }
                job.order = Some(order);
                Ok(false)
            }
            Stage::Finalize => {
                // Another node's certificate may have reached the feed
                // since this job started: do not issue a duplicate.
                let now_held = feed_cert(state, &job.target, now).map(|(_, na)| na);
                if now_held.is_some_and(|na| job.feed_not_after.is_none_or(|was| na > was)) {
                    return Err(Abort::Wait(
                        AFTER_UPLOAD_S,
                        "a certificate arrived meanwhile",
                    ));
                }
                let finalize = job
                    .order
                    .as_ref()
                    .map(|o| o.finalize.clone())
                    .ok_or(Abort::Other("job-state"))?;
                let key = CertKey::generate().map_err(|e| Abort::Other(e.class()))?;
                let csr = key
                    .csr_der(&[&job.target.name])
                    .map_err(|e| Abort::Other(e.class()))?;
                let order = self.with_ca(job.ca, |ca| ca.finalize(&finalize, &csr))?;
                job.key = Some(key);
                job.stage = if order.status == "valid" && order.certificate.is_some() {
                    Stage::Download
                } else {
                    Stage::AwaitValid
                };
                job.order = Some(order);
                Ok(false)
            }
            Stage::AwaitValid => {
                let url = job.order_url.clone().ok_or(Abort::Other("job-state"))?;
                let Some(order) = self.poll_ca(job.ca, |ca| ca.order(&url))? else {
                    return Ok(false);
                };
                match order.status.as_str() {
                    "valid" if order.certificate.is_some() => job.stage = Stage::Download,
                    "processing" | "ready" | "valid" => {}
                    _ => return Err(Abort::Ca("order-invalid")),
                }
                job.order = Some(order);
                Ok(false)
            }
            Stage::Download => {
                let url = job
                    .order
                    .as_ref()
                    .and_then(|o| o.certificate.clone())
                    .ok_or(Abort::Other("job-state"))?;
                let Some(chain) = self.poll_ca(job.ca, |ca| ca.certificate(&url))? else {
                    return Ok(false);
                };
                let key = job.key.take().ok_or(Abort::Other("job-state"))?;
                let leaf = check_leaf(&chain, &job.target.name, now)
                    .map_err(|_| Abort::Ca("chain-leaf"))?;
                // Exactly the ordered name (the backend refuses anything
                // else), and our own key.
                if leaf.dns_names != [job.target.name.clone()] {
                    return Err(Abort::Ca("chain-names"));
                }
                if leaf.spki_der != key.spki_der() {
                    return Err(Abort::Ca("chain-key-mismatch"));
                }
                job.issued = Some(Issued {
                    key,
                    chain,
                    not_before: leaf.not_before,
                    not_after: leaf.not_after,
                });
                job.stage = Stage::Upload;
                Ok(false)
            }
            Stage::Upload => {
                let issued = job.issued.as_ref().ok_or(Abort::Other("job-state"))?;
                upload(&job.target, issued, client, auth, state, keyring)
                    .map_err(|e| Abort::Other(e.class()))?;
                Ok(true)
            }
        }
    }
}

/// The feed's valid certificate for `target`: `(not_before, not_after)`.
fn feed_cert(state: &FeedState, target: &Target, now: u64) -> Option<(u64, u64)> {
    state.certs.get(&target.hostname_id).and_then(|c| {
        check_leaf(&c.cert_chain_pem, &target.name, now)
            .ok()
            .map(|leaf| (leaf.not_before, leaf.not_after))
    })
}

/// Whether `target` needs a new certificate (see module docs).
fn is_due(plan: &mut Plan, held: Option<(u64, u64)>, ours: bool, now: u64) -> bool {
    match held {
        None => {
            let since = *plan.missing_since.get_or_insert(now);
            ours || now.saturating_sub(since) >= NON_SHIELD_GRACE_S
        }
        Some((nb, na)) => {
            plan.missing_since = None;
            let lifetime = na.saturating_sub(nb).max(1);
            let jitter = match plan.jitter {
                Some((at, j)) if at == na => j,
                _ => {
                    let j = renewal_jitter(lifetime);
                    plan.jitter = Some((na, j));
                    j
                }
            };
            let renew_at = shift(nb + lifetime * 2 / 3, jitter);
            let overdue = renew_at + lifetime / 12;
            now >= renew_at && (ours || now >= overdue)
        }
    }
}

fn backoff(plan: &Plan) -> u64 {
    let n = plan
        .ca_failures
        .saturating_add(plan.other_failures)
        .clamp(1, 13);
    BACKOFF_MIN_S
        .saturating_mul(1 << (n - 1))
        .min(BACKOFF_MAX_S)
}

/// Seal the key to the active fleet key this node holds and upload.
fn upload(
    target: &Target,
    issued: &Issued,
    client: &BackendClient,
    auth: &NodeAuth<'_>,
    state: &FeedState,
    keyring: &FleetKeyring,
) -> Result<()> {
    let (version, public) = active_fleet_key(state, keyring)?;
    let pem = issued.key.pkcs8_pem();
    let sealed = B64.encode(crate::unseal::seal_to(&public, pem.as_bytes())?);
    let not_after = format_rfc3339(issued.not_after);
    client.upload_cert(
        auth,
        &CertUpload {
            hostname_id: &target.hostname_id,
            sealed_blob_b64: &sealed,
            fleet_key_version: version,
            cert_chain_pem: &issued.chain,
            not_after: &not_after,
        },
    )
}

/// The newest fleet key that vali marks `active` and that this node holds.
/// The public half comes from the node's own keyring; a different one in
/// the feed is refused rather than sealed to.
fn active_fleet_key(state: &FeedState, keyring: &FleetKeyring) -> Result<(u32, [u8; 32])> {
    let mut best: Option<(u32, [u8; 32])> = None;
    for k in &state.fleet_key_versions {
        if k.state != FleetKeyState::Active {
            continue;
        }
        let Some(public) = keyring.public_key(k.version) else {
            continue;
        };
        if let Some(published) = &k.x25519_public_b64 {
            if B64.decode(published).ok().as_deref() != Some(public.as_slice()) {
                return Err(CdnError::Acme("fleet-public-key-mismatch"));
            }
        }
        if best.is_none_or(|(v, _)| k.version > v) {
            best = Some((k.version, public));
        }
    }
    best.ok_or(CdnError::Acme("no-active-fleet-key"))
}

/// `base32(sha256(hostname))[:16]`, lower-case (contract §C.6).
pub fn dcv_label(hostname: &str) -> String {
    const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
    let digest = Sha256::digest(hostname.as_bytes());
    let mut out = String::with_capacity(16);
    let mut buffer: u32 = 0;
    let mut bits = 0;
    for byte in digest.iter() {
        buffer = (buffer << 8) | u32::from(*byte);
        bits += 8;
        while bits >= 5 && out.len() < 16 {
            bits -= 5;
            out.push(char::from(ALPHABET[((buffer >> bits) & 31) as usize]));
        }
        if out.len() == 16 {
            break;
        }
    }
    out
}

/// ± `lifetime / 30`, uniformly.
fn renewal_jitter(lifetime: u64) -> i64 {
    let span = i64::try_from(lifetime / 30).unwrap_or(0);
    if span == 0 {
        return 0;
    }
    let r = i64::from(OsRng.next_u32()) % (2 * span + 1);
    r - span
}

fn shift(t: u64, by: i64) -> u64 {
    u64::try_from(i128::from(t) + i128::from(by)).unwrap_or(0)
}

/// ± 20 %.
fn jittered(s: u64) -> u64 {
    let span = s / 5;
    if span == 0 {
        return s;
    }
    s - span + u64::from(OsRng.next_u32()) % (2 * span + 1)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::config::{BackendConfig, BackendUrl};
    use crate::fake_ca::FakeCa;
    use crate::identity::NodeKey;
    use crate::test_support::{MockBackend, Reply};
    use crate::unseal::FleetKeyring;
    use crate::wire::{FleetKeyVersion, Hostname, SessionToken, Zone};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use zeroize::Zeroizing;

    const FLEET_SECRET: [u8; 32] = [9u8; 32];

    fn keyring() -> FleetKeyring {
        FleetKeyring::from_secrets([(1, FLEET_SECRET)])
    }

    fn state() -> FeedState {
        let mut s = FeedState {
            revision: 5,
            ..FeedState::default()
        };
        s.fleet_key_versions = vec![FleetKeyVersion {
            version: 1,
            state: FleetKeyState::Active,
            x25519_public_b64: Some(B64.encode(keyring().public_key(1).unwrap())),
        }];
        s
    }

    fn acme_cfg(ca: &FakeCa) -> AcmeConfig {
        AcmeConfig {
            enabled: true,
            directory: ca.directory_url(),
            fallback_directory: ca.directory_url(),
            contact: None,
            fallback_eab: None,
        }
    }

    struct Backend {
        mock: MockBackend,
        uploads: Arc<Mutex<Vec<serde_json::Value>>>,
    }

    /// A backend that grants leases, says INSYNC on the second DNS-01
    /// post, and records uploads.
    fn backend(lease_status: u16, dns_status: u16) -> Backend {
        backend_with_uploads(lease_status, dns_status, 0)
    }

    /// … whose first `failing_uploads` uploads answer 500.
    fn backend_with_uploads(lease_status: u16, dns_status: u16, failing_uploads: usize) -> Backend {
        let uploads = Arc::new(Mutex::new(Vec::new()));
        let u2 = Arc::clone(&uploads);
        let dns_posts = Arc::new(AtomicUsize::new(0));
        let upload_posts = Arc::new(AtomicUsize::new(0));
        let mock = MockBackend::start(move |req| match req.target.as_str() {
            "/api/cdn/node/acme/lease/" if lease_status == 200 => Reply::json(
                200,
                r#"{"lease_id":"L1","expires_at":"2099-01-01T00:00:00Z"}"#,
            ),
            "/api/cdn/node/acme/lease/" => Reply::json(lease_status, r#"{"code":"lease-held"}"#),
            "/api/cdn/node/acme/dns01/" if dns_status == 200 => {
                let n = dns_posts.fetch_add(1, Ordering::SeqCst);
                Reply::json(
                    200,
                    &format!(r#"{{"change_id":"/change/C1","insync":{}}}"#, n >= 1),
                )
            }
            "/api/cdn/node/acme/dns01/" => Reply::json(dns_status, r#"{"code":"dns01-disabled"}"#),
            "/api/cdn/node/certs/" => {
                if upload_posts.fetch_add(1, Ordering::SeqCst) < failing_uploads {
                    return Reply::json(500, r#"{"code":"oops"}"#);
                }
                u2.lock().unwrap().push(req.json());
                Reply::status(204)
            }
            _ => Reply::status(404),
        });
        Backend { mock, uploads }
    }

    fn client(b: &Backend) -> BackendClient {
        BackendClient::new(&BackendConfig {
            url: BackendUrl::loopback_for_tests(b.mock.addr()),
            ca_bundle: None,
            request_signatures: true,
            request_timeout_s: 5,
            feed_poll_s: 1,
        })
        .unwrap()
    }

    fn run(issuer: &mut Issuer, b: &Backend, state: &FeedState, now: u64, ticks: usize) {
        let c = client(b);
        let key = NodeKey::derive(&[7u8; 32]);
        let tok = SessionToken::for_tests("t");
        let auth = NodeAuth {
            token: &tok,
            session_id: "s",
            node_id: "cdn-fr-7k2m",
            key: &key,
            sign: true,
        };
        for _ in 0..ticks {
            issuer.tick(now, &c, &auth, state, &keyring());
        }
    }

    #[test]
    fn the_fleet_wildcard_is_issued_sealed_and_uploaded() {
        let ca = FakeCa::start();
        let b = backend(200, 200);
        let mut issuer = Issuer::new(acme_cfg(&ca), "*.cdn.example.test", "FR").unwrap();
        let st = state();
        let now = crate::clock::unix_now();
        run(&mut issuer, &b, &st, now, 12);
        assert!(issuer.busy_with().is_none(), "the job finished");

        // DNS-01 at the fleet's name, with the key authorization digest.
        let dns = b.mock.requests_to("/api/cdn/node/acme/dns01/");
        assert_eq!(dns.len(), 2, "re-posted until INSYNC");
        let body = dns[0].json();
        assert_eq!(body["lease_id"], "L1");
        assert_eq!(body["name"], "_acme-challenge.cdn.example.test");
        assert_eq!(body["value"].as_str().unwrap().len(), 43);
        // The CA was told only after INSYNC.
        assert_eq!(ca.state.lock().unwrap().responded.len(), 1);

        let up = b.uploads.lock().unwrap()[0].clone();
        assert_eq!(up["hostname_id"], "fleet");
        assert_eq!(up["fleet_key_version"], 1);
        let chain = up["cert_chain_pem"].as_str().unwrap();
        let leaf = check_leaf(chain, "*.cdn.example.test", now).unwrap();
        assert_eq!(leaf.dns_names, vec!["*.cdn.example.test"]);
        assert_eq!(up["not_after"], format_rfc3339(leaf.not_after));
        // The sealed key opens with the fleet key and is the leaf's key.
        let pem = keyring()
            .open_b64(1, up["sealed_blob_b64"].as_str().unwrap())
            .unwrap();
        let sealed =
            crate::certstore::tests::sealed_from(chain, &pem, "fleet", "*.cdn.example.test");
        let store = crate::certstore::build(
            &{
                let mut s = st.clone();
                s.certs.insert("fleet".into(), sealed);
                s
            },
            &keyring(),
            "*.cdn.example.test",
            now,
        )
        .unwrap();
        assert_eq!(store.loaded, 1, "skipped: {:?}", store.skipped);
        // Every backend call was signed.
        for r in b.mock.requests() {
            assert!(
                r.header("x-hippius-node-signature").is_some(),
                "{}",
                r.target
            );
        }
    }

    #[test]
    fn a_held_lease_waits_without_touching_the_ca() {
        let ca = FakeCa::start();
        let b = backend(409, 200);
        let mut issuer = Issuer::new(acme_cfg(&ca), "*.cdn.example.test", "FR").unwrap();
        let now = crate::clock::unix_now();
        run(&mut issuer, &b, &state(), now, 5);
        assert_eq!(b.mock.requests_to("/api/cdn/node/acme/lease/").len(), 1);
        assert!(ca.mock.requests().is_empty());
        // Still waiting a minute later, retried after the hold.
        run(&mut issuer, &b, &state(), now + 60, 3);
        assert_eq!(b.mock.requests_to("/api/cdn/node/acme/lease/").len(), 1);
        run(&mut issuer, &b, &state(), now + LEASE_HELD_S * 2, 1);
        assert_eq!(b.mock.requests_to("/api/cdn/node/acme/lease/").len(), 2);
    }

    #[test]
    fn dns01_disabled_backs_off() {
        let ca = FakeCa::start();
        let b = backend(200, 503);
        let mut issuer = Issuer::new(acme_cfg(&ca), "*.cdn.example.test", "FR").unwrap();
        let now = crate::clock::unix_now();
        run(&mut issuer, &b, &state(), now, 6);
        assert_eq!(b.mock.requests_to("/api/cdn/node/acme/dns01/").len(), 1);
        assert!(issuer.busy_with().is_none());
        assert!(ca.state.lock().unwrap().responded.is_empty());
        run(&mut issuer, &b, &state(), now + 60, 6);
        assert_eq!(b.mock.requests_to("/api/cdn/node/acme/lease/").len(), 1);
    }

    #[test]
    fn a_rate_limit_moves_to_the_fallback_ca_with_its_binding() {
        let primary = FakeCa::start();
        primary.state.lock().unwrap().rate_limited = true;
        let fallback = FakeCa::start();
        let mac = b"0123456789abcdef0123456789abcdef".to_vec();
        fallback.state.lock().unwrap().eab = Some(("kid-9".into(), mac.clone()));
        let b = backend(200, 200);
        let mut cfg = acme_cfg(&primary);
        cfg.fallback_directory = fallback.directory_url();
        cfg.fallback_eab = Some(crate::acme::Eab {
            kid: "kid-9".into(),
            hmac_b64u: Zeroizing::new(
                base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&mac),
            ),
        });
        let mut issuer = Issuer::new(cfg, "*.cdn.example.test", "FR").unwrap();
        let now = crate::clock::unix_now();
        run(&mut issuer, &b, &state(), now, 4);
        assert!(b.uploads.lock().unwrap().is_empty());
        run(&mut issuer, &b, &state(), now + BACKOFF_MAX_S, 12);
        assert_eq!(b.uploads.lock().unwrap().len(), 1);
        assert_eq!(fallback.state.lock().unwrap().responded.len(), 1);
    }

    fn with_custom(shield: &str) -> FeedState {
        let mut s = state();
        s.zones.insert(
            "z1".into(),
            serde_json::from_value::<Zone>(serde_json::json!({
                "zone_id": "z1", "state": "active",
                "origin": {"type": "s3", "bucket": "b"},
                "shield_region": shield}))
            .unwrap(),
        );
        s.hostnames.insert(
            "h7".into(),
            Hostname {
                hostname_id: "h7".into(),
                hostname: "www.example.com".into(),
                zone_id: "z1".into(),
                needs_cert: false,
            },
        );
        // A default hostname, covered by the fleet wildcard.
        s.hostnames.insert(
            "h8".into(),
            Hostname {
                hostname_id: "h8".into(),
                hostname: "z1.cdn.example.test".into(),
                zone_id: "z1".into(),
                needs_cert: false,
            },
        );
        s
    }

    fn fresh_fleet_cert(s: &mut FeedState, days: i64) {
        let c = crate::certstore::tests::sealed_cert(
            "fleet",
            "*.cdn.example.test",
            &["*.cdn.example.test"],
            &keyring().public_key(1).unwrap(),
            1,
            days,
        );
        s.certs.insert("fleet".into(), c);
    }

    #[test]
    fn what_is_due_and_who_issues_it() {
        let ca = FakeCa::start();
        let mut issuer = Issuer::new(acme_cfg(&ca), "*.cdn.example.test", "FR").unwrap();
        let now = crate::clock::unix_now();
        // A fresh fleet certificate (1 h old, 90 days): nothing for it.
        let mut s = with_custom("FR");
        fresh_fleet_cert(&mut s, 90);
        let t = issuer.next_due(now, &s).unwrap();
        assert_eq!(
            t.hostname_id, "h7",
            "the custom name, not the covered default"
        );
        assert_eq!(t.dns01_name, "qd6a7ojgnw33qp4f.dcv.cdn.example.test");
        // Another region's shield: not before the grace period.
        let mut other = Issuer::new(acme_cfg(&ca), "*.cdn.example.test", "AU").unwrap();
        assert!(other.next_due(now, &s).is_none());
        assert_eq!(
            other
                .next_due(now + NON_SHIELD_GRACE_S, &s)
                .unwrap()
                .hostname_id,
            "h7"
        );
        // A fleet certificate two thirds through its life is due.
        let mut s2 = state();
        fresh_fleet_cert(&mut s2, 3);
        assert!(issuer.next_due(now, &s2).is_none());
        assert_eq!(
            issuer
                .next_due(now + 2 * 86_400 + 6 * 3600, &s2)
                .unwrap()
                .hostname_id,
            "fleet"
        );
    }

    #[test]
    fn a_hostname_waiting_for_its_first_certificate_is_issued() {
        let ca = FakeCa::start();
        let mut issuer = Issuer::new(acme_cfg(&ca), "*.cdn.example.test", "FR").unwrap();
        let mut s = with_custom("FR");
        fresh_fleet_cert(&mut s, 90);
        s.hostnames.get_mut("h7").unwrap().needs_cert = true;
        let t = issuer.next_due(crate::clock::unix_now(), &s).unwrap();
        assert_eq!(t.hostname_id, "h7");
        assert_eq!(t.name, "www.example.com");
    }

    #[test]
    fn draining_or_disabled_nodes_do_not_issue() {
        let ca = FakeCa::start();
        let b = backend(200, 200);
        let mut cfg = acme_cfg(&ca);
        cfg.enabled = false;
        let mut off = Issuer::new(cfg, "*.cdn.example.test", "FR").unwrap();
        run(&mut off, &b, &state(), crate::clock::unix_now(), 3);
        let mut draining = Issuer::new(acme_cfg(&ca), "*.cdn.example.test", "FR").unwrap();
        let mut s = state();
        s.self_state.draining = true;
        run(&mut draining, &b, &s, crate::clock::unix_now(), 3);
        assert!(b.mock.requests().is_empty());
    }

    #[test]
    fn a_failed_upload_keeps_the_certificate_and_never_orders_again() {
        let ca = FakeCa::start();
        let b = backend_with_uploads(200, 200, 1);
        let mut issuer = Issuer::new(acme_cfg(&ca), "*.cdn.example.test", "FR").unwrap();
        let now = crate::clock::unix_now();
        run(&mut issuer, &b, &state(), now, 12);
        assert!(b.uploads.lock().unwrap().is_empty());
        assert_eq!(ca.mock.requests_to("/order").len(), 1);
        // After the back-off: lease, then the same certificate, no order.
        run(&mut issuer, &b, &state(), now + 600, 3);
        assert_eq!(b.uploads.lock().unwrap().len(), 1);
        assert_eq!(ca.mock.requests_to("/order").len(), 1, "no second order");
        assert_eq!(ca.mock.requests_to("/finalize/").len(), 1);
    }

    #[test]
    fn a_feed_fleet_key_that_is_not_ours_is_never_sealed_to() {
        let ca = FakeCa::start();
        let b = backend(200, 200);
        let mut issuer = Issuer::new(acme_cfg(&ca), "*.cdn.example.test", "FR").unwrap();
        let mut st = state();
        st.fleet_key_versions[0].x25519_public_b64 = Some(B64.encode([1u8; 32]));
        run(&mut issuer, &b, &st, crate::clock::unix_now(), 12);
        assert!(b.uploads.lock().unwrap().is_empty());
        assert!(b.mock.requests_to("/api/cdn/node/certs/").is_empty());
        // A feed that omits the public half is fine: ours is used.
        st.fleet_key_versions[0].x25519_public_b64 = None;
        run(&mut issuer, &b, &st, crate::clock::unix_now() + 600, 3);
        assert_eq!(b.uploads.lock().unwrap().len(), 1);
    }

    #[test]
    fn a_certificate_arriving_before_finalize_stops_the_job() {
        let ca = FakeCa::start();
        let b = backend(200, 200);
        let mut issuer = Issuer::new(acme_cfg(&ca), "*.cdn.example.test", "FR").unwrap();
        let now = crate::clock::unix_now();
        run(&mut issuer, &b, &state(), now, 8);
        assert_eq!(issuer.busy_with(), Some("fleet"));
        let mut with_cert = state();
        fresh_fleet_cert(&mut with_cert, 90);
        run(&mut issuer, &b, &with_cert, now, 1);
        assert!(issuer.busy_with().is_none());
        assert!(
            ca.mock.requests_to("/finalize/").is_empty(),
            "no duplicate issued"
        );
    }

    #[test]
    fn an_abandoned_order_gives_its_authorization_back() {
        let ca = FakeCa::start();
        let b = backend(200, 503);
        let mut issuer = Issuer::new(acme_cfg(&ca), "*.cdn.example.test", "FR").unwrap();
        run(&mut issuer, &b, &state(), crate::clock::unix_now(), 6);
        assert_eq!(ca.state.lock().unwrap().deactivated, vec![1]);
    }

    #[test]
    fn a_failing_fallback_hands_back_to_the_primary() {
        let primary = FakeCa::start();
        primary.state.lock().unwrap().rate_limited = true;
        let fallback = FakeCa::start();
        fallback.state.lock().unwrap().rate_limited = true;
        let b = backend(200, 200);
        let mut cfg = acme_cfg(&primary);
        cfg.fallback_directory = fallback.directory_url();
        cfg.fallback_eab = Some(crate::acme::Eab {
            kid: "k".into(),
            hmac_b64u: Zeroizing::new("c2VjcmV0".into()),
        });
        let mut issuer = Issuer::new(cfg, "*.cdn.example.test", "FR").unwrap();
        let now = crate::clock::unix_now();
        for i in 0..3u64 {
            run(&mut issuer, &b, &state(), now + i * 2 * BACKOFF_MAX_S, 4);
        }
        assert_eq!(
            primary.mock.requests_to("/order").len(),
            2,
            "primary, fallback, primary"
        );
        assert_eq!(fallback.mock.requests_to("/order").len(), 1);
    }

    #[test]
    fn a_transient_ca_error_after_finalize_is_retried_not_reordered() {
        let ca = FakeCa::start();
        ca.state.lock().unwrap().cert_unavailable = 2;
        let b = backend(200, 200);
        let mut issuer = Issuer::new(acme_cfg(&ca), "*.cdn.example.test", "FR").unwrap();
        run(&mut issuer, &b, &state(), crate::clock::unix_now(), 14);
        assert_eq!(b.uploads.lock().unwrap().len(), 1);
        assert_eq!(ca.mock.requests_to("/order").len(), 1);
        assert_eq!(
            ca.mock.requests_to("/cert/").len(),
            3,
            "two 503s, then the chain"
        );
    }

    #[test]
    fn dcv_labels_match_the_backend() {
        assert_eq!(dcv_label("www.example.com"), "qd6a7ojgnw33qp4f");
        assert_eq!(dcv_label("*.shop.example.org"), "okatrax2wpeqijpm");
    }

    #[test]
    fn the_fleet_wildcard_must_be_a_wildcard() {
        let ca = FakeCa::start();
        assert!(Issuer::new(acme_cfg(&ca), "cdn.example.test", "FR").is_err());
    }
}
