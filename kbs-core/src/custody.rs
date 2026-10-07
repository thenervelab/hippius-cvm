//! Guest custody lease — the KBS side (wire contract:
//! `hippius_types::custody`).
//!
//! A running guest keeps its disk keys only while the KBS keeps renewing a
//! short lease. Three requests reach this module through the untrusted
//! miner's vsock relay:
//!
//! - [`process_bind`] — once per boot (and per daemon / KBS restart).
//!   Re-runs the release gates WITHOUT releasing anything and WITHOUT
//!   advancing the boot counter: OrderTicket signature (not its expiry),
//!   SNP report + measurement ∈ ticket ∩ §22 allowlist + TCB + launch
//!   policy, attested CHIP_ID == ticket placement, KBS-nonce single use,
//!   `REPORT_DATA == custody_bind(nonce, vm_id, gen, N, lease_pub)`, and
//!   the VM's §7 lifecycle-key signature over the whole body (a report
//!   alone does not name the VM: the golden measurement is shared). On a
//!   Grant it records the per-boot lease key.
//! - [`process_renew`] — every few minutes, authenticated ONLY by that
//!   lease key. No SNP report, no AMD KDS, no Vault.
//! - [`process_rekey`] — a renew that also returns the disk key (HPKE to a
//!   fresh key) so a guest that suspended its dm-crypt mappings can resume
//!   them. Reads Vault; advances NOTHING (no boot counter commit, no
//!   volume-stamp release note — the same attested launch already held
//!   this key).
//!
//! Standing comes from [`crate::lifecycle::custody_standing`], i.e. from
//! the same `VmState` the release path checks. Kill verdicts only on
//! positive evidence; everything else is an unsigned retry that the guest
//! must not act on.
//!
//! ## Clock
//!
//! Without SEV-SNP Secure TSC the host owns the guest's clocks, so the
//! guest's deadline can be stretched. What the KBS CAN do is notice it
//! while the guest is reachable: every renew carries the guest's
//! `CLOCK_MONOTONIC_RAW` (the clock its deadline runs on), and the KBS
//! compares its advance since bind with its own wall clock. A guest clock
//! running slow by more than the configured tolerance is flagged
//! (`skew_suspected`). A late delivery by the relay looks the same — both
//! are the miner's doing, and both deserve the alert. The miner cannot
//! hide a dilation by delivering EARLY (it cannot deliver before the
//! guest sends); only by delaying the FIRST bind of the boot, which the
//! single-use KBS nonce bounds to its TTL. The baseline is per boot: a
//! re-bind of the same boot (which a miner can force by forging the
//! unsigned `rebind-required`) keeps the baseline and the sticky flag and
//! is itself scored as a sample — otherwise an hourly forced re-bind would
//! hide any dilation inside the `min_window_s` grace.

use crate::crypto::hpke_seal_raw;
use crate::error::{KbsError, Result};
use crate::lifecycle::{custody_standing, revoked_standing, CustodyClaim, CustodyStanding};
use crate::lifecycle::{VmState, VmStateStore};
use crate::persist::KbsNonceStore;
use crate::release::{
    derive_lifecycle_path, transit_unwrap_if_wrapped, AuditSink, LIFECYCLE_KEY_VERSION,
};
use crate::report_data::ct_eq;
use crate::snp::{check_attestation, AttestationVerifier, LaunchPolicy, MeasurementAllowlist};
use crate::ticket::{verify_order_ticket_ignoring_expiry, L1Keyring};
use crate::vault::{AttestedVaultAuth, KbsAuthEvidence, VaultKv, VaultScope};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use hippius_types::custody::{
    decode_canonical, encode_canonical, lease_pub_hash, rekey_kek_aad, retry_reason, signing_input,
    verdict_reason, CustodyBindBody, CustodyBindRequest, CustodyRekeyBody, CustodyRekeyRequest,
    CustodyRekeyResponse, CustodyRenewBody, CustodyRenewRequest, CustodyVerdictBody,
    SignedCustodyVerdict, Verdict, WrappedKek, BIND_SIG_DOMAIN, CUSTODY_WIRE_V, KEY_LEN,
    REKEY_HPKE_INFO, REKEY_SIG_DOMAIN, RENEW_SIG_DOMAIN, VERDICT_SIG_DOMAIN,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Mutex, RwLock};
use zeroize::Zeroizing;

/// Longest lease the KBS will ever hand out (the guest additionally
/// clamps every value to the cap in its MEASURED cmdline).
pub const MAX_TTL_S: u32 = 604_800;
/// Shortest lease the admin policy may set — below this a KBS hiccup
/// suspends the fleet.
pub const MIN_TTL_S: u32 = 3_600;
/// Shortest renew interval the admin policy may set.
pub const MIN_RENEW_S: u32 = 30;
/// Longest stage-2 grace (suspended → self-reboot) the policy may set.
pub const MAX_STAGE2_S: u32 = 604_800;
/// Shortest stage-2 grace — below this "suspend" means "reboot now".
pub const MIN_STAGE2_S: u32 = 3_600;
/// Rebinds of one VM kept for the per-hour count (`rebinds_1h`).
const REBIND_WINDOW_S: u64 = 3_600;

/// The lease parameters every verdict carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CustodyPolicy {
    pub ttl_s: u32,
    pub stage2_s: u32,
    pub renew_s: u32,
}

impl Default for CustodyPolicy {
    fn default() -> Self {
        Self {
            ttl_s: 86_400,
            stage2_s: 172_800,
            renew_s: 600,
        }
    }
}

impl CustodyPolicy {
    /// Bounds shared by the config loader and the admin policy route.
    /// There is deliberately no "grant for ever" value: the longest lease
    /// is a week.
    pub fn validate(&self) -> Result<()> {
        if !(MIN_TTL_S..=MAX_TTL_S).contains(&self.ttl_s) {
            return Err(KbsError::Policy(format!(
                "custody ttl_s must be in [{MIN_TTL_S}, {MAX_TTL_S}]"
            )));
        }
        if !(MIN_STAGE2_S..=MAX_STAGE2_S).contains(&self.stage2_s) {
            return Err(KbsError::Policy(format!(
                "custody stage2_s must be in [{MIN_STAGE2_S}, {MAX_STAGE2_S}]"
            )));
        }
        // At least four renew attempts per lease, so one lost renew never
        // costs a suspend.
        if self.renew_s < MIN_RENEW_S || self.renew_s > self.ttl_s / 4 {
            return Err(KbsError::Policy(format!(
                "custody renew_s must be in [{MIN_RENEW_S}, ttl_s/4]"
            )));
        }
        Ok(())
    }
}

/// Untrusted-clock skew detection thresholds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SkewConfig {
    /// Allowed slowness of the guest clock, parts per million.
    pub tolerance_ppm: u64,
    /// No verdict before the window since bind is at least this long.
    pub min_window_s: u64,
    /// Absolute slack for honest relay/processing delays.
    pub slack_s: u64,
}

impl Default for SkewConfig {
    fn default() -> Self {
        Self {
            tolerance_ppm: 10_000,
            min_window_s: 3_600,
            slack_s: 120,
        }
    }
}

/// The Vault scope a bind's ticket named — kept so a rekey can read the
/// KEK without the ticket.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CustodyScope {
    pub luks_path: String,
    pub luks_version: u64,
    pub userdata_path: String,
    pub userdata_version: u64,
}

/// One bound guest. Keyed by `vm_id`: a VM has at most one binding, and a
/// newer Grant-standing bind replaces it.
///
/// `#[serde(default)]`: the on-disk snapshot must keep loading when a
/// field is added (see also [`MapCustodyStore::open`]).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct CustodyRecord {
    pub vm_id: String,
    pub generation: u64,
    pub boot_counter: u64,
    /// Attested CHIP_ID (hex, ticket length) the bind came from.
    pub node: String,
    pub lease_id: String,
    pub lease_pub: [u8; KEY_LEN],
    pub last_seq: u64,
    pub scope: CustodyScope,
    pub clock_mode: u8,
    /// KBS time the FIRST bind of this boot `(generation, boot_counter)`
    /// arrived — the skew baseline. A re-bind of the same boot (daemon
    /// restart, `rebind-required`) keeps it: resetting the baseline on
    /// every rebind would let a miner that forges `rebind-required` hide
    /// any clock dilation inside the `min_window_s` grace, forever.
    pub bound_at: u64,
    /// Guest `CLOCK_MONOTONIC_RAW` at that first bind, milliseconds.
    pub bind_mono_ms: u64,
    pub bind_tsc: u64,
    /// The latest guest monotonic reading accepted (bind or renew). A
    /// same-boot bind that does not move past it is a replayed or
    /// withheld older bind and never replaces the binding.
    pub last_mono_ms: u64,
    pub last_request_at: u64,
    pub last_grant_at: Option<u64>,
    pub last_verdict: Option<u8>,
    pub phase: u8,
    pub since_last_grant_s: u32,
    pub suspended_s: u32,
    /// Latest `(KBS elapsed since bind) − (guest elapsed since bind)`,
    /// seconds. Positive = the guest's clock is behind (dilated or the
    /// relay held the request).
    pub lag_s: i64,
    /// Sticky once set for this binding.
    pub skew_suspected: bool,
    /// KBS times of the binds of this VM within the last hour.
    pub rebinds: Vec<u64>,
    /// The attested launch measurement of the guest that bound (hex). A
    /// renew or rekey is refused once the VM's current launch is another
    /// one (`lifecycle::LaunchBinding`): a lease outlives nothing its
    /// launch did not. Empty only on a record from before the field —
    /// refused as well whenever the VM has a current launch on record.
    pub measurement: String,
}

/// Outcome of [`CustodyStore::advance`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Advance {
    Applied(Box<CustodyRecord>),
    /// No binding for this VM, or one for another lease key.
    NoBinding,
    /// `seq` is not strictly greater than the last accepted one.
    StaleSeq,
}

/// Outcome of [`CustodyStore::bind`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BindOutcome {
    /// Installed; the rebind count of the last hour.
    Bound { rebinds_1h: usize },
    /// A binding for a NEWER boot of this VM is in place; an older boot
    /// never replaces it.
    OlderBoot,
    /// Same boot, but the bind does not move past what the KBS already
    /// accepted (a replayed or withheld older bind), or it re-presents the
    /// lease key already bound (every bind MUST carry a fresh key, so a
    /// replay of the previous key's signed renews can never verify
    /// against a rebound record).
    Stale,
}

/// The custody binding store. Mutations are atomic per call.
pub trait CustodyStore: Send + Sync {
    fn get(&self, vm_id: &str) -> Result<Option<CustodyRecord>>;
    fn list(&self) -> Result<Vec<CustodyRecord>>;
    /// Install `rec` as THE binding of its VM, under the store lock:
    ///
    /// - a different (newer) boot replaces the binding with a fresh skew
    ///   baseline;
    /// - the SAME boot (`generation`, `boot_counter`) keeps its skew
    ///   baseline (`bound_at`, `bind_mono_ms`, `bind_tsc`) and its sticky
    ///   `skew_suspected`, and is refused as [`BindOutcome::Stale`] unless
    ///   its `last_mono_ms` moves forward and its lease key is new;
    /// - an OLDER boot never replaces a newer one.
    ///
    /// `rescore` recomputes the clock lag of the merged record (the bind
    /// itself is a clock sample).
    fn bind(&self, rec: CustodyRecord, rescore: &dyn Fn(&mut CustodyRecord))
        -> Result<BindOutcome>;
    /// Apply `f` iff the VM's binding has `lease_pub` and `last_seq <
    /// seq`; `last_seq` is set to `seq` in the same step, so a replayed
    /// or reordered request can never be accepted twice.
    fn advance(
        &self,
        vm_id: &str,
        lease_pub: &[u8; KEY_LEN],
        seq: u64,
        f: &mut dyn FnMut(&mut CustodyRecord),
    ) -> Result<Advance>;
}

/// Map-backed store; optionally persisted as one JSON snapshot (same
/// publish-then-cache discipline as the VM state store). The KBS state
/// dir is wiped on every pod restart anyway — persistence only saves a
/// fleet-wide rebind storm on a CONTAINER restart.
pub struct MapCustodyStore {
    path: Option<PathBuf>,
    map: Mutex<HashMap<String, CustodyRecord>>,
}

impl MapCustodyStore {
    pub fn in_memory() -> Self {
        Self {
            path: None,
            map: Mutex::new(HashMap::new()),
        }
    }

    pub fn open(path: impl Into<PathBuf>) -> Result<Self> {
        let path = path.into();
        let map = match std::fs::read(&path) {
            // Disposable by design: every guest re-binds on
            // `rebind-required`. An undecodable snapshot therefore starts
            // the store empty (loudly) instead of taking the whole KBS —
            // release path included — down at startup.
            Ok(bytes) => match serde_json::from_slice(&bytes) {
                Ok(map) => map,
                Err(e) => {
                    eprintln!(
                        "kbs-core::custody: {} does not decode ({e}); starting with no \
                         custody bindings — every guest will re-bind",
                        path.display()
                    );
                    HashMap::new()
                }
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => HashMap::new(),
            Err(e) => return Err(KbsError::Vault(format!("custody store read: {e}"))),
        };
        Ok(Self {
            path: Some(path),
            map: Mutex::new(map),
        })
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, HashMap<String, CustodyRecord>>> {
        self.map
            .lock()
            .map_err(|_| KbsError::Lifecycle("custody store lock poisoned".into()))
    }

    fn publish(
        &self,
        cache: &mut HashMap<String, CustodyRecord>,
        staged: HashMap<String, CustodyRecord>,
    ) -> Result<()> {
        let Some(path) = &self.path else {
            *cache = staged;
            return Ok(());
        };
        let bytes = serde_json::to_vec(&staged)
            .map_err(|e| KbsError::Vault(format!("custody store encode: {e}")))?;
        let synced = crate::persist::atomic_write_published(path, &bytes)?;
        *cache = staged;
        synced
    }
}

impl CustodyStore for MapCustodyStore {
    fn get(&self, vm_id: &str) -> Result<Option<CustodyRecord>> {
        Ok(self.lock()?.get(vm_id).cloned())
    }

    fn list(&self) -> Result<Vec<CustodyRecord>> {
        let mut v: Vec<CustodyRecord> = self.lock()?.values().cloned().collect();
        v.sort_by(|a, b| a.vm_id.cmp(&b.vm_id));
        Ok(v)
    }

    fn bind(
        &self,
        mut rec: CustodyRecord,
        rescore: &dyn Fn(&mut CustodyRecord),
    ) -> Result<BindOutcome> {
        let mut g = self.lock()?;
        let arrived = rec.last_request_at;
        let mut rebinds = Vec::new();
        if let Some(cur) = g.get(&rec.vm_id) {
            let this_boot = (rec.generation, rec.boot_counter);
            let bound_boot = (cur.generation, cur.boot_counter);
            if this_boot < bound_boot {
                return Ok(BindOutcome::OlderBoot);
            }
            if this_boot == bound_boot {
                if rec.last_mono_ms <= cur.last_mono_ms || ct_eq(&rec.lease_pub, &cur.lease_pub) {
                    return Ok(BindOutcome::Stale);
                }
                rec.bound_at = cur.bound_at;
                rec.bind_mono_ms = cur.bind_mono_ms;
                rec.bind_tsc = cur.bind_tsc;
                rec.skew_suspected = cur.skew_suspected;
                rescore(&mut rec);
            }
            rebinds = cur.rebinds.clone();
        }
        rebinds.retain(|t| arrived.saturating_sub(*t) < REBIND_WINDOW_S);
        rebinds.push(arrived);
        rec.rebinds = rebinds;
        let n = rec.rebinds.len();
        let mut staged = g.clone();
        staged.insert(rec.vm_id.clone(), rec);
        self.publish(&mut g, staged)?;
        Ok(BindOutcome::Bound { rebinds_1h: n })
    }

    fn advance(
        &self,
        vm_id: &str,
        lease_pub: &[u8; KEY_LEN],
        seq: u64,
        f: &mut dyn FnMut(&mut CustodyRecord),
    ) -> Result<Advance> {
        let mut g = self.lock()?;
        let Some(cur) = g.get(vm_id) else {
            return Ok(Advance::NoBinding);
        };
        if !ct_eq(&cur.lease_pub, lease_pub) {
            return Ok(Advance::NoBinding);
        }
        if seq <= cur.last_seq {
            return Ok(Advance::StaleSeq);
        }
        let mut next = cur.clone();
        next.last_seq = seq;
        f(&mut next);
        let mut staged = g.clone();
        staged.insert(vm_id.to_string(), next.clone());
        self.publish(&mut g, staged)?;
        Ok(Advance::Applied(Box::new(next)))
    }
}

/// Everything custody needs at runtime besides the release deps. Shared
/// (one `Arc`) by the public routes and the admin routes.
pub struct CustodyRuntime {
    pub store: std::sync::Arc<dyn CustodyStore>,
    policy: RwLock<CustodyPolicy>,
    pub skew: SkewConfig,
    /// `vm_id → lifecycle verifying key`, filled by the first bind's
    /// Vault read so a daemon restart does not read Vault again.
    lifecycle_vks: Mutex<HashMap<String, [u8; KEY_LEN]>>,
    /// `vm_id → (tokens, last refill)` for AUTHENTICATED renew/rekey. It is
    /// charged only after the lease signature verified, so nobody but the
    /// guest itself can drain a VM's budget; a flood of garbage hits the
    /// transport's global bucket instead.
    per_vm: Mutex<HashMap<String, (u32, u64)>>,
}

/// Per-VM authenticated renew/rekey budget: a burst of this many…
const PER_VM_BURST: u32 = 12;
/// …refilled one token every this many seconds. A healthy guest renews
/// once per `renew_s` (minutes) and backs off from 30 s on failures.
const PER_VM_REFILL_S: u64 = 10;

impl CustodyRuntime {
    pub fn new(
        store: std::sync::Arc<dyn CustodyStore>,
        policy: CustodyPolicy,
        skew: SkewConfig,
    ) -> Result<Self> {
        policy.validate()?;
        Ok(Self {
            store,
            policy: RwLock::new(policy),
            skew,
            lifecycle_vks: Mutex::new(HashMap::new()),
            per_vm: Mutex::new(HashMap::new()),
        })
    }

    /// Take one per-VM token. Entries exist only for VMs with a binding
    /// (callers charge after the lease signature verified), so the map is
    /// bounded by the number of bound guests.
    fn take_vm_token(&self, vm_id: &str, now: u64) -> bool {
        let Ok(mut m) = self.per_vm.lock() else {
            return false;
        };
        let (tokens, last) = m.entry(vm_id.to_string()).or_insert((PER_VM_BURST, now));
        let refill = now.saturating_sub(*last) / PER_VM_REFILL_S;
        if refill > 0 {
            *tokens = tokens
                .saturating_add(u32::try_from(refill).unwrap_or(u32::MAX))
                .min(PER_VM_BURST);
            *last = now;
        }
        if *tokens == 0 {
            return false;
        }
        *tokens -= 1;
        true
    }

    pub fn policy(&self) -> CustodyPolicy {
        match self.policy.read() {
            Ok(p) => *p,
            Err(poisoned) => *poisoned.into_inner(),
        }
    }

    /// Admin kill switch: replace the fleet policy (validated). In memory
    /// only — a restart returns to the configured policy.
    pub fn set_policy(&self, policy: CustodyPolicy) -> Result<()> {
        policy.validate()?;
        let mut w = self
            .policy
            .write()
            .map_err(|_| KbsError::Lifecycle("custody policy lock poisoned".into()))?;
        *w = policy;
        Ok(())
    }

    fn cached_vk(&self, vm_id: &str) -> Option<[u8; KEY_LEN]> {
        self.lifecycle_vks.lock().ok()?.get(vm_id).copied()
    }

    fn remember_vk(&self, vm_id: &str, vk: [u8; KEY_LEN]) {
        if let Ok(mut m) = self.lifecycle_vks.lock() {
            m.insert(vm_id.to_string(), vk);
        }
    }
}

/// The release-path dependencies custody reuses — the SAME verifier,
/// allowlist, policy, stores, Vault and L0 key.
pub struct CustodyDeps<'a> {
    pub l1_keyring: &'a dyn L1Keyring,
    pub attn: &'a dyn AttestationVerifier,
    pub offline_allowlist: &'a dyn MeasurementAllowlist,
    pub launch_policy: &'a LaunchPolicy,
    pub vm_states: &'a dyn VmStateStore,
    pub kbs_nonce_store: &'a dyn KbsNonceStore,
    pub vault_auth: &'a dyn AttestedVaultAuth,
    pub vault_kv: &'a dyn VaultKv,
    pub kbs_attestation: &'a crate::snp::VerifiedReport,
    pub kbs_auth_pubkey: &'a [u8],
    pub kbs_signing_key: &'a SigningKey,
    pub kbs_kid: &'a [u8],
    pub audit: &'a dyn AuditSink,
    pub boot_counter: &'a dyn crate::boot_counter::BootCounterStore,
    pub require_wrapped_kek: bool,
    pub runtime: &'a CustodyRuntime,
}

/// What the transport sends back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CustodyReply {
    /// HTTP 200, the signed verdict (bind / renew).
    Verdict(SignedCustodyVerdict),
    /// HTTP 200, the rekey response.
    Rekey(CustodyRekeyResponse),
    /// Unsigned, retryable. The guest changes nothing.
    Retry { status: u16, reason: &'static str },
}

impl CustodyReply {
    pub fn disabled() -> Self {
        Self::Retry {
            status: 404,
            reason: retry_reason::DISABLED,
        }
    }
    fn malformed() -> Self {
        Self::Retry {
            status: 400,
            reason: "malformed",
        }
    }
    fn denied() -> Self {
        Self::Retry {
            status: 403,
            reason: "denied",
        }
    }
    fn unavailable() -> Self {
        Self::Retry {
            status: 503,
            reason: retry_reason::UNAVAILABLE,
        }
    }
    fn rebind() -> Self {
        Self::Retry {
            status: 503,
            reason: retry_reason::REBIND_REQUIRED,
        }
    }
}

/// Sign a verdict body under [`VERDICT_SIG_DOMAIN`]. The body is
/// validated first, so the reason/verdict vocabulary cannot drift.
pub fn sign_verdict(
    signing_key: &SigningKey,
    kid: &[u8],
    body: &CustodyVerdictBody,
) -> Result<SignedCustodyVerdict> {
    body.validate()?;
    let bytes = encode_canonical(body)?;
    let sig = signing_key.sign(&signing_input(VERDICT_SIG_DOMAIN, &bytes));
    Ok(SignedCustodyVerdict {
        body: bytes,
        kid: kid.to_vec(),
        sig: sig.to_bytes().to_vec(),
    })
}

/// Verify a signed verdict (guest parity; tests).
pub fn verify_verdict(
    vk: &VerifyingKey,
    signed: &SignedCustodyVerdict,
) -> Result<CustodyVerdictBody> {
    let sig = Signature::from_slice(&signed.sig)
        .map_err(|e| KbsError::Crypto(format!("verdict sig decode: {e}")))?;
    vk.verify_strict(&signing_input(VERDICT_SIG_DOMAIN, &signed.body), &sig)
        .map_err(|e| KbsError::Crypto(format!("verdict sig invalid: {e}")))?;
    let body: CustodyVerdictBody = decode_canonical(&signed.body)?;
    body.validate()?;
    Ok(body)
}

fn verify_sig(vk: &[u8; KEY_LEN], domain: &[u8], body: &[u8], sig: &[u8]) -> Result<()> {
    let vk =
        VerifyingKey::from_bytes(vk).map_err(|e| KbsError::Crypto(format!("custody vk: {e}")))?;
    let sig = Signature::from_slice(sig)
        .map_err(|e| KbsError::Crypto(format!("custody sig decode: {e}")))?;
    vk.verify_strict(&signing_input(domain, body), &sig)
        .map_err(|e| KbsError::Crypto(format!("custody sig invalid: {e}")))
}

/// The identity a verdict echoes back to the guest.
struct Echo<'a> {
    vm_id: &'a str,
    generation: u64,
    boot_counter: u64,
    lease_pub: &'a [u8],
    guest_challenge: &'a [u8],
    seq: u64,
}

fn verdict_for(
    deps: &CustodyDeps,
    echo: &Echo,
    standing: CustodyStanding,
    now: u64,
) -> Result<Option<(SignedCustodyVerdict, CustodyVerdictBody)>> {
    let (verdict, reason) = match standing {
        CustodyStanding::Grant => (Verdict::Grant, verdict_reason::GRANTED),
        CustodyStanding::Revoked { reason } => (Verdict::Revoked, reason),
        CustodyStanding::Superseded { reason } => (Verdict::Superseded, reason),
        CustodyStanding::Retry { .. } => return Ok(None),
    };
    let policy = deps.runtime.policy();
    let body = CustodyVerdictBody {
        v: CUSTODY_WIRE_V,
        vm_id: echo.vm_id.to_string(),
        generation: echo.generation,
        boot_counter: echo.boot_counter,
        lease_pub_hash: lease_pub_hash(echo.lease_pub).to_vec(),
        guest_challenge: echo.guest_challenge.to_vec(),
        seq: echo.seq,
        verdict: verdict as u8,
        ttl_s: policy.ttl_s,
        stage2_s: policy.stage2_s,
        renew_s: policy.renew_s,
        // Secure TSC is not available on the fleet; the KBS never claims
        // a TSC deadline it could not calibrate.
        deadline_tsc: None,
        kbs_time_unix: now,
        reason: reason.to_string(),
    };
    let signed = sign_verdict(deps.kbs_signing_key, deps.kbs_kid, &body)?;
    Ok(Some((signed, body)))
}

fn reply_for(deps: &CustodyDeps, echo: &Echo, standing: CustodyStanding, now: u64) -> CustodyReply {
    match standing {
        CustodyStanding::Retry { reason } => CustodyReply::Retry {
            status: 503,
            reason,
        },
        _ => match verdict_for(deps, echo, standing, now) {
            Ok(Some((signed, _))) => CustodyReply::Verdict(signed),
            Ok(None) => CustodyReply::unavailable(),
            Err(_) => CustodyReply::unavailable(),
        },
    }
}

fn read_state(deps: &CustodyDeps, vm_id: &str) -> Result<Option<VmState>> {
    match deps.vm_states.get(vm_id) {
        Ok(s) => Ok(Some(s)),
        // `no state for vm_id` — absent, which custody reads as unknown.
        Err(KbsError::Lifecycle(_)) => Ok(None),
        Err(e) => Err(e),
    }
}

fn audit(deps: &CustodyDeps, vm_id: &str, what: &str, ok: bool) {
    deps.audit
        .record(ok, None, Some(vm_id), &format!("custody-{what}"));
}

fn standing_label(s: &CustodyStanding) -> String {
    match s {
        CustodyStanding::Grant => "granted".into(),
        CustodyStanding::Revoked { reason } => format!("revoked:{reason}"),
        CustodyStanding::Superseded { reason } => format!("superseded:{reason}"),
        CustodyStanding::Retry { reason } => format!("retry:{reason}"),
    }
}

// ─────────────────────────────── bind ────────────────────────────────

pub fn process_bind(req: &CustodyBindRequest, now: u64, deps: &CustodyDeps) -> CustodyReply {
    let body: CustodyBindBody = match decode_canonical(&req.body) {
        Ok(b) => b,
        Err(_) => return CustodyReply::malformed(),
    };
    if body.validate().is_err() {
        return CustodyReply::malformed();
    }
    let echo = Echo {
        vm_id: &body.vm_id,
        generation: body.generation,
        boot_counter: body.boot_counter,
        lease_pub: &body.lease_pub,
        guest_challenge: &body.guest_challenge,
        seq: 0,
    };
    match bind_inner(req, &body, now, deps) {
        Ok(standing) => {
            audit(
                deps,
                &body.vm_id,
                &format!("bind:{}", standing_label(&standing)),
                standing == CustodyStanding::Grant,
            );
            reply_for(deps, &echo, standing, now)
        }
        Err(e) => {
            let (r, why) = e.reply();
            audit(deps, &body.vm_id, &format!("bind:refused:{why}"), false);
            r
        }
    }
}

/// Why a bind produced no verdict. Both are unsigned retries for the
/// guest; the distinction is the HTTP status (403 vs 503) and the audit.
enum BindError {
    Denied(String),
    Unavailable(String),
}

impl BindError {
    fn reply(&self) -> (CustodyReply, &str) {
        match self {
            BindError::Denied(why) => (CustodyReply::denied(), why),
            BindError::Unavailable(why) => (CustodyReply::unavailable(), why),
        }
    }
}

fn denied(why: impl std::fmt::Display) -> BindError {
    BindError::Denied(why.to_string())
}

fn unavailable(why: impl std::fmt::Display) -> BindError {
    BindError::Unavailable(why.to_string())
}

/// `true` iff the key mode pinned for `vm_id` at register is M0.
fn pinned_hippius(deps: &CustodyDeps, vm_id: &str) -> Result<bool> {
    Ok(deps.vm_states.key_mode(vm_id)? == hippius_types::guardian::KeyMode::Hippius)
}

fn bind_inner(
    req: &CustodyBindRequest,
    body: &CustodyBindBody,
    now: u64,
    deps: &CustodyDeps,
) -> core::result::Result<CustodyStanding, BindError> {
    // Revoked is a public fact: answered before any verification, so a
    // decommissioned VM is told so even while AMD KDS or Vault is down.
    let state = read_state(deps, &body.vm_id).map_err(unavailable)?;
    if let Some(revoked) = revoked_standing(state.as_ref()) {
        return Ok(revoked);
    }

    deps.offline_allowlist
        .pre_release_validate()
        .map_err(unavailable)?;

    // 1. The ticket this boot was released under — signature and schema,
    //    not expiry (see `verify_order_ticket_ignoring_expiry`).
    let (ticket, ticket_kid) =
        verify_order_ticket_ignoring_expiry(&body.cose_ticket, deps.l1_keyring).map_err(denied)?;
    if ticket.vm_id != body.vm_id || ticket.vm_generation != body.generation {
        return Err(denied("ticket does not name this vm_id/generation"));
    }
    // Customer-held keys: a custody rekey hands back the Vault-staged KEK
    // as the COMPLETE key. That is only true in M0 — in M1 it is just the
    // Hippius share, in M2 it does not exist. Until the guardian rerelease
    // path lands with custody, bind and rekey are M0-only. The PINNED mode
    // is authoritative (an M0 ticket for a VM registered M1/M2 is refused);
    // the ticket's own mode is checked too.
    if !pinned_hippius(deps, &body.vm_id).map_err(unavailable)?
        || ticket.key_mode() != hippius_types::guardian::KeyMode::Hippius
    {
        return Err(denied("custody is not supported for customer-held keys"));
    }

    // 2. Attestation, with the custody REPORT_DATA binding in place of
    //    the release one — a bind report can never pass as a release
    //    report (the release gate compares REPORT_DATA[0..32] to its
    //    nonce) and a release report can never pass here.
    let nonce: [u8; 32] = body
        .kbs_nonce
        .as_slice()
        .try_into()
        .map_err(|_| denied("kbs_nonce length"))?;
    let lease_pub: [u8; KEY_LEN] = body
        .lease_pub
        .as_slice()
        .try_into()
        .map_err(|_| denied("lease_pub length"))?;
    let expected_rd = hippius_types::report_data::custody_bind(
        &nonce,
        &body.vm_id,
        body.generation,
        body.boot_counter,
        &lease_pub,
    )
    .map_err(|e| denied(KbsError::from(e)))?;
    // Nonce freshness BEFORE the report verify: the verify may fetch a
    // VCEK from AMD KDS, and only a nonce this KBS minted (and has not
    // seen spent) earns that work. Spent below, once everything verified.
    deps.kbs_nonce_store
        .verify_unspent(&nonce, now)
        .map_err(denied)?;
    let report = deps.attn.verify(&body.snp_report).map_err(denied)?;
    let ticket_allowed: Vec<Vec<u8>> = ticket
        .allowed_measurements
        .iter()
        .map(|b| b.as_ref().to_vec())
        .collect();
    check_attestation(
        &report,
        &ticket_allowed,
        deps.offline_allowlist,
        &expected_rd,
        deps.launch_policy,
    )
    .map_err(denied)?;
    // 2b. Allowlist class × ticket role, as at release. Custody is new, so
    // the host-attestor refusal is on here unconditionally; a CDN node
    // (class and perm agreeing) may hold a lease like any VM.
    crate::snp::check_release_class(
        deps.offline_allowlist,
        &report.measurement,
        &ticket.lifecycle_perms,
        true,
    )
    .map_err(denied)?;

    // 3. CHIP_ID == ticket placement — same generation-aware truncation as
    //    the release path.
    let id_len = ticket.platform_id.len() / 2;
    if id_len == 0 || id_len > report.chip_id.len() {
        return Err(denied("attested platform_id != ticket placement"));
    }
    let attested_node = hex::encode(&report.chip_id[..id_len]);
    if attested_node != ticket.platform_id {
        return Err(denied("attested platform_id != ticket placement"));
    }

    // 4. Kid gates, as at release.
    if !deps
        .offline_allowlist
        .accepts_l1_kid(&report.measurement, &ticket_kid)
    {
        return Err(denied(
            "L1 ticket kid not accepted for attested measurement",
        ));
    }
    if !deps
        .offline_allowlist
        .accepts_kbs_kid(&report.measurement, deps.kbs_kid)
    {
        return Err(denied("KBS kid not accepted for attested measurement"));
    }

    // 5'. Only the VM's current launch binds a lease
    //     (`lifecycle::check_current_launch` — the release path is what
    //     moves the binding; a bind never does). A guest of a superseded
    //     launch, the pre-resize size say, gets no lease; one bound before
    //     the supersession renews and rekeys nothing from then on
    //     (`within_current_launch`).
    if let Some(current) = deps.vm_states.launch_binding(&body.vm_id).map_err(denied)? {
        if current.measurement != report.measurement {
            return Err(denied(
                "superseded-launch: the attested measurement is not the VM's current launch",
            ));
        }
    }

    // 6. The lifecycle-key signature — what names THIS VM. The golden
    //    measurement is shared, so without it a miner's own golden VM on
    //    the same host could bind a lease key under a victim's vm_id.
    let scope = CustodyScope {
        luks_path: ticket.luks_vault_ref.path.clone(),
        luks_version: ticket.luks_vault_ref.version,
        userdata_path: ticket.userdata_vault_ref.path.clone(),
        userdata_version: ticket.userdata_vault_ref.version,
    };
    let lifecycle_vk = lifecycle_vk(deps, &body.vm_id, &scope, now)?;
    verify_sig(
        &lifecycle_vk,
        BIND_SIG_DOMAIN,
        &req.body,
        &req.lifecycle_sig,
    )
    .map_err(denied)?;

    // 7. Single use.
    deps.kbs_nonce_store.spend(&nonce, now).map_err(denied)?;

    // 8. Standing, from the attested + signed claim.
    let stored = deps.boot_counter.get(&body.vm_id).map_err(unavailable)?;
    let standing = custody_standing(
        state.as_ref(),
        stored,
        &CustodyClaim {
            generation: body.generation,
            boot_counter: body.boot_counter,
            node: &attested_node,
            lease_id: &ticket.lease_id,
        },
    );
    let existing = deps.runtime.store.get(&body.vm_id).map_err(unavailable)?;
    // A boot-superseded kill at BIND time rests on the stored counter —
    // and after a KBS wipe that counter is re-seeded from the miner's own
    // plaintext state disk. So at bind it is only issued when custody
    // itself has seen the newer boot bind (positive evidence the KBS
    // observed); otherwise it is a retry. A lying seed can then deny a
    // guest service — which the miner can always do — but never kill it.
    if let CustodyStanding::Superseded {
        reason: verdict_reason::BOOT_SUPERSEDED,
    } = standing
    {
        let newer_boot_bound = existing
            .as_ref()
            .is_some_and(|r| r.generation == body.generation && r.boot_counter > body.boot_counter);
        if !newer_boot_bound {
            return Ok(CustodyStanding::Retry {
                reason: retry_reason::UNKNOWN_VM,
            });
        }
    }
    if standing == CustodyStanding::Grant {
        let rec = CustodyRecord {
            vm_id: body.vm_id.clone(),
            generation: body.generation,
            boot_counter: body.boot_counter,
            node: attested_node,
            lease_id: ticket.lease_id.clone(),
            lease_pub,
            last_seq: 0,
            scope,
            clock_mode: body.clock_mode,
            bound_at: now,
            bind_mono_ms: body.mono_ms,
            bind_tsc: body.tsc,
            last_mono_ms: body.mono_ms,
            last_request_at: now,
            last_grant_at: Some(now),
            last_verdict: Some(Verdict::Grant as u8),
            phase: hippius_types::custody::CustodyPhase::Armed as u8,
            since_last_grant_s: 0,
            suspended_s: 0,
            lag_s: 0,
            skew_suspected: false,
            rebinds: Vec::new(),
            measurement: hex::encode(report.measurement),
        };
        let skew = deps.runtime.skew;
        let rescore = |r: &mut CustodyRecord| {
            let (lag, suspect) = clock_lag(r, body.mono_ms, now, &skew);
            r.lag_s = lag;
            r.skew_suspected |= suspect;
        };
        // A Grant is only issued once the binding it promises is durable.
        match deps
            .runtime
            .store
            .bind(rec, &rescore)
            .map_err(unavailable)?
        {
            BindOutcome::Bound { .. } => {}
            BindOutcome::OlderBoot | BindOutcome::Stale => {
                return Ok(CustodyStanding::Retry {
                    reason: "stale-bind",
                })
            }
        }
    }
    Ok(standing)
}

/// The VM's §7 lifecycle verifying key: cached after the first read,
/// otherwise derived from the seed read through the SAME attested Vault
/// capability flow the release uses.
fn lifecycle_vk(
    deps: &CustodyDeps,
    vm_id: &str,
    scope: &CustodyScope,
    now: u64,
) -> core::result::Result<[u8; KEY_LEN], BindError> {
    if let Some(vk) = deps.runtime.cached_vk(vm_id) {
        return Ok(vk);
    }
    let lifecycle_path = derive_lifecycle_path(&scope.luks_path)
        .ok_or_else(|| denied("no lifecycle-key path for this ticket"))?;
    let vscope = vault_scope(vm_id, scope, Some(lifecycle_path.clone()));
    let cap = redeem(deps, &vscope, now).map_err(unavailable)?;
    let seed = match deps
        .vault_kv
        .read_exact(&cap, &lifecycle_path, LIFECYCLE_KEY_VERSION)
    {
        Ok(seed) => seed,
        // A VM staged without a lifecycle key can never bind — custody
        // needs the key that names the VM.
        Err(KbsError::VaultNotFound(_)) => return Err(denied("no lifecycle key staged")),
        Err(e) => return Err(unavailable(e)),
    };
    let seed: Zeroizing<[u8; 32]> = Zeroizing::new(
        seed.as_slice()
            .try_into()
            .map_err(|_| denied("lifecycle seed is not 32 bytes"))?,
    );
    let vk = SigningKey::from_bytes(&seed).verifying_key().to_bytes();
    deps.runtime.remember_vk(vm_id, vk);
    Ok(vk)
}

fn vault_scope(vm_id: &str, scope: &CustodyScope, lifecycle_path: Option<String>) -> VaultScope {
    VaultScope {
        vm_id: vm_id.to_string(),
        luks_path: scope.luks_path.clone(),
        luks_version: scope.luks_version,
        userdata_path: scope.userdata_path.clone(),
        userdata_version: scope.userdata_version,
        lifecycle_version: lifecycle_path.as_ref().map(|_| LIFECYCLE_KEY_VERSION),
        cdn_fleet_versions: None,
        lifecycle_path,
    }
}

fn redeem(
    deps: &CustodyDeps,
    scope: &VaultScope,
    now: u64,
) -> Result<crate::vault::VaultCapability> {
    let challenge = deps.vault_auth.issue_challenge(scope, now)?;
    let ev = KbsAuthEvidence {
        verified: deps.kbs_attestation,
        challenge: &challenge,
        scope,
        auth_pubkey: deps.kbs_auth_pubkey,
    };
    deps.vault_auth.redeem(&ev, now)
}

// ──────────────────────────── renew / rekey ──────────────────────────

/// What the lease-key path produced before any rekey work.
enum LeaseOutcome {
    Reply(CustodyReply),
    Standing {
        standing: CustodyStanding,
        record: Box<CustodyRecord>,
    },
}

/// Shared by renew and rekey: public Revoked, binding lookup, lease
/// signature, seq CAS + telemetry, standing.
fn lease_step(
    renew: &CustodyRenewBody,
    signed_body: &[u8],
    sig: &[u8],
    domain: &[u8],
    now: u64,
    deps: &CustodyDeps,
) -> LeaseOutcome {
    let echo = Echo {
        vm_id: &renew.vm_id,
        generation: renew.generation,
        boot_counter: renew.boot_counter,
        lease_pub: &renew.lease_pub,
        guest_challenge: &renew.guest_challenge,
        seq: renew.seq,
    };
    let state = match read_state(deps, &renew.vm_id) {
        Ok(s) => s,
        Err(_) => return LeaseOutcome::Reply(CustodyReply::unavailable()),
    };
    if let Some(revoked) = revoked_standing(state.as_ref()) {
        return LeaseOutcome::Reply(reply_for(deps, &echo, revoked, now));
    }
    let Ok(lease_pub) = <[u8; KEY_LEN]>::try_from(renew.lease_pub.as_slice()) else {
        return LeaseOutcome::Reply(CustodyReply::malformed());
    };
    let record = match deps.runtime.store.get(&renew.vm_id) {
        Ok(Some(r)) if ct_eq(&r.lease_pub, &lease_pub) => r,
        Ok(_) => return LeaseOutcome::Reply(CustodyReply::rebind()),
        Err(_) => return LeaseOutcome::Reply(CustodyReply::unavailable()),
    };
    if verify_sig(&lease_pub, domain, signed_body, sig).is_err() {
        return LeaseOutcome::Reply(CustodyReply::denied());
    }
    if !deps.runtime.take_vm_token(&renew.vm_id, now) {
        return LeaseOutcome::Reply(CustodyReply::Retry {
            status: 429,
            reason: "rate-limited",
        });
    }
    if renew.generation != record.generation || renew.boot_counter != record.boot_counter {
        return LeaseOutcome::Reply(CustodyReply::rebind());
    }
    let stored = match deps.boot_counter.get(&renew.vm_id) {
        Ok(s) => s,
        Err(_) => return LeaseOutcome::Reply(CustodyReply::unavailable()),
    };
    let standing = custody_standing(
        state.as_ref(),
        stored,
        &CustodyClaim {
            generation: record.generation,
            boot_counter: record.boot_counter,
            node: &record.node,
            lease_id: &record.lease_id,
        },
    );
    let standing = match within_current_launch(deps, &record, standing) {
        Ok(Some(s)) => s,
        Ok(None) => return LeaseOutcome::Reply(CustodyReply::rebind()),
        Err(_) => return LeaseOutcome::Reply(CustodyReply::unavailable()),
    };
    let skew = deps.runtime.skew;
    let mut update = |r: &mut CustodyRecord| {
        r.last_request_at = now;
        r.phase = renew.status.phase;
        r.since_last_grant_s = renew.status.since_last_grant_s;
        r.suspended_s = renew.status.suspended_s;
        let (lag, suspect) = clock_lag(r, renew.mono_ms, now, &skew);
        r.lag_s = lag;
        r.skew_suspected |= suspect;
        r.last_mono_ms = r.last_mono_ms.max(renew.mono_ms);
        match standing {
            CustodyStanding::Grant => {
                r.last_grant_at = Some(now);
                r.last_verdict = Some(Verdict::Grant as u8);
            }
            CustodyStanding::Revoked { .. } => r.last_verdict = Some(Verdict::Revoked as u8),
            CustodyStanding::Superseded { .. } => r.last_verdict = Some(Verdict::Superseded as u8),
            CustodyStanding::Retry { .. } => {}
        }
    };
    match deps
        .runtime
        .store
        .advance(&renew.vm_id, &lease_pub, renew.seq, &mut update)
    {
        Ok(Advance::Applied(record)) => LeaseOutcome::Standing { standing, record },
        Ok(Advance::StaleSeq) => LeaseOutcome::Reply(CustodyReply::Retry {
            status: 409,
            reason: "stale-seq",
        }),
        Ok(Advance::NoBinding) => LeaseOutcome::Reply(CustodyReply::rebind()),
        Err(_) => LeaseOutcome::Reply(CustodyReply::unavailable()),
    }
}

/// `(lag_s, suspect)` for a renew whose guest monotonic clock reads
/// `mono_ms` at KBS time `now`. See the module docs.
pub fn clock_lag(r: &CustodyRecord, mono_ms: u64, now: u64, skew: &SkewConfig) -> (i64, bool) {
    let kbs_elapsed = now.saturating_sub(r.bound_at);
    if mono_ms < r.bind_mono_ms {
        // The same boot's monotonic clock went backwards: not a clock
        // this guest's deadline can be trusted on.
        return (i64::try_from(kbs_elapsed).unwrap_or(i64::MAX), true);
    }
    let guest_elapsed = (mono_ms - r.bind_mono_ms) / 1_000;
    let lag = i64::try_from(kbs_elapsed)
        .unwrap_or(i64::MAX)
        .saturating_sub(i64::try_from(guest_elapsed).unwrap_or(i64::MAX));
    if kbs_elapsed < skew.min_window_s {
        return (lag, false);
    }
    let allowed = skew
        .slack_s
        .max(kbs_elapsed.saturating_mul(skew.tolerance_ppm) / 1_000_000);
    (lag, lag > i64::try_from(allowed).unwrap_or(i64::MAX))
}

pub fn process_renew(req: &CustodyRenewRequest, now: u64, deps: &CustodyDeps) -> CustodyReply {
    let body: CustodyRenewBody = match decode_canonical(&req.body) {
        Ok(b) => b,
        Err(_) => return CustodyReply::malformed(),
    };
    if body.validate().is_err() {
        return CustodyReply::malformed();
    }
    let reply = match lease_step(&body, &req.body, &req.sig, RENEW_SIG_DOMAIN, now, deps) {
        LeaseOutcome::Reply(r) => r,
        LeaseOutcome::Standing { standing, .. } => {
            let echo = Echo {
                vm_id: &body.vm_id,
                generation: body.generation,
                boot_counter: body.boot_counter,
                lease_pub: &body.lease_pub,
                guest_challenge: &body.guest_challenge,
                seq: body.seq,
            };
            reply_for(deps, &echo, standing, now)
        }
    };
    // Routine Grants and unauthenticated refusals are not audited (one row
    // per guest per renew interval, or per junk request, would bury the
    // log); the binding records the last grant. Revoked / Superseded are.
    if let CustodyReply::Verdict(_) = &reply {
        let label = reply_label(&reply);
        if label != verdict_reason::GRANTED {
            audit(deps, &body.vm_id, &format!("renew:{label}"), false);
        }
    }
    reply
}

pub fn process_rekey(req: &CustodyRekeyRequest, now: u64, deps: &CustodyDeps) -> CustodyReply {
    let body: CustodyRekeyBody = match decode_canonical(&req.body) {
        Ok(b) => b,
        Err(_) => return CustodyReply::malformed(),
    };
    if body.validate().is_err() {
        return CustodyReply::malformed();
    }
    let reply = rekey_inner(&body, req, now, deps);
    audit(
        deps,
        &body.renew.vm_id,
        &format!("rekey:{}", reply_label(&reply)),
        matches!(&reply, CustodyReply::Rekey(r) if r.wrapped_kek.is_some()),
    );
    reply
}

fn reply_label(r: &CustodyReply) -> String {
    match r {
        CustodyReply::Verdict(v) | CustodyReply::Rekey(CustodyRekeyResponse { verdict: v, .. }) => {
            match decode_canonical::<CustodyVerdictBody>(&v.body) {
                Ok(b) => b.reason,
                Err(_) => "verdict".into(),
            }
        }
        CustodyReply::Retry { status, reason } => format!("retry:{status}:{reason}"),
    }
}

/// `standing`, unless the lease was bound by a launch the VM has since
/// moved past (`lifecycle::LaunchBinding` — a resize relaunch registered
/// or released): then the lease is superseded, so it renews and rekeys
/// nothing. A lease never outlives the launch that bound it.
///
/// `Ok(None)` ⇒ the record does not say which launch bound it (written
/// before the field): no evidence either way, so the guest is asked to
/// rebind — its fresh bind records the attested launch — never killed.
fn within_current_launch(
    deps: &CustodyDeps,
    record: &CustodyRecord,
    standing: CustodyStanding,
) -> Result<Option<CustodyStanding>> {
    if standing != CustodyStanding::Grant {
        return Ok(Some(standing));
    }
    match deps.vm_states.launch_binding(&record.vm_id)? {
        Some(_) if record.measurement.is_empty() => Ok(None),
        Some(current) if record.measurement != hex::encode(current.measurement) => {
            Ok(Some(CustodyStanding::Superseded {
                reason: verdict_reason::BOOT_SUPERSEDED,
            }))
        }
        _ => Ok(Some(standing)),
    }
}

fn rekey_inner(
    body: &CustodyRekeyBody,
    req: &CustodyRekeyRequest,
    now: u64,
    deps: &CustodyDeps,
) -> CustodyReply {
    let renew = &body.renew;
    let echo = Echo {
        vm_id: &renew.vm_id,
        generation: renew.generation,
        boot_counter: renew.boot_counter,
        lease_pub: &renew.lease_pub,
        guest_challenge: &renew.guest_challenge,
        seq: renew.seq,
    };
    let (standing, record) =
        match lease_step(renew, &req.body, &req.sig, REKEY_SIG_DOMAIN, now, deps) {
            LeaseOutcome::Reply(CustodyReply::Verdict(v)) => {
                // Public Revoked: a rekey response with no key.
                return CustodyReply::Rekey(CustodyRekeyResponse {
                    verdict: v,
                    wrapped_kek: None,
                });
            }
            LeaseOutcome::Reply(r) => return r,
            LeaseOutcome::Standing { standing, record } => (standing, record),
        };
    if standing != CustodyStanding::Grant {
        return match verdict_for(deps, &echo, standing, now) {
            Ok(Some((verdict, _))) => CustodyReply::Rekey(CustodyRekeyResponse {
                verdict,
                wrapped_kek: None,
            }),
            Ok(None) => match standing {
                CustodyStanding::Retry { reason } => CustodyReply::Retry {
                    status: 503,
                    reason,
                },
                _ => CustodyReply::unavailable(),
            },
            Err(_) => CustodyReply::unavailable(),
        };
    }

    // Customer-held keys: the KEK below is the whole key only in M0 (see
    // `bind_inner`). Checked against the PINNED mode, before any Vault read.
    match pinned_hippius(deps, &renew.vm_id) {
        Ok(true) => {}
        Ok(false) => return CustodyReply::denied(),
        Err(_) => return CustodyReply::unavailable(),
    }

    // The KEK, through the SAME attested Vault capability + per-VM Transit
    // unwrap the release uses. Nothing here touches the boot counter or
    // the volume stamp: this re-serves a key to the attested launch that
    // already held it (its lease key was bound by an attested report and
    // lives only in SNP-encrypted RAM).
    let scope = vault_scope(
        &renew.vm_id,
        &record.scope,
        derive_lifecycle_path(&record.scope.luks_path),
    );
    let kek = match read_kek(deps, &renew.vm_id, &scope, now) {
        Ok(k) => k,
        Err(_) => return CustodyReply::unavailable(),
    };

    // Lifecycle again after the Vault read, as the release does: a fence
    // that landed meanwhile wins, and the key stays here.
    let state = match read_state(deps, &renew.vm_id) {
        Ok(s) => s,
        Err(_) => return CustodyReply::unavailable(),
    };
    let stored = match deps.boot_counter.get(&renew.vm_id) {
        Ok(s) => s,
        Err(_) => return CustodyReply::unavailable(),
    };
    let recheck = custody_standing(
        state.as_ref(),
        stored,
        &CustodyClaim {
            generation: record.generation,
            boot_counter: record.boot_counter,
            node: &record.node,
            lease_id: &record.lease_id,
        },
    );
    let recheck = match within_current_launch(deps, &record, recheck) {
        Ok(Some(s)) => s,
        Ok(None) => return CustodyReply::rebind(),
        Err(_) => return CustodyReply::unavailable(),
    };
    let Ok(Some((verdict, _))) = verdict_for(deps, &echo, recheck, now) else {
        return match recheck {
            CustodyStanding::Retry { reason } => CustodyReply::Retry {
                status: 503,
                reason,
            },
            _ => CustodyReply::unavailable(),
        };
    };
    if recheck != CustodyStanding::Grant {
        return CustodyReply::Rekey(CustodyRekeyResponse {
            verdict,
            wrapped_kek: None,
        });
    }
    let Ok(hpke_pub) = <[u8; KEY_LEN]>::try_from(body.hpke_pub.as_slice()) else {
        return CustodyReply::malformed();
    };
    // AAD = sha256(the exact signed verdict body): the ciphertext opens
    // only next to the Grant it was issued with.
    match hpke_seal_raw(
        &hpke_pub,
        &kek,
        REKEY_HPKE_INFO,
        &rekey_kek_aad(&verdict.body),
    ) {
        Ok((enc, ct)) => CustodyReply::Rekey(CustodyRekeyResponse {
            verdict,
            wrapped_kek: Some(WrappedKek { enc, ct }),
        }),
        Err(_) => CustodyReply::unavailable(),
    }
}

fn read_kek(
    deps: &CustodyDeps,
    vm_id: &str,
    scope: &VaultScope,
    now: u64,
) -> Result<Zeroizing<Vec<u8>>> {
    let cap = redeem(deps, scope, now)?;
    let luks = deps
        .vault_kv
        .read_exact(&cap, &scope.luks_path, scope.luks_version)?;
    if deps.require_wrapped_kek && !luks.starts_with(b"vault:") {
        return Err(KbsError::Policy(
            "require_wrapped_kek: refusing a non-Transit-wrapped (plaintext) KEK at rest".into(),
        ));
    }
    transit_unwrap_if_wrapped(deps.vault_kv, &cap, vm_id, luks)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admin::VmStateRegister;
    use crate::boot_counter::{BootCounterStore, InMemoryBootCounterStore};
    use crate::persist::FileVmStateStore;
    use crate::snp::{VerifiedReport, MEASUREMENT_LEN};
    use crate::vault::{ChallengeVaultAuth, VaultCapability};
    use ciborium::value::Value;
    use coset::CborSerializable;
    use hippius_types::cbor::to_canonical_vec;
    use hippius_types::custody::{CustodyStatus, WrappedKek};
    use std::collections::HashSet;
    use std::sync::Arc;
    use tempfile::TempDir;

    const MEAS: [u8; 48] = [7u8; 48];
    const VM: &str = "abc";
    const LEASE: &str = "lease-1";
    const NOW: u64 = 1_000_000;
    const LIFECYCLE_SEED: [u8; 32] = [0x5e; 32];
    const KEK: &[u8] = b"THE-DISK-KEK";

    struct Kr(Vec<u8>, VerifyingKey);
    impl L1Keyring for Kr {
        fn verifying_key(&self, kid: &[u8]) -> Option<VerifyingKey> {
            (kid == self.0).then_some(self.1)
        }
    }
    struct AllowAll;
    impl MeasurementAllowlist for AllowAll {
        fn contains(&self, _m: &[u8; MEASUREMENT_LEN]) -> bool {
            true
        }
        fn accepts_l1_kid(&self, _m: &[u8; MEASUREMENT_LEN], _k: &[u8]) -> bool {
            true
        }
        fn accepts_kbs_kid(&self, _m: &[u8; MEASUREMENT_LEN], _k: &[u8]) -> bool {
            true
        }
    }
    /// Returns whatever REPORT_DATA the test staged, so a test can hand in
    /// the right binding or a wrong one.
    struct Av(Mutex<[u8; 64]>, [u8; 64], Mutex<u32>);
    impl AttestationVerifier for Av {
        fn verify(&self, _r: &[u8]) -> Result<VerifiedReport> {
            *self.2.lock().unwrap() += 1;
            Ok(VerifiedReport {
                measurement: MEAS,
                report_data: *self.0.lock().unwrap(),
                tcb: 10,
                policy: 0b10,
                chip_id: self.1,
                chain_pem: Vec::new(),
            })
        }
    }
    #[derive(Default)]
    struct Nonces {
        issued: Mutex<HashSet<[u8; 32]>>,
        spent: Mutex<HashSet<[u8; 32]>>,
    }
    impl KbsNonceStore for Nonces {
        fn issue(&self, _now: u64) -> Result<[u8; 32]> {
            Err(KbsError::Replay)
        }
        fn verify_unspent(&self, n: &[u8; 32], _now: u64) -> Result<()> {
            if !self.issued.lock().unwrap().contains(n) || self.spent.lock().unwrap().contains(n) {
                return Err(KbsError::Replay);
            }
            Ok(())
        }
        fn spend(&self, n: &[u8; 32], now: u64) -> Result<()> {
            self.verify_unspent(n, now)?;
            self.spent.lock().unwrap().insert(*n);
            Ok(())
        }
    }
    /// Vault KV that counts reads, so a test can prove renew reads nothing.
    struct Kv(HashMap<String, Vec<u8>>, Mutex<u32>);
    impl VaultKv for Kv {
        fn read_exact(
            &self,
            _c: &VaultCapability,
            path: &str,
            _v: u64,
        ) -> Result<Zeroizing<Vec<u8>>> {
            *self.1.lock().unwrap() += 1;
            self.0
                .get(path)
                .cloned()
                .map(Zeroizing::new)
                .ok_or_else(|| KbsError::VaultNotFound("nf".into()))
        }
        fn transit_decrypt(
            &self,
            _c: &VaultCapability,
            key: &str,
            ct: &[u8],
        ) -> Result<Zeroizing<Vec<u8>>> {
            let s = core::str::from_utf8(ct).unwrap();
            let rest = s
                .strip_prefix(&format!("vault:v1:{key}:"))
                .ok_or_else(|| KbsError::Vault("wrong transit key".into()))?;
            Ok(Zeroizing::new(hex::decode(rest).unwrap()))
        }
    }
    #[derive(Default)]
    struct Audit(Mutex<Vec<(bool, String)>>);
    impl AuditSink for Audit {
        fn record(&self, g: bool, _t: Option<&str>, _v: Option<&str>, reason: &str) {
            self.0.lock().unwrap().push((g, reason.to_string()));
        }
    }
    /// A boot-counter store whose WRITES panic: renew/rekey/bind must only
    /// ever read it.
    struct ReadOnlyCounter(InMemoryBootCounterStore);
    impl BootCounterStore for ReadOnlyCounter {
        fn check_only(&self, vm_id: &str, s: u64) -> Result<u64> {
            self.0.check_only(vm_id, s)
        }
        fn commit(&self, _vm_id: &str, _v: u64) -> Result<()> {
            panic!("custody must never commit a boot counter")
        }
        fn get(&self, vm_id: &str) -> Result<u64> {
            self.0.get(vm_id)
        }
        fn seed(&self, _vm_id: &str, _v: u64) -> Result<crate::boot_counter::SeedOutcome> {
            panic!("custody must never seed a boot counter")
        }
        fn arm_resync(&self, _vm_id: &str) -> Result<crate::boot_counter::ResyncOutcome> {
            panic!("custody must never arm a resync")
        }
        fn resync_armed(&self, vm_id: &str) -> Result<bool> {
            self.0.resync_armed(vm_id)
        }
    }

    fn ticket(gen: u64, plat: &str, l1: &SigningKey) -> Vec<u8> {
        ticket_keyed(gen, plat, l1, None)
    }

    fn ticket_keyed(gen: u64, plat: &str, l1: &SigningKey, key_mode: Option<&str>) -> Vec<u8> {
        let digest = hippius_types::digest::userdata_digest(
            "t",
            VM,
            "tk-1",
            "userdata",
            "kbs/vm/abc/ud",
            2,
            b"ud",
        )
        .to_vec();
        let mut entries = vec![
            (
                Value::Text("allowed_measurements".into()),
                Value::Array(vec![Value::Bytes(MEAS.to_vec())]),
            ),
            (
                Value::Text("allowed_userdata_digest".into()),
                Value::Bytes(digest),
            ),
            // Long expired at NOW: the bind must not care.
            (Value::Text("expiry".into()), Value::Integer(999.into())),
            (Value::Text("issue_time".into()), Value::Integer(100.into())),
            (Value::Text("lease_id".into()), Value::Text(LEASE.into())),
            (Value::Text("lifecycle_perms".into()), Value::Array(vec![])),
            (
                Value::Text("luks_vault_ref".into()),
                Value::Map(vec![
                    (
                        Value::Text("path".into()),
                        Value::Text("kbs/vm/abc/luks-kek".into()),
                    ),
                    (Value::Text("version".into()), Value::Integer(3.into())),
                ]),
            ),
            (Value::Text("node_id".into()), Value::Text(plat.into())),
            (Value::Text("nonce".into()), Value::Bytes(vec![1u8; 32])),
            (Value::Text("platform_id".into()), Value::Text(plat.into())),
            (Value::Text("flavor".into()), Value::Text("small".into())),
            (Value::Text("tenant_id".into()), Value::Text("t".into())),
            (Value::Text("ticket_id".into()), Value::Text("tk-1".into())),
            (Value::Text("user_id".into()), Value::Text("u".into())),
            (
                Value::Text("userdata_vault_ref".into()),
                Value::Map(vec![
                    (
                        Value::Text("path".into()),
                        Value::Text("kbs/vm/abc/ud".into()),
                    ),
                    (Value::Text("version".into()), Value::Integer(2.into())),
                ]),
            ),
            (Value::Text("v".into()), Value::Integer(2.into())),
            (
                Value::Text("vm_generation".into()),
                Value::Integer(gen.into()),
            ),
            (Value::Text("vm_id".into()), Value::Text(VM.into())),
        ];
        if let Some(mode) = key_mode {
            entries.push((Value::Text("key_mode".into()), Value::Text(mode.into())));
        }
        let payload = to_canonical_vec(&Value::Map(entries)).unwrap();
        let protected = coset::HeaderBuilder::new()
            .algorithm(coset::iana::Algorithm::EdDSA)
            .key_id(b"l1".to_vec())
            .build();
        coset::CoseSign1Builder::new()
            .protected(protected)
            .payload(payload)
            .create_signature(b"", |t| l1.sign(t).to_bytes().to_vec())
            .build()
            .to_vec()
            .unwrap()
    }

    struct Rig {
        _td: TempDir,
        kr: Kr,
        av: Av,
        al: AllowAll,
        lp: LaunchPolicy,
        st: Arc<FileVmStateStore>,
        nonces: Nonces,
        va: ChallengeVaultAuth<fn(&[u8; 48]) -> bool>,
        kv: Kv,
        kbs_rep: VerifiedReport,
        kbs_sk: SigningKey,
        audit: Audit,
        counter: ReadOnlyCounter,
        runtime: CustodyRuntime,
        l1: SigningKey,
        plat: String,
        /// The CURRENT lease key; every bind must carry a fresh one.
        lease_sk: std::cell::RefCell<SigningKey>,
    }

    impl Rig {
        /// VM `abc` Active at gen 5 on `plat`, boot counter 7, pinned M0.
        fn new() -> Self {
            Self::pinned(hippius_types::guardian::KeyMode::Hippius)
        }

        /// A store holding VM `abc` Active at gen 5 on `plat`, pinned to
        /// `mode` at register.
        fn store(
            dir: &std::path::Path,
            plat: &str,
            mode: hippius_types::guardian::KeyMode,
        ) -> Arc<FileVmStateStore> {
            let st = Arc::new(FileVmStateStore::open(dir.join("vm.json")).unwrap());
            st.register(
                VM,
                VmState::Active {
                    gen: 5,
                    host: plat.into(),
                    lease_id: LEASE.into(),
                },
                mode,
            )
            .unwrap();
            st
        }

        /// As [`Rig::new`], with the VM pinned to `mode`.
        fn pinned(mode: hippius_types::guardian::KeyMode) -> Self {
            let td = TempDir::new().unwrap();
            let chip = [0xabu8; 64];
            let plat = hex::encode(&chip[..8]);
            let st = Self::store(td.path(), &plat, mode);
            let counter = InMemoryBootCounterStore::default();
            counter.commit(VM, 7).unwrap();
            let l1 = SigningKey::from_bytes(&[42u8; 32]);
            let mut kvm = HashMap::new();
            kvm.insert("kbs/vm/abc/lifecycle-key".into(), LIFECYCLE_SEED.to_vec());
            kvm.insert(
                "kbs/vm/abc/luks-kek".into(),
                format!("vault:v1:kek-abc:{}", hex::encode(KEK)).into_bytes(),
            );
            let ok: fn(&[u8; 48]) -> bool = |_m| true;
            Self {
                _td: td,
                kr: Kr(b"l1".to_vec(), l1.verifying_key()),
                av: Av(Mutex::new([0u8; 64]), chip, Mutex::new(0)),
                al: AllowAll,
                lp: LaunchPolicy {
                    min_tcb: 1,
                    required_bits: 0b10,
                    allowed_mask: 0b1101,
                },
                st,
                nonces: Nonces::default(),
                va: ChallengeVaultAuth {
                    kbs_measurement_ok: ok,
                    policy: LaunchPolicy {
                        min_tcb: 1,
                        required_bits: 0,
                        allowed_mask: u64::MAX,
                    },
                    challenge_ttl: 60,
                    cap_ttl: 60,
                    challenge_nonce: [2u8; 32],
                },
                kv: Kv(kvm, Mutex::new(0)),
                kbs_rep: VerifiedReport {
                    measurement: MEAS,
                    report_data: [0; 64],
                    tcb: 5,
                    policy: 0,
                    chip_id: [0; 64],
                    chain_pem: Vec::new(),
                },
                kbs_sk: SigningKey::from_bytes(&[9u8; 32]),
                audit: Audit::default(),
                counter: ReadOnlyCounter(counter),
                runtime: CustodyRuntime::new(
                    Arc::new(MapCustodyStore::in_memory()),
                    CustodyPolicy::default(),
                    SkewConfig::default(),
                )
                .unwrap(),
                l1,
                plat,
                lease_sk: std::cell::RefCell::new(SigningKey::from_bytes(&[0x1e; 32])),
            }
        }

        fn deps(&self) -> CustodyDeps<'_> {
            CustodyDeps {
                l1_keyring: &self.kr,
                attn: &self.av,
                offline_allowlist: &self.al,
                launch_policy: &self.lp,
                vm_states: self.st.as_ref(),
                kbs_nonce_store: &self.nonces,
                vault_auth: &self.va,
                vault_kv: &self.kv,
                kbs_attestation: &self.kbs_rep,
                kbs_auth_pubkey: b"kbs-pub",
                kbs_signing_key: &self.kbs_sk,
                kbs_kid: b"kbs-kid",
                audit: &self.audit,
                boot_counter: &self.counter,
                require_wrapped_kek: true,
                runtime: &self.runtime,
            }
        }

        fn lease_pub(&self) -> [u8; 32] {
            self.lease_sk.borrow().verifying_key().to_bytes()
        }

        /// What a guest daemon does before every re-bind.
        fn rotate_lease_key(&self, seed: u8) {
            *self.lease_sk.borrow_mut() = SigningKey::from_bytes(&[seed; 32]);
        }

        /// A well-formed bind for (gen, N), with a matching attested
        /// REPORT_DATA staged and a fresh nonce issued.
        fn bind_body(&self, gen: u64, n: u64, nonce: [u8; 32]) -> CustodyBindBody {
            self.nonces.issued.lock().unwrap().insert(nonce);
            let rd =
                hippius_types::report_data::custody_bind(&nonce, VM, gen, n, &self.lease_pub())
                    .unwrap();
            *self.av.0.lock().unwrap() = rd;
            CustodyBindBody {
                v: 1,
                vm_id: VM.into(),
                generation: gen,
                boot_counter: n,
                cose_ticket: ticket(gen, &self.plat, &self.l1),
                kbs_nonce: nonce.to_vec(),
                snp_report: vec![0u8; 1184],
                lease_pub: self.lease_pub().to_vec(),
                guest_challenge: vec![0xc0; 32],
                tsc: 1,
                // Later binds (higher nonce byte) read a later clock.
                mono_ms: 50_000 + (u64::from(nonce[0]) - 1) * 1_000,
                clock_mode: 0,
            }
        }

        fn signed_bind(
            &self,
            body: &CustodyBindBody,
            lifecycle: &SigningKey,
        ) -> CustodyBindRequest {
            let bytes = encode_canonical(body).unwrap();
            let sig = lifecycle.sign(&signing_input(BIND_SIG_DOMAIN, &bytes));
            CustodyBindRequest {
                body: bytes,
                lifecycle_sig: sig.to_bytes().to_vec(),
            }
        }

        fn bind(&self, gen: u64, n: u64, nonce: u8) -> CustodyReply {
            let body = self.bind_body(gen, n, [nonce; 32]);
            let req = self.signed_bind(&body, &SigningKey::from_bytes(&LIFECYCLE_SEED));
            process_bind(&req, NOW, &self.deps())
        }

        fn renew_body(&self, seq: u64, mono_ms: u64) -> CustodyRenewBody {
            CustodyRenewBody {
                v: 1,
                vm_id: VM.into(),
                generation: 5,
                boot_counter: 7,
                lease_pub: self.lease_pub().to_vec(),
                seq,
                guest_challenge: vec![seq as u8; 32],
                tsc: 2,
                mono_ms,
                clock_mode: 0,
                status: CustodyStatus {
                    phase: 0,
                    since_last_grant_s: 600,
                    suspended_s: 0,
                },
            }
        }

        fn renew_at(&self, seq: u64, mono_ms: u64, now: u64) -> CustodyReply {
            let body = encode_canonical(&self.renew_body(seq, mono_ms)).unwrap();
            let sig = self
                .lease_sk
                .borrow()
                .sign(&signing_input(RENEW_SIG_DOMAIN, &body));
            process_renew(
                &CustodyRenewRequest {
                    body,
                    sig: sig.to_bytes().to_vec(),
                },
                now,
                &self.deps(),
            )
        }

        fn renew(&self, seq: u64) -> CustodyReply {
            self.renew_at(seq, 50_000 + seq * 600_000, NOW + seq * 600)
        }

        fn rekey(&self, seq: u64, hpke_pub: [u8; 32]) -> CustodyReply {
            let body = CustodyRekeyBody {
                v: 1,
                hpke_pub: hpke_pub.to_vec(),
                renew: self.renew_body(seq, 50_000 + seq * 1_000),
            };
            let bytes = encode_canonical(&body).unwrap();
            let sig = self
                .lease_sk
                .borrow()
                .sign(&signing_input(REKEY_SIG_DOMAIN, &bytes));
            process_rekey(
                &CustodyRekeyRequest {
                    body: bytes,
                    sig: sig.to_bytes().to_vec(),
                },
                NOW + seq,
                &self.deps(),
            )
        }

        fn verdict(&self, r: &CustodyReply) -> CustodyVerdictBody {
            let signed = match r {
                CustodyReply::Verdict(v) => v,
                CustodyReply::Rekey(k) => &k.verdict,
                CustodyReply::Retry { status, reason } => {
                    panic!("expected a verdict, got {status} {reason}")
                }
            };
            verify_verdict(&self.kbs_sk.verifying_key(), signed).unwrap()
        }
    }

    fn is_retry(r: &CustodyReply) -> bool {
        matches!(r, CustodyReply::Retry { .. })
    }

    // ── bind ──────────────────────────────────────────────────────────

    #[test]
    fn a_valid_bind_is_granted_and_records_the_lease_key() {
        let rig = Rig::new();
        let v = rig.verdict(&rig.bind(5, 7, 1));
        assert_eq!(v.verdict, Verdict::Grant as u8);
        assert_eq!(v.lease_pub_hash, lease_pub_hash(&rig.lease_pub()).to_vec());
        assert_eq!(v.guest_challenge, vec![0xc0; 32]);
        assert_eq!((v.generation, v.boot_counter, v.seq), (5, 7, 0));
        assert_eq!(v.ttl_s, CustodyPolicy::default().ttl_s);
        assert_eq!(v.deadline_tsc, None);
        let rec = rig.runtime.store.get(VM).unwrap().unwrap();
        assert_eq!(rec.lease_pub, rig.lease_pub());
        assert_eq!(rec.node, rig.plat);
        // The nonce is single-use.
        assert!(rig.nonces.spent.lock().unwrap().contains(&[1u8; 32]));
    }

    #[test]
    fn a_bind_signed_by_any_key_but_the_vms_lifecycle_key_is_refused() {
        // The miner's own golden VM: same measurement, same host, a valid
        // report bound to ITS lease key — but not the victim's lifecycle
        // signature.
        let rig = Rig::new();
        let body = rig.bind_body(5, 7, [1; 32]);
        let req = rig.signed_bind(&body, &SigningKey::from_bytes(&[0x66; 32]));
        let r = process_bind(&req, NOW, &rig.deps());
        assert_eq!(r, CustodyReply::denied());
        assert!(rig.runtime.store.get(VM).unwrap().is_none());
        // …and the nonce was not burned by the refused attempt.
        assert!(rig.nonces.spent.lock().unwrap().is_empty());
    }

    #[test]
    fn a_bind_whose_report_does_not_bind_the_lease_key_is_refused() {
        // A relay that swaps lease_pub (and re-signs nothing) breaks the
        // REPORT_DATA binding.
        let rig = Rig::new();
        let body = rig.bind_body(5, 7, [1; 32]);
        let other =
            hippius_types::report_data::custody_bind(&[1; 32], VM, 5, 7, &[0x77; 32]).unwrap();
        *rig.av.0.lock().unwrap() = other;
        let req = rig.signed_bind(&body, &SigningKey::from_bytes(&LIFECYCLE_SEED));
        assert_eq!(process_bind(&req, NOW, &rig.deps()), CustodyReply::denied());
    }

    #[test]
    fn a_release_shaped_report_cannot_bind() {
        // REPORT_DATA = nonce ‖ x25519 (the release layout) is not the
        // custody binding.
        let rig = Rig::new();
        let body = rig.bind_body(5, 7, [1; 32]);
        let rd = hippius_types::report_data::tenant(&[1; 32], &rig.lease_pub());
        *rig.av.0.lock().unwrap() = rd;
        let req = rig.signed_bind(&body, &SigningKey::from_bytes(&LIFECYCLE_SEED));
        assert_eq!(process_bind(&req, NOW, &rig.deps()), CustodyReply::denied());
    }

    #[test]
    fn a_bind_must_present_the_ticket_of_its_own_generation() {
        // An older generation's ticket (other measurements, other
        // placement) cannot vouch for a bind at the current one.
        let rig = Rig::new();
        let mut body = rig.bind_body(5, 7, [1; 32]);
        body.cose_ticket = ticket(4, &rig.plat, &rig.l1);
        let req = rig.signed_bind(&body, &SigningKey::from_bytes(&LIFECYCLE_SEED));
        assert_eq!(process_bind(&req, NOW, &rig.deps()), CustodyReply::denied());
    }

    #[test]
    fn a_bind_under_customer_held_keys_is_refused() {
        // A rekey returns the Vault KEK as the WHOLE key: wrong in M1
        // (it is only share_H) and impossible in M2 (there is none). So
        // custody binds M0 only, until the guardian rerelease exists.
        for mode in ["split", "customer"] {
            let rig = Rig::new();
            let mut body = rig.bind_body(5, 7, [1; 32]);
            body.cose_ticket = ticket_keyed(5, &rig.plat, &rig.l1, Some(mode));
            let req = rig.signed_bind(&body, &SigningKey::from_bytes(&LIFECYCLE_SEED));
            assert_eq!(
                process_bind(&req, NOW, &rig.deps()),
                CustodyReply::denied(),
                "{mode}"
            );
        }
    }

    #[test]
    fn an_m0_ticket_for_a_vm_pinned_customer_held_is_refused_at_bind() {
        // The PINNED mode decides, not the ticket: an M0 ticket (no
        // key_mode) presented for a VM registered M1/M2 binds nothing.
        use hippius_types::guardian::KeyMode;
        for mode in [KeyMode::Split, KeyMode::Customer] {
            let rig = Rig::pinned(mode);
            assert_eq!(rig.bind(5, 7, 1), CustodyReply::denied(), "{mode:?}");
        }
        // Control: the same bind on an M0-pinned VM is granted.
        let rig = Rig::new();
        assert_eq!(
            rig.verdict(&rig.bind(5, 7, 1)).verdict,
            Verdict::Grant as u8
        );
    }

    #[test]
    fn a_rekey_for_a_vm_pinned_customer_held_carries_no_key() {
        // A lease bound under M0, then the store pins the VM M1/M2 (e.g.
        // re-seeded after a KBS restart): rekey checks the PINNED mode and
        // refuses before any Vault read.
        use hippius_types::guardian::KeyMode;
        for mode in [KeyMode::Split, KeyMode::Customer] {
            let mut rig = Rig::new();
            assert_eq!(
                rig.verdict(&rig.bind(5, 7, 1)).verdict,
                Verdict::Grant as u8
            );
            let td = TempDir::new().unwrap();
            rig.st = Rig::store(td.path(), &rig.plat, mode);
            let reads = *rig.kv.1.lock().unwrap();
            let (pk, _) = crate::crypto::test_support::gen_x25519();
            assert_eq!(rig.rekey(1, pk), CustodyReply::denied(), "{mode:?}");
            assert_eq!(*rig.kv.1.lock().unwrap(), reads, "no Vault read: {mode:?}");
        }
    }

    #[test]
    fn a_bind_from_another_host_is_refused() {
        let mut rig = Rig::new();
        rig.av.1 = [0xcd; 64];
        assert_eq!(rig.bind(5, 7, 1), CustodyReply::denied());
    }

    #[test]
    fn a_replayed_bind_nonce_is_refused() {
        let rig = Rig::new();
        assert!(!is_retry(&rig.bind(5, 7, 1)));
        let body = rig.bind_body(5, 7, [1; 32]);
        rig.nonces.spent.lock().unwrap().insert([1; 32]);
        let req = rig.signed_bind(&body, &SigningKey::from_bytes(&LIFECYCLE_SEED));
        assert_eq!(process_bind(&req, NOW, &rig.deps()), CustodyReply::denied());
    }

    #[test]
    fn a_bind_with_an_unissued_nonce_never_reaches_the_report_verifier() {
        // The verifier may fetch from AMD KDS; only a KBS-minted nonce
        // earns that work.
        let rig = Rig::new();
        let body = rig.bind_body(5, 7, [1; 32]);
        rig.nonces.issued.lock().unwrap().clear();
        let req = rig.signed_bind(&body, &SigningKey::from_bytes(&LIFECYCLE_SEED));
        assert_eq!(process_bind(&req, NOW, &rig.deps()), CustodyReply::denied());
        assert_eq!(*rig.av.2.lock().unwrap(), 0);
    }

    #[test]
    fn bind_never_advances_the_boot_counter() {
        // ReadOnlyCounter panics on any write; N == stored is the gate.
        let rig = Rig::new();
        assert!(!is_retry(&rig.bind(5, 7, 1)));
        assert_eq!(rig.counter.get(VM).unwrap(), 7);
        // N = stored + 1 (what a RELEASE submits) is not a bind.
        assert!(is_retry(&rig.bind(5, 8, 2)));
    }

    #[test]
    fn an_older_boot_bind_is_superseded_only_once_the_newer_boot_has_bound() {
        let rig = Rig::new();
        // Stored counter 7, bind at 6, no binding for boot 7: this could be
        // a counter re-seeded from the miner's own disk — never a kill.
        assert_eq!(
            rig.bind(5, 6, 1),
            CustodyReply::Retry {
                status: 503,
                reason: retry_reason::UNKNOWN_VM
            }
        );
        assert!(rig.runtime.store.get(VM).unwrap().is_none());
        // Once boot 7 has bound, boot 6 is positively a stale copy.
        assert!(!is_retry(&rig.bind(5, 7, 2)));
        rig.rotate_lease_key(0x2e);
        let v = rig.verdict(&rig.bind(5, 6, 3));
        assert_eq!(v.verdict, Verdict::Superseded as u8);
        assert_eq!(v.reason, verdict_reason::BOOT_SUPERSEDED);
        assert_eq!(rig.runtime.store.get(VM).unwrap().unwrap().boot_counter, 7);
    }

    #[test]
    fn a_bind_after_a_kbs_wipe_is_a_retry_not_a_kill() {
        // Fresh store: no VM row and no counter (the pod restarted and the
        // recovery ceremony has not run yet).
        let rig = Rig::new();
        let wiped = FileVmStateStore::open(rig._td.path().join("wiped.json")).unwrap();
        let empty_counter = ReadOnlyCounter(InMemoryBootCounterStore::default());
        let mut deps = rig.deps();
        deps.vm_states = &wiped;
        deps.boot_counter = &empty_counter;
        let body = rig.bind_body(5, 7, [1; 32]);
        let req = rig.signed_bind(&body, &SigningKey::from_bytes(&LIFECYCLE_SEED));
        let r = process_bind(&req, NOW, &deps);
        assert_eq!(
            r,
            CustodyReply::Retry {
                status: 503,
                reason: retry_reason::UNKNOWN_VM
            }
        );
    }

    #[test]
    fn a_decommissioned_vm_is_revoked_without_any_verification() {
        // No valid report, no signature, KDS could be down: Revoked is a
        // public fact.
        let rig = Rig::new();
        rig.st.decommission(VM).unwrap();
        let body = rig.bind_body(5, 7, [1; 32]);
        *rig.av.0.lock().unwrap() = [0; 64];
        let req = CustodyBindRequest {
            body: encode_canonical(&body).unwrap(),
            lifecycle_sig: vec![0; 64],
        };
        let v = rig.verdict(&process_bind(&req, NOW, &rig.deps()));
        assert_eq!(v.verdict, Verdict::Revoked as u8);
        assert_eq!(v.reason, verdict_reason::DECOMMISSIONING);
    }

    #[test]
    fn the_lifecycle_key_is_read_from_vault_once_then_cached() {
        let rig = Rig::new();
        rig.bind(5, 7, 1);
        let reads = *rig.kv.1.lock().unwrap();
        assert_eq!(reads, 1);
        rig.rotate_lease_key(0x2e);
        assert!(!is_retry(&rig.bind(5, 7, 2))); // daemon restart ⇒ rebind
        assert_eq!(*rig.kv.1.lock().unwrap(), 1);
        assert_eq!(rig.runtime.store.get(VM).unwrap().unwrap().rebinds.len(), 2);
    }

    #[test]
    fn a_same_boot_rebind_keeps_the_skew_baseline_and_flag() {
        // A miner that forges `rebind-required` every hour must not be
        // able to reset the skew window.
        let rig = Rig::new();
        rig.bind(5, 7, 1); // mono 50_000 at NOW
        rig.renew_at(1, 50_000 + 3_600_000, NOW + 7_200); // 2 h vs 1 h: flagged
        assert!(rig.runtime.store.get(VM).unwrap().unwrap().skew_suspected);
        rig.rotate_lease_key(0x2e);
        let body = rig.bind_body(5, 7, [2; 32]);
        // The rebind itself reads an honest clock (lag 10 s), so only the
        // copied flag can keep the earlier finding.
        let body = CustodyBindBody {
            mono_ms: 50_000 + 7_290_000,
            ..body
        };
        let req = rig.signed_bind(&body, &SigningKey::from_bytes(&LIFECYCLE_SEED));
        assert!(!is_retry(&process_bind(&req, NOW + 7_300, &rig.deps())));
        let rec = rig.runtime.store.get(VM).unwrap().unwrap();
        assert_eq!((rec.bound_at, rec.bind_mono_ms), (NOW, 50_000));
        assert!(rec.skew_suspected, "the flag survives the rebind");
        assert_eq!(rec.lease_pub, rig.lease_pub());
    }

    #[test]
    fn a_rebind_is_itself_a_clock_sample() {
        let rig = Rig::new();
        rig.bind(5, 7, 1);
        rig.rotate_lease_key(0x2e);
        let body = rig.bind_body(5, 7, [2; 32]);
        // Two hours on the KBS, one on the guest — seen at the rebind.
        let body = CustodyBindBody {
            mono_ms: 50_000 + 3_600_000,
            ..body
        };
        let req = rig.signed_bind(&body, &SigningKey::from_bytes(&LIFECYCLE_SEED));
        assert!(!is_retry(&process_bind(&req, NOW + 7_200, &rig.deps())));
        assert!(rig.runtime.store.get(VM).unwrap().unwrap().skew_suspected);
    }

    #[test]
    fn a_withheld_older_bind_or_a_reused_lease_key_never_replaces_the_binding() {
        let rig = Rig::new();
        // Guest binds twice (daemon restart); the miner withholds the
        // FIRST and delivers it after the second.
        let first = rig.bind_body(5, 7, [1; 32]);
        let first = rig.signed_bind(&first, &SigningKey::from_bytes(&LIFECYCLE_SEED));
        rig.rotate_lease_key(0x2e);
        assert!(!is_retry(&rig.bind(5, 7, 2)));
        let bound = rig.runtime.store.get(VM).unwrap().unwrap();
        *rig.av.0.lock().unwrap() = hippius_types::report_data::custody_bind(
            &[1; 32],
            VM,
            5,
            7,
            &SigningKey::from_bytes(&[0x1e; 32])
                .verifying_key()
                .to_bytes(),
        )
        .unwrap();
        assert_eq!(
            process_bind(&first, NOW, &rig.deps()),
            CustodyReply::Retry {
                status: 503,
                reason: "stale-bind"
            }
        );
        assert_eq!(
            rig.runtime.store.get(VM).unwrap().unwrap().lease_pub,
            bound.lease_pub
        );
        // Same boot, later clock, but the SAME lease key: refused too.
        let again = rig.bind_body(5, 7, [3; 32]);
        let again = rig.signed_bind(&again, &SigningKey::from_bytes(&LIFECYCLE_SEED));
        assert_eq!(
            process_bind(&again, NOW, &rig.deps()),
            CustodyReply::Retry {
                status: 503,
                reason: "stale-bind"
            }
        );
    }

    #[test]
    fn a_same_boot_bind_must_move_past_the_latest_renew_clock() {
        let rig = Rig::new();
        rig.bind(5, 7, 1); // mono 50_000
        rig.renew_at(1, 900_000, NOW + 850);
        rig.rotate_lease_key(0x2e);
        // Newer than the bind, older than the renew the KBS accepted.
        let body = rig.bind_body(5, 7, [2; 32]);
        let body = CustodyBindBody {
            mono_ms: 500_000,
            ..body
        };
        let req = rig.signed_bind(&body, &SigningKey::from_bytes(&LIFECYCLE_SEED));
        assert_eq!(
            process_bind(&req, NOW + 900, &rig.deps()),
            CustodyReply::Retry {
                status: 503,
                reason: "stale-bind"
            }
        );
    }

    #[test]
    fn the_store_never_lets_an_older_boot_replace_a_newer_binding() {
        let store = MapCustodyStore::in_memory();
        let rec = |gen, n, key: u8, mono| CustodyRecord {
            vm_id: VM.into(),
            generation: gen,
            boot_counter: n,
            lease_pub: [key; 32],
            last_mono_ms: mono,
            ..Default::default()
        };
        assert!(matches!(
            store.bind(rec(5, 8, 1, 10), &|_| {}).unwrap(),
            BindOutcome::Bound { .. }
        ));
        assert_eq!(
            store.bind(rec(5, 7, 2, 99), &|_| {}).unwrap(),
            BindOutcome::OlderBoot
        );
        assert_eq!(
            store.bind(rec(4, 9, 3, 99), &|_| {}).unwrap(),
            BindOutcome::OlderBoot
        );
        assert_eq!(store.get(VM).unwrap().unwrap().lease_pub, [1; 32]);
        // A newer boot replaces with a FRESH baseline.
        assert!(matches!(
            store.bind(rec(6, 1, 4, 5), &|_| {}).unwrap(),
            BindOutcome::Bound { .. }
        ));
        assert_eq!(store.get(VM).unwrap().unwrap().bind_mono_ms, 0);
    }

    #[test]
    fn the_migration_destination_binds_at_the_new_generation() {
        let rig = Rig::new();
        rig.st.activate(VM, 6, &rig.plat).unwrap();
        // The destination's first boot at gen 6 commits counter 8.
        rig.counter.0.commit(VM, 8).unwrap();
        let v = rig.verdict(&rig.bind(6, 8, 1));
        assert_eq!(v.verdict, Verdict::Grant as u8);
        assert_eq!(v.generation, 6);
    }

    #[test]
    fn a_flood_cannot_drain_a_guests_budget_but_the_guest_itself_is_bounded() {
        let rig = Rig::new();
        rig.bind(5, 7, 1);
        // Junk signatures never touch the per-VM bucket…
        for _ in 0..50 {
            let body = encode_canonical(&rig.renew_body(1, 60_000)).unwrap();
            let r = process_renew(
                &CustodyRenewRequest {
                    body,
                    sig: vec![0; 64],
                },
                NOW,
                &rig.deps(),
            );
            assert_eq!(r, CustodyReply::denied());
        }
        assert!(!is_retry(&rig.renew_at(1, 60_000, NOW)));
        // …while a looping guest is cut off after its burst.
        let mut limited = false;
        for seq in 2..40 {
            if rig.renew_at(seq, 60_000 + seq, NOW)
                == (CustodyReply::Retry {
                    status: 429,
                    reason: "rate-limited",
                })
            {
                limited = true;
                break;
            }
        }
        assert!(limited);
    }

    // ── renew ─────────────────────────────────────────────────────────

    #[test]
    fn renew_grants_with_the_bound_lease_key_and_touches_no_vault() {
        let rig = Rig::new();
        rig.bind(5, 7, 1);
        let reads = *rig.kv.1.lock().unwrap();
        let v = rig.verdict(&rig.renew(1));
        assert_eq!(v.verdict, Verdict::Grant as u8);
        assert_eq!(v.seq, 1);
        assert_eq!(v.guest_challenge, vec![1u8; 32]);
        assert_eq!(*rig.kv.1.lock().unwrap(), reads, "renew never reads Vault");
        let rec = rig.runtime.store.get(VM).unwrap().unwrap();
        assert_eq!(rec.last_seq, 1);
        assert_eq!(rec.last_grant_at, Some(NOW + 600));
    }

    #[test]
    fn a_replayed_or_reordered_renew_is_refused() {
        let rig = Rig::new();
        rig.bind(5, 7, 1);
        assert!(!is_retry(&rig.renew(2)));
        assert_eq!(
            rig.renew(2),
            CustodyReply::Retry {
                status: 409,
                reason: "stale-seq"
            }
        );
        assert_eq!(
            rig.renew(1),
            CustodyReply::Retry {
                status: 409,
                reason: "stale-seq"
            }
        );
        assert!(!is_retry(&rig.renew(3)));
    }

    #[test]
    fn a_renew_not_signed_by_the_lease_key_is_refused_and_does_not_advance_seq() {
        let rig = Rig::new();
        rig.bind(5, 7, 1);
        let body = encode_canonical(&rig.renew_body(1, 60_000)).unwrap();
        let sig = SigningKey::from_bytes(&[0x99; 32]).sign(&signing_input(RENEW_SIG_DOMAIN, &body));
        let r = process_renew(
            &CustodyRenewRequest {
                body,
                sig: sig.to_bytes().to_vec(),
            },
            NOW,
            &rig.deps(),
        );
        assert_eq!(r, CustodyReply::denied());
        assert_eq!(rig.runtime.store.get(VM).unwrap().unwrap().last_seq, 0);
        // A lease signature under the REKEY domain is not a renew either.
        let body = encode_canonical(&rig.renew_body(1, 60_000)).unwrap();
        let sig = rig
            .lease_sk
            .borrow()
            .sign(&signing_input(REKEY_SIG_DOMAIN, &body));
        let r = process_renew(
            &CustodyRenewRequest {
                body,
                sig: sig.to_bytes().to_vec(),
            },
            NOW,
            &rig.deps(),
        );
        assert_eq!(r, CustodyReply::denied());
    }

    #[test]
    fn renew_with_an_unknown_lease_key_asks_for_a_rebind() {
        let rig = Rig::new();
        // No bind at all (KBS restarted): rebind-required, not a kill.
        assert_eq!(rig.renew(1), CustodyReply::rebind());
    }

    #[test]
    fn renew_after_the_fence_is_revoked_even_without_a_binding() {
        let rig = Rig::new();
        rig.st.decommission(VM).unwrap();
        let v = rig.verdict(&rig.renew(1));
        assert_eq!(v.verdict, Verdict::Revoked as u8);
        rig.st.tombstone(VM, 5).unwrap();
        assert_eq!(rig.verdict(&rig.renew(2)).reason, verdict_reason::DESTROYED);
    }

    #[test]
    fn a_newer_boot_supersedes_the_old_instance() {
        let rig = Rig::new();
        rig.bind(5, 7, 1);
        // A second instance booted from a disk copy committed N = 8.
        rig.counter.0.commit(VM, 8).unwrap();
        let v = rig.verdict(&rig.renew(1));
        assert_eq!(v.verdict, Verdict::Superseded as u8);
        assert_eq!(v.reason, verdict_reason::BOOT_SUPERSEDED);
    }

    #[test]
    fn a_migration_supersedes_the_source() {
        let rig = Rig::new();
        rig.bind(5, 7, 1);
        rig.st.activate(VM, 6, "dest-node").unwrap();
        let v = rig.verdict(&rig.renew(1));
        assert_eq!(v.verdict, Verdict::Superseded as u8);
        assert_eq!(v.reason, verdict_reason::GENERATION_SUPERSEDED);
    }

    #[test]
    fn a_verdict_is_signed_under_the_custody_domain_only() {
        let rig = Rig::new();
        let r = rig.bind(5, 7, 1);
        let CustodyReply::Verdict(signed) = &r else {
            panic!()
        };
        let vk = rig.kbs_sk.verifying_key();
        let sig = Signature::from_slice(&signed.sig).unwrap();
        // Not a signature over the bare body (what the release response,
        // the denial and the live attestation sign).
        assert!(vk.verify_strict(&signed.body, &sig).is_err());
        // Not a release response either.
        let as_release = crate::crypto::verify_response(
            &vk,
            &hippius_types::release::SignedResponse {
                body: signed.body.clone(),
                sig: signed.sig.clone(),
            },
        );
        assert!(as_release.is_err());
        verify_verdict(&vk, signed).unwrap();
        assert_eq!(signed.kid, b"kbs-kid".to_vec());
    }

    #[test]
    fn skew_is_flagged_when_the_guest_clock_runs_slow() {
        let rig = Rig::new();
        rig.bind(5, 7, 1); // bind: mono 50_000 at NOW
                           // Two hours later on the KBS, the guest says ONE hour passed.
        rig.renew_at(1, 50_000 + 3_600_000, NOW + 7_200);
        let rec = rig.runtime.store.get(VM).unwrap().unwrap();
        assert!(rec.skew_suspected);
        assert_eq!(rec.lag_s, 3_600);
    }

    #[test]
    fn an_honest_guest_clock_is_not_flagged() {
        let rig = Rig::new();
        rig.bind(5, 7, 1);
        // Two hours, delivered 30 s late.
        rig.renew_at(1, 50_000 + 7_200_000, NOW + 7_230);
        let rec = rig.runtime.store.get(VM).unwrap().unwrap();
        assert!(!rec.skew_suspected);
        assert_eq!(rec.lag_s, 30);
    }

    #[test]
    fn clock_lag_rules() {
        let rig = Rig::new();
        rig.bind(5, 7, 1);
        let rec = rig.runtime.store.get(VM).unwrap().unwrap();
        let skew = SkewConfig::default();
        // Before the window: never a verdict, whatever the lag.
        assert_eq!(clock_lag(&rec, 50_000, NOW + 3_000, &skew), (3_000, false));
        // A monotonic clock that went backwards is always suspect.
        assert!(clock_lag(&rec, 1_000, NOW + 10, &skew).1);
        // 1% of a 100 000 s window = 1 000 s allowed.
        let t = NOW + 100_000;
        assert!(!clock_lag(&rec, 50_000 + 99_000_000, t, &skew).1);
        assert!(clock_lag(&rec, 50_000 + 98_999_000 - 1_000, t, &skew).1);
    }

    // ── rekey ─────────────────────────────────────────────────────────

    #[test]
    fn rekey_returns_the_kek_sealed_to_the_fresh_key_and_bound_to_the_verdict() {
        let rig = Rig::new();
        rig.bind(5, 7, 1);
        let (pk, sk) = crate::crypto::test_support::gen_x25519();
        let r = rig.rekey(1, pk);
        let CustodyReply::Rekey(resp) = &r else {
            panic!("{r:?}")
        };
        let body = rig.verdict(&r);
        assert_eq!(body.verdict, Verdict::Grant as u8);
        resp.validate_against(&body).unwrap();
        let WrappedKek { enc, ct } = resp.wrapped_kek.clone().unwrap();
        let aad = rekey_kek_aad(&resp.verdict.body);
        let kek = crate::crypto::hpke_open_raw(&sk, &enc, &ct, REKEY_HPKE_INFO, &aad).unwrap();
        assert_eq!(kek.as_slice(), KEK);
        // Bound to THIS verdict: another aad does not open it.
        assert!(crate::crypto::hpke_open_raw(&sk, &enc, &ct, REKEY_HPKE_INFO, &[0; 32]).is_err());
        // …and never advanced the counter (ReadOnlyCounter would panic).
        assert_eq!(rig.counter.get(VM).unwrap(), 7);
    }

    #[test]
    fn rekey_for_a_superseded_or_revoked_vm_carries_no_key() {
        let rig = Rig::new();
        rig.bind(5, 7, 1);
        let (pk, _sk) = crate::crypto::test_support::gen_x25519();
        rig.counter.0.commit(VM, 8).unwrap();
        let r = rig.rekey(1, pk);
        let CustodyReply::Rekey(resp) = &r else {
            panic!()
        };
        assert!(resp.wrapped_kek.is_none());
        assert_eq!(rig.verdict(&r).verdict, Verdict::Superseded as u8);

        let rig = Rig::new();
        rig.bind(5, 7, 1);
        rig.st.decommission(VM).unwrap();
        let r = rig.rekey(1, pk);
        let CustodyReply::Rekey(resp) = &r else {
            panic!()
        };
        assert!(resp.wrapped_kek.is_none());
        assert_eq!(rig.verdict(&r).verdict, Verdict::Revoked as u8);
    }

    /// A lease bound before the VM moved to a later launch (a resize
    /// relaunch registered with `supersede`, or released) renews and
    /// rekeys nothing: the pre-resize guest cannot keep its key by lease.
    #[test]
    fn a_lease_of_a_superseded_launch_renews_and_rekeys_nothing() {
        use crate::lifecycle::{LaunchBinding, VmStateStore};
        let rig = Rig::new();
        rig.bind(5, 7, 1);
        // The bound launch is still current: the rekey serves the key.
        rig.st
            .bind_launch(
                VM,
                LaunchBinding {
                    measurement: MEAS,
                    issue_time: 100,
                },
            )
            .unwrap();
        let (pk, _sk) = crate::crypto::test_support::gen_x25519();
        let CustodyReply::Rekey(ok) = rig.rekey(1, pk) else {
            panic!()
        };
        assert!(ok.wrapped_kek.is_some());
        // A resize relaunch becomes current.
        rig.st
            .bind_launch(
                VM,
                LaunchBinding {
                    measurement: [0xEE; 48],
                    issue_time: 200,
                },
            )
            .unwrap();
        let r = rig.rekey(2, pk);
        let CustodyReply::Rekey(resp) = &r else {
            panic!("{r:?}")
        };
        assert!(
            resp.wrapped_kek.is_none(),
            "the old launch's lease got the key"
        );
        assert_eq!(rig.verdict(&r).verdict, Verdict::Superseded as u8);
        assert_eq!(
            rig.st.launch_binding(VM).unwrap().unwrap().measurement,
            [0xEE; 48]
        );
    }

    /// A lease recorded before the launch field existed: no evidence of
    /// which launch bound it, so the guest is asked to rebind — never
    /// killed.
    #[test]
    fn a_lease_that_does_not_name_its_launch_is_asked_to_rebind() {
        use crate::lifecycle::{LaunchBinding, VmStateStore};
        let rig = Rig::new();
        rig.bind(5, 7, 1);
        rig.runtime
            .store
            .advance(VM, &rig.lease_pub(), 1, &mut |r| r.measurement.clear())
            .unwrap();
        rig.st
            .bind_launch(
                VM,
                LaunchBinding {
                    measurement: MEAS,
                    issue_time: 100,
                },
            )
            .unwrap();
        let (pk, _sk) = crate::crypto::test_support::gen_x25519();
        let r = rig.rekey(2, pk);
        assert_eq!(r, CustodyReply::rebind(), "{r:?}");
    }

    #[test]
    fn a_fence_during_the_rekey_vault_read_keeps_the_key() {
        // The fence lands between the first standing check and the
        // emission: the re-check must win.
        struct FenceOnRead<'a>(&'a Kv, &'a FileVmStateStore);
        impl VaultKv for FenceOnRead<'_> {
            fn read_exact(
                &self,
                c: &VaultCapability,
                p: &str,
                v: u64,
            ) -> Result<Zeroizing<Vec<u8>>> {
                self.1.decommission(VM).unwrap();
                self.0.read_exact(c, p, v)
            }
            fn transit_decrypt(
                &self,
                c: &VaultCapability,
                k: &str,
                ct: &[u8],
            ) -> Result<Zeroizing<Vec<u8>>> {
                self.0.transit_decrypt(c, k, ct)
            }
        }
        let rig = Rig::new();
        rig.bind(5, 7, 1);
        let fencing = FenceOnRead(&rig.kv, rig.st.as_ref());
        let mut deps = rig.deps();
        deps.vault_kv = &fencing;
        let (pk, _sk) = crate::crypto::test_support::gen_x25519();
        let body = CustodyRekeyBody {
            v: 1,
            hpke_pub: pk.to_vec(),
            renew: rig.renew_body(1, 51_000),
        };
        let bytes = encode_canonical(&body).unwrap();
        let sig = rig
            .lease_sk
            .borrow()
            .sign(&signing_input(REKEY_SIG_DOMAIN, &bytes));
        let r = process_rekey(
            &CustodyRekeyRequest {
                body: bytes,
                sig: sig.to_bytes().to_vec(),
            },
            NOW + 1,
            &deps,
        );
        let CustodyReply::Rekey(resp) = &r else {
            panic!("{r:?}")
        };
        assert!(resp.wrapped_kek.is_none());
        assert_eq!(rig.verdict(&r).verdict, Verdict::Revoked as u8);
    }

    #[test]
    fn rekey_refuses_a_plaintext_kek_when_wrapping_is_required() {
        let mut rig = Rig::new();
        rig.kv.0.insert("kbs/vm/abc/luks-kek".into(), KEK.to_vec());
        rig.bind(5, 7, 1);
        let (pk, _sk) = crate::crypto::test_support::gen_x25519();
        assert_eq!(rig.rekey(1, pk), CustodyReply::unavailable());
    }

    // ── store / policy ────────────────────────────────────────────────

    #[test]
    fn policy_bounds_have_no_grant_forever() {
        CustodyPolicy::default().validate().unwrap();
        for bad in [
            CustodyPolicy {
                ttl_s: MAX_TTL_S + 1,
                ..Default::default()
            },
            CustodyPolicy {
                ttl_s: MIN_TTL_S - 1,
                ..Default::default()
            },
            CustodyPolicy {
                stage2_s: 0,
                ..Default::default()
            },
            CustodyPolicy {
                renew_s: 86_400 / 4 + 1,
                ..Default::default()
            },
            CustodyPolicy {
                renew_s: MIN_RENEW_S - 1,
                ..Default::default()
            },
        ] {
            assert!(bad.validate().is_err(), "{bad:?}");
        }
    }

    #[test]
    fn the_file_store_survives_a_process_restart() {
        let td = TempDir::new().unwrap();
        let path = td.path().join("custody.json");
        let rig = Rig::new();
        {
            let store = MapCustodyStore::open(&path).unwrap();
            rig.runtime.store.as_ref();
            let rec = CustodyRecord {
                vm_id: VM.into(),
                generation: 5,
                boot_counter: 7,
                node: "n".into(),
                lease_id: LEASE.into(),
                lease_pub: [1; 32],
                last_seq: 0,
                scope: CustodyScope {
                    luks_path: "a".into(),
                    luks_version: 1,
                    userdata_path: "b".into(),
                    userdata_version: 1,
                },
                clock_mode: 0,
                bound_at: 1,
                bind_mono_ms: 0,
                bind_tsc: 0,
                last_request_at: 1,
                last_mono_ms: 0,
                last_grant_at: None,
                last_verdict: None,
                phase: 0,
                since_last_grant_s: 0,
                suspended_s: 0,
                lag_s: 0,
                skew_suspected: false,
                rebinds: vec![],
                measurement: String::new(),
            };
            store.bind(rec, &|_| {}).unwrap();
            assert!(matches!(
                store.advance(VM, &[1; 32], 4, &mut |_| {}).unwrap(),
                Advance::Applied(_)
            ));
        }
        let store = MapCustodyStore::open(&path).unwrap();
        assert_eq!(store.get(VM).unwrap().unwrap().last_seq, 4);
        assert_eq!(
            store.advance(VM, &[1; 32], 4, &mut |_| {}).unwrap(),
            Advance::StaleSeq
        );
        assert_eq!(
            store.advance(VM, &[2; 32], 5, &mut |_| {}).unwrap(),
            Advance::NoBinding
        );
    }

    #[test]
    fn a_corrupt_snapshot_starts_the_store_empty_instead_of_failing() {
        let td = TempDir::new().unwrap();
        let path = td.path().join("custody.json");
        std::fs::write(&path, b"{not json").unwrap();
        let store = MapCustodyStore::open(&path).unwrap();
        assert!(store.list().unwrap().is_empty());
    }

    #[test]
    fn a_decoded_but_invalid_body_is_malformed() {
        let rig = Rig::new();
        let mut body = rig.bind_body(5, 7, [1; 32]);
        body.boot_counter = 0;
        let req = CustodyBindRequest {
            body: encode_canonical(&body).unwrap(),
            lifecycle_sig: vec![0; 64],
        };
        assert_eq!(
            process_bind(&req, NOW, &rig.deps()),
            CustodyReply::malformed()
        );
        let req = CustodyRenewRequest {
            body: vec![0xa0],
            sig: vec![],
        };
        assert_eq!(
            process_renew(&req, NOW, &rig.deps()),
            CustodyReply::malformed()
        );
    }
}
