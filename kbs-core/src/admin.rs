//! KBS admin operations (ARCHITECTURE.md §24 / §25 lifecycle
//! pre-registration).
//!
//! ## Trust model
//!
//! The admin transport is mTLS — the kbs-server's `:8001` listener
//! demands a client cert signed by the operator-controlled admin CA
//! whose SAN URI is in the configured allowlist. That gate is
//! enforced BEFORE this module is reached.
//!
//! But mTLS only authenticates the *caller* identity (vali) — it does
//! NOT authorize what's being written. **This module's contract is
//! that the request body IS a byte-exact L1-signed `OrderTicket`**.
//! The KBS verifies it via the same [`crate::ticket::verify_order_
//! ticket`] path used on the release endpoint, then derives the new
//! VmState fields (`gen`, `host`, `lease_id`) from the verified
//! ticket — NOT from anything vali sends in the URL or body wrapper.
//!
//! Result: a compromised vali cert without a valid L1-signed ticket
//! cannot poison the lifecycle store. The cryptographic anchor stays
//! at L1, where it already was for the release path.
//!
//! ## Idempotency
//!
//! Keyed by `OrderTicket.ticket_id`. The producer (vali) MUST submit
//! the same body bytes when retrying — same ticket = same canonical
//! body = same response hash = idempotent 200 return on hit. A
//! different body sharing the same ticket_id = 409 (state-divergent).
//!
//! ## Phase A scope
//!
//! Only [`process_admin_register`] is implemented. The Phase B ops
//! (`Decommission`, `CryptoErase`, `Activate`) get 501 stubs at the
//! handler layer; this crate does not even expose entry points for
//! them until their CAS predicates and migration semantics are
//! locked.

use crate::admin_audit::{AdminAuditRecord, FileAdminAuditSink};
use crate::error::{KbsError, Result};
use crate::lifecycle::{VmState, VmStateStore};
use crate::persist::{IdempotencyKey, IdempotencyStore};
use crate::ticket::{verify_order_ticket, L1Keyring, OrderTicket};
use sha2::{Digest, Sha256};

/// Maximum admin request body size. The signed `OrderTicket` is a
/// few hundred bytes in practice; cap aggressively to bound the
/// memory hit before this module runs.
pub const MAX_ADMIN_BODY_BYTES: usize = 16 * 1024;

/// Outcome of a successful (or idempotently-cached) register-vm.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminRegisterOk {
    pub ticket_id: String,
    pub vm_id: String,
    pub vm_generation: u64,
    pub host: String,
    pub lease_id: String,
    pub applied_at: u64,
    /// `true` ⇒ this exact ticket_id was previously registered with a
    /// matching body; the KBS returned the cached response without a
    /// fresh state-store write.
    pub cached: bool,
}

/// Discriminated failure shape mirrored into the on-the-wire 4xx body
/// schema (`hippius_types::admin::AdminErrorResponse`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdminRegisterErr {
    /// 400 — body too large.
    BodyTooLarge,
    /// 400 — body failed canonical-CBOR check at COSE / payload
    /// level, or `OrderTicket` decode failed.
    TicketDecode(String),
    /// 400 — ticket signature / expiry / not-yet-valid / kid-unknown.
    TicketInvalid(String),
    /// 400 — the URL's `{vm_id}` path component does not match the
    /// verified ticket's `vm_id`. Guards against an operator
    /// pasting the wrong ticket to a wrong URL by accident.
    UrlVmIdMismatch { url: String, ticket_vm_id: String },
    /// 409 — `request_id` (= ticket_id) already saw a register, but
    /// the body bytes diverge. Operator must reconcile.
    StateDivergent { ticket_id: String, vm_id: String },
    /// 409 — VmState already present for vm_id with a state that
    /// disagrees with the one this ticket would write. `current` is
    /// boxed so the enum's stack size stays small (clippy
    /// `result_large_err`).
    StateConflict {
        ticket_id: String,
        vm_id: String,
        current: Box<VmState>,
    },
    /// 500 — persistence layer failed. Retry safe.
    Internal(String),
}

impl AdminRegisterErr {
    pub fn status_code(&self) -> u16 {
        match self {
            AdminRegisterErr::BodyTooLarge => 413,
            AdminRegisterErr::TicketDecode(_) => 400,
            AdminRegisterErr::TicketInvalid(_) => 400,
            AdminRegisterErr::UrlVmIdMismatch { .. } => 400,
            AdminRegisterErr::StateDivergent { .. } => 409,
            AdminRegisterErr::StateConflict { .. } => 409,
            AdminRegisterErr::Internal(_) => 500,
        }
    }

    pub fn reason(&self) -> &'static str {
        match self {
            AdminRegisterErr::BodyTooLarge => "body-too-large",
            AdminRegisterErr::TicketDecode(_) => "ticket-decode",
            AdminRegisterErr::TicketInvalid(_) => "ticket-invalid",
            AdminRegisterErr::UrlVmIdMismatch { .. } => "url-vm-id-mismatch",
            AdminRegisterErr::StateDivergent { .. } => "state-divergent",
            AdminRegisterErr::StateConflict { .. } => "state-conflict",
            AdminRegisterErr::Internal(_) => "internal-error",
        }
    }

    pub fn ticket_id(&self) -> Option<&str> {
        match self {
            AdminRegisterErr::StateDivergent { ticket_id, .. }
            | AdminRegisterErr::StateConflict { ticket_id, .. } => Some(ticket_id),
            _ => None,
        }
    }

    pub fn vm_id(&self) -> Option<&str> {
        match self {
            AdminRegisterErr::UrlVmIdMismatch { ticket_vm_id, .. } => Some(ticket_vm_id),
            AdminRegisterErr::StateDivergent { vm_id, .. }
            | AdminRegisterErr::StateConflict { vm_id, .. } => Some(vm_id),
            _ => None,
        }
    }
}

/// Writer-side CAS-shaped interface for the lifecycle store. The
/// existing [`crate::lifecycle::VmStateStore`] is read-only by design
/// (the release path only reads); this trait adds the narrow
/// register-shaped write.
pub trait VmStateRegister {
    /// Apply a `Register` op:
    /// - if `vm_id` is absent  ⇒ insert `new_state`, return [`RegisterOutcome::Inserted`]
    /// - if `vm_id == new_state` ⇒ no-op, return [`RegisterOutcome::AlreadyMatching`]
    /// - otherwise ⇒ return [`RegisterOutcome::Conflict`] with the
    ///   current state (handler maps to 409).
    fn register(&self, vm_id: &str, new_state: VmState) -> Result<RegisterOutcome>;

    /// §25 — atomically transition `vm_id` `Active{old_gen,source,lease}`
    /// → `Migrating{old_gen,new_gen,source,dest,lease}` (the destination
    /// re-activation fence). This is the ONLY admin write that opens the
    /// §25 release path for the destination: after it,
    /// [`crate::lifecycle::check_releasable`] lets exactly
    /// `(new_gen, dest)` unlock and continues to deny the source at
    /// `old_gen` — the split-brain gate.
    ///
    /// CAS semantics (handled by [`Self::activate`]'s default impl over
    /// the store's atomic primitive):
    /// - `new_gen <= current.gen` ⇒ nothing written,
    ///   [`ActivateOutcome::NonMonotonic`] (see below);
    /// - current `Active{gen==old_gen, host==source, lease}` ⇒ swap to
    ///   `Migrating{…}`, return [`ActivateOutcome::Activated`];
    /// - current already `Migrating{old_gen,new_gen,source,dest,lease}`
    ///   matching this exact request ⇒ no-op
    ///   [`ActivateOutcome::AlreadyMigrating`] (idempotent re-drive);
    /// - anything else ⇒ [`ActivateOutcome::Conflict`] with the current
    ///   state (handler maps to 409 — never force a transition).
    ///
    /// **The generation must strictly increase.** `check_releasable`
    /// admits exactly `ticket_gen == new_gen` once the row is
    /// `Migrating`, so an activate at `new_gen == old_gen` would leave
    /// the SOURCE's generation releasable on the destination host — the
    /// split-brain the fence exists to prevent — and `new_gen < old_gen`
    /// would re-admit an already-burned generation (rollback). Both are
    /// refused BEFORE the CAS, so nothing is written.
    fn activate(&self, vm_id: &str, new_gen: u64, dest: &str) -> Result<ActivateOutcome>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegisterOutcome {
    Inserted,
    AlreadyMatching,
    Conflict(VmState),
}

/// Outcome of a §25 [`VmStateRegister::activate`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ActivateOutcome {
    /// The `Active → Migrating` swap was applied this call.
    Activated { old_gen: u64, lease_id: String },
    /// Already `Migrating` to this exact `(new_gen, dest)` — idempotent
    /// re-drive of a prior activate.
    AlreadyMigrating { old_gen: u64, lease_id: String },
    /// The requested `new_gen` does not strictly exceed the generation
    /// the KBS currently holds for this VM. Nothing was written. The
    /// handler maps this to 409 — a non-increasing activation would
    /// either un-fence the source (`==`) or re-admit a burned
    /// generation (`<`).
    NonMonotonic { old_gen: u64 },
    /// The current state does not permit this activation (not `Active`,
    /// wrong host, or a divergent in-flight migration). The handler maps
    /// this to 409 — vali never forces a transition across the fence.
    Conflict(Box<VmState>),
}

impl VmStateRegister for crate::persist::FileVmStateStore {
    fn register(&self, vm_id: &str, new_state: VmState) -> Result<RegisterOutcome> {
        match self.get(vm_id) {
            Ok(cur) if cur == new_state => Ok(RegisterOutcome::AlreadyMatching),
            Ok(other) => Ok(RegisterOutcome::Conflict(other)),
            Err(KbsError::Lifecycle(_)) => {
                // `no state for vm_id` ⇒ fresh insert. The internal CAS
                // is `expected_now == None`. If a racing caller wrote
                // the same vm_id between our `get` and `cas`, CAS will
                // fail; we recurse once to surface the conflict.
                match self.cas(vm_id, |cur| cur.is_none(), new_state.clone()) {
                    Ok(()) => Ok(RegisterOutcome::Inserted),
                    Err(KbsError::Lifecycle(_)) => match self.get(vm_id) {
                        Ok(cur) if cur == new_state => Ok(RegisterOutcome::AlreadyMatching),
                        Ok(other) => Ok(RegisterOutcome::Conflict(other)),
                        Err(e) => Err(e),
                    },
                    Err(e) => Err(e),
                }
            }
            Err(e) => Err(e),
        }
    }

    fn activate(&self, vm_id: &str, new_gen: u64, dest: &str) -> Result<ActivateOutcome> {
        // Read the current state to derive the `Migrating` fields the
        // request does NOT carry (old_gen, source, lease) — vali only
        // supplies the forward-only `(new_gen, dest)`. The KBS owns the
        // authoritative current `Active{…}`, so it never trusts vali for
        // those fields.
        let current = match self.get(vm_id) {
            Ok(s) => s,
            Err(KbsError::Lifecycle(_)) => {
                // No state at all — nothing to activate over. A fresh VM
                // must be `register-vm`'d first. Treat as a conflict the
                // handler maps to 409 (vali surfaces + retries / aborts).
                return Ok(ActivateOutcome::Conflict(Box::new(
                    VmState::Decommissioning,
                )));
            }
            Err(e) => return Err(e),
        };

        match &current {
            VmState::Active {
                gen: old_gen,
                host: source,
                lease_id,
            } => {
                // Forward-only gate, BEFORE the CAS so a refusal writes
                // nothing. `check_releasable` admits exactly `new_gen`
                // once the row is `Migrating`: at `new_gen == old_gen`
                // the source's own generation would stay releasable (the
                // split-brain this fence exists to prevent) and at
                // `new_gen < old_gen` a burned generation would be
                // re-admitted (rollback).
                if new_gen <= *old_gen {
                    return Ok(ActivateOutcome::NonMonotonic { old_gen: *old_gen });
                }
                let target = VmState::Migrating {
                    old_gen: *old_gen,
                    new_gen,
                    source: source.clone(),
                    dest: dest.to_string(),
                    lease_id: lease_id.clone(),
                };
                let old_gen_v = *old_gen;
                let lease_v = lease_id.clone();
                // CAS predicate pins the EXACT current Active row — if a
                // racing write changed it between our `get` and the
                // `cas`, the predicate fails and we re-read to surface
                // the conflict rather than clobber.
                let expected = current.clone();
                match self.cas(vm_id, |cur| cur == Some(&expected), target) {
                    Ok(()) => Ok(ActivateOutcome::Activated {
                        old_gen: old_gen_v,
                        lease_id: lease_v,
                    }),
                    Err(KbsError::Lifecycle(_)) => match self.get(vm_id) {
                        Ok(other) => Ok(activate_recheck(other, new_gen, dest)),
                        Err(e) => Err(e),
                    },
                    Err(e) => Err(e),
                }
            }
            // Already migrating — idempotent ONLY if it is the same
            // forward-only `(new_gen, dest)`; a divergent migration is a
            // conflict, never silently re-targeted.
            _ => Ok(activate_recheck(current, new_gen, dest)),
        }
    }
}

/// Classify a current state against the requested `(new_gen, dest)` for
/// the idempotent / conflict arms of [`VmStateRegister::activate`].
fn activate_recheck(current: VmState, new_gen: u64, dest: &str) -> ActivateOutcome {
    if let VmState::Migrating {
        old_gen,
        new_gen: cur_new,
        dest: cur_dest,
        lease_id,
        ..
    } = &current
    {
        if *cur_new == new_gen && cur_dest == dest {
            return ActivateOutcome::AlreadyMigrating {
                old_gen: *old_gen,
                lease_id: lease_id.clone(),
            };
        }
    }
    ActivateOutcome::Conflict(Box::new(current))
}

/// Process a `POST /v1/admin/register-vm` request body.
///
/// `body` is the byte-exact COSE_Sign1 `OrderTicket` (same bytes vali
/// submits to the public `/v1/order_ticket` endpoint). `url_vm_id` is
/// the URL path component — used for attribution audit even when the
/// ticket itself fails to decode.
///
/// Returns either [`AdminRegisterOk`] (HTTP 200) or
/// [`AdminRegisterErr`] (4xx/5xx). The caller (kbs-server handler) is
/// responsible for the audit-log append AND the HTTP response — this
/// function only computes the verdict.
pub fn process_admin_register(
    body: &[u8],
    url_vm_id: &str,
    keyring: &dyn L1Keyring,
    vm_states: &dyn VmStateRegister,
    idempotency: &dyn IdempotencyStore,
    now_unix: u64,
) -> core::result::Result<AdminRegisterOk, AdminRegisterErr> {
    // 0. body size cap. Before any decode work.
    if body.len() > MAX_ADMIN_BODY_BYTES {
        return Err(AdminRegisterErr::BodyTooLarge);
    }

    // 1. body sha (used for idempotency `response_hash` AND audit).
    //    We hash the BODY here so the recorded fingerprint pins the
    //    exact ticket bytes that produced the registered state.
    let mut h = [0u8; 32];
    h.copy_from_slice(Sha256::digest(body).as_slice());

    // 2. verify the COSE_Sign1 OrderTicket envelope. This subsumes
    //    canonical-CBOR check, signature verify, expiry/issue_time,
    //    schema, and kid-in-keyring check.
    let (ticket, _kid): (OrderTicket, Vec<u8>) = verify_order_ticket(body, keyring, now_unix)
        .map_err(|e| match e {
            KbsError::Ticket(msg) => AdminRegisterErr::TicketInvalid(msg),
            KbsError::Crypto(msg) => AdminRegisterErr::TicketInvalid(msg),
            other => AdminRegisterErr::TicketDecode(format!("{other}")),
        })?;

    // 3. URL path's {vm_id} must equal the verified ticket's vm_id.
    //    A mismatch is operator error (pasted the wrong ticket).
    if url_vm_id != ticket.vm_id {
        return Err(AdminRegisterErr::UrlVmIdMismatch {
            url: url_vm_id.into(),
            ticket_vm_id: ticket.vm_id.clone(),
        });
    }

    // 4. Idempotency: was this ticket_id already registered?
    //    Key = ticket_id bytes. Response hash = body sha256.
    let idem_key = IdempotencyKey(ticket.ticket_id.as_bytes().to_vec());
    if let Some(cached_hash) = idempotency
        .recall(&idem_key, now_unix)
        .map_err(|e| AdminRegisterErr::Internal(format!("idem recall: {e}")))?
    {
        if cached_hash == h {
            // Idempotent hit — same ticket, same body. Return the
            // cached response shape. We've already verified the ticket
            // (cheap) so we can echo its fields without trusting the
            // cache contents.
            return Ok(AdminRegisterOk {
                ticket_id: ticket.ticket_id.clone(),
                vm_id: ticket.vm_id.clone(),
                vm_generation: ticket.vm_generation,
                host: ticket.platform_id.clone(),
                lease_id: ticket.lease_id.clone(),
                applied_at: now_unix,
                cached: true,
            });
        }
        // Same ticket_id, DIFFERENT body. State drift — caller error.
        return Err(AdminRegisterErr::StateDivergent {
            ticket_id: ticket.ticket_id.clone(),
            vm_id: ticket.vm_id.clone(),
        });
    }

    // 5. Build desired VmState from the verified ticket fields.
    //    Phase A: ticket `platform_id` maps to lifecycle `host`.
    //    Production §B locked decision: `host` is the attested chip
    //    id; for now vali knows the chip id and bakes it into the
    //    ticket as `platform_id`, then KBS uses the attested CHIP_ID
    //    on release to confirm.
    let desired = VmState::Active {
        gen: ticket.vm_generation,
        host: ticket.platform_id.clone(),
        lease_id: ticket.lease_id.clone(),
    };

    // 6. Apply via the lifecycle-store CAS.
    match vm_states
        .register(&ticket.vm_id, desired.clone())
        .map_err(|e| AdminRegisterErr::Internal(format!("vm_states.register: {e}")))?
    {
        RegisterOutcome::Inserted | RegisterOutcome::AlreadyMatching => {
            // Record into idempotency store. Best-effort — a failure
            // here doesn't unmake the lifecycle write; the next retry
            // will hit `RegisterOutcome::AlreadyMatching` and succeed
            // again. We still surface a 500 if record fails, so vali
            // is aware retry semantics are degraded.
            idempotency
                .record(&idem_key, &h, now_unix)
                .map_err(|e| AdminRegisterErr::Internal(format!("idem record: {e}")))?;
            Ok(AdminRegisterOk {
                ticket_id: ticket.ticket_id.clone(),
                vm_id: ticket.vm_id.clone(),
                vm_generation: ticket.vm_generation,
                host: ticket.platform_id.clone(),
                lease_id: ticket.lease_id.clone(),
                applied_at: now_unix,
                cached: false,
            })
        }
        RegisterOutcome::Conflict(current) => Err(AdminRegisterErr::StateConflict {
            ticket_id: ticket.ticket_id.clone(),
            vm_id: ticket.vm_id.clone(),
            current: Box::new(current),
        }),
    }
}

/// Convenience: pair a verdict with an audit-log append. The handler
/// uses this so success-and-fail both end up in admin.log
/// byte-for-byte attributable.
#[allow(clippy::too_many_arguments)]
pub fn record_admin_register_outcome(
    audit: &FileAdminAuditSink,
    url_vm_id: &str,
    body_sha256: &[u8; 32],
    peer_san: Option<&str>,
    peer_serial: Option<&str>,
    outcome: &core::result::Result<AdminRegisterOk, AdminRegisterErr>,
    now_unix: u64,
) -> Result<[u8; 32]> {
    let (applied, status, reason, ticket_id, vm_id) = match outcome {
        Ok(ok) => (
            !ok.cached,
            200u16,
            None,
            Some(ok.ticket_id.as_str()),
            Some(ok.vm_id.as_str()),
        ),
        Err(e) => (
            false,
            e.status_code(),
            Some(e.reason()),
            e.ticket_id(),
            e.vm_id(),
        ),
    };
    let record = AdminAuditRecord {
        op: "register-vm",
        url_vm_id,
        ticket_id,
        vm_id,
        applied,
        status_code: status,
        reason,
        peer_san,
        peer_serial,
        body_sha256,
    };
    audit.append(&record, now_unix)
}

// ─── §25 destination re-activation (Active → Migrating) ──────────────

/// Outcome of a successful (or idempotently-cached) `activate`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminActivateOk {
    pub vm_id: String,
    pub old_gen: u64,
    pub new_gen: u64,
    pub dest: String,
    pub lease_id: String,
    /// `true` ⇒ the VM was already `Migrating` to this exact
    /// `(new_gen, dest)` — an idempotent re-drive, no fresh write.
    pub cached: bool,
}

/// Discriminated failure shape for `activate`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdminActivateErr {
    /// 400 — `new_gen` / `dest` was missing or malformed.
    BadRequest(&'static str),
    /// 409 — the current VmState does not permit this activation (not
    /// `Active`, wrong host, a divergent in-flight migration, or no
    /// state registered at all). The `current` is boxed to keep the
    /// enum small (clippy `result_large_err`).
    Conflict {
        vm_id: String,
        current: Box<VmState>,
    },
    /// 409 — **anti-rollback / anti-split-brain**: `new_gen` did not
    /// strictly exceed the generation the KBS holds. Nothing was
    /// written. Distinct from [`AdminActivateErr::Conflict`] on purpose:
    /// a conflict means "the VM is not in a state I can activate over",
    /// this one means "the VM is exactly activatable but the requested
    /// generation would un-fence the source".
    NonMonotonic {
        vm_id: String,
        old_gen: u64,
        requested: u64,
    },
    /// 500 — the persistence layer failed. Retry-safe.
    Internal(String),
}

impl AdminActivateErr {
    pub fn status_code(&self) -> u16 {
        match self {
            AdminActivateErr::BadRequest(_) => 400,
            AdminActivateErr::Conflict { .. } => 409,
            AdminActivateErr::NonMonotonic { .. } => 409,
            AdminActivateErr::Internal(_) => 500,
        }
    }

    pub fn reason(&self) -> &'static str {
        match self {
            AdminActivateErr::BadRequest(r) => r,
            AdminActivateErr::Conflict { .. } => "activate-conflict",
            AdminActivateErr::NonMonotonic { .. } => "activate-not-monotonic",
            AdminActivateErr::Internal(_) => "internal-error",
        }
    }

    /// The VM this failure is about, when the shape carries one. Used by
    /// [`record_admin_activate_outcome`] so a refusal is attributable to
    /// a VM in the audit chain.
    pub fn vm_id(&self) -> Option<&str> {
        match self {
            AdminActivateErr::Conflict { vm_id, .. }
            | AdminActivateErr::NonMonotonic { vm_id, .. } => Some(vm_id.as_str()),
            AdminActivateErr::BadRequest(_) | AdminActivateErr::Internal(_) => None,
        }
    }
}

/// Process a `POST /v1/admin/vm/{vm_id}/activate` request (§25
/// destination re-activation).
///
/// **This is the cryptographic split-brain fence on the KBS side.**
/// vali calls it ONLY after it has verified the source guest's signed
/// `stopped{}` ack at the source generation (see
/// `vali/apps/orchestration/service.py::_h_mig_awaiting_source_ack` →
/// `_h_mig_dest_activating`). The transition `Active → Migrating` is what
/// flips [`crate::lifecycle::check_releasable`] so that — from this
/// instant — ONLY the destination node attesting at `new_gen` can unlock
/// the rootfs KEK, and the source at `old_gen` is permanently fenced
/// out. The KEK itself is unchanged (same encrypted disk); only the boot
/// generation + bound host move forward. A stale generation can never
/// unlock: `check_releasable` denies any `ticket_gen != new_gen`
/// (replay / rollback protection).
///
/// `vm_id` is the URL path component. `new_gen` + `dest` come from the
/// JSON body vali posts. The `old_gen`, `source`, and `lease_id` are
/// taken from the KBS's OWN authoritative `Active{…}` state — never from
/// vali — so a compromised vali cert cannot rewrite them.
///
/// Idempotent: a re-drive that finds the VM already `Migrating` to this
/// exact `(new_gen, dest)` returns 200 `cached`. A request that would
/// re-target a different `(new_gen, dest)`, or one against a
/// non-`Active` state, is a 409 conflict — the fence never force-moves.
///
/// Forward-only: `new_gen` MUST strictly exceed the generation the KBS
/// currently holds, else 409 `activate-not-monotonic` and nothing is
/// written (see [`VmStateRegister::activate`] for why `==` is as unsafe
/// as `<`).
pub fn process_admin_activate(
    url_vm_id: &str,
    new_gen: u64,
    dest: &str,
    vm_states: &dyn VmStateRegister,
) -> core::result::Result<AdminActivateOk, AdminActivateErr> {
    if url_vm_id.is_empty() {
        return Err(AdminActivateErr::BadRequest("vm-id-empty"));
    }
    if dest.is_empty() {
        return Err(AdminActivateErr::BadRequest("dest-empty"));
    }

    match vm_states
        .activate(url_vm_id, new_gen, dest)
        .map_err(|e| AdminActivateErr::Internal(format!("vm_states.activate: {e}")))?
    {
        ActivateOutcome::Activated { old_gen, lease_id } => Ok(AdminActivateOk {
            vm_id: url_vm_id.to_string(),
            old_gen,
            new_gen,
            dest: dest.to_string(),
            lease_id,
            cached: false,
        }),
        ActivateOutcome::AlreadyMigrating { old_gen, lease_id } => Ok(AdminActivateOk {
            vm_id: url_vm_id.to_string(),
            old_gen,
            new_gen,
            dest: dest.to_string(),
            lease_id,
            cached: true,
        }),
        ActivateOutcome::NonMonotonic { old_gen } => Err(AdminActivateErr::NonMonotonic {
            vm_id: url_vm_id.to_string(),
            old_gen,
            requested: new_gen,
        }),
        ActivateOutcome::Conflict(current) => Err(AdminActivateErr::Conflict {
            vm_id: url_vm_id.to_string(),
            current,
        }),
    }
}

/// Convenience: pair an `activate` verdict with an audit-log append —
/// the same "every admin write is attributable" contract
/// [`record_admin_register_outcome`] gives `register-vm`.
///
/// `activate` is the §25 split-brain fence: it is the single call that
/// moves which host may unlock a tenant's disk. Before this existed the
/// op left NO trace in the hash-chained admin log, so an operator could
/// not tell — after the fact — who moved a VM's generation, or that a
/// refused attempt had even happened. Both outcomes are recorded, so a
/// probing caller shows up as a run of `applied=false` rows.
pub fn record_admin_activate_outcome(
    audit: &FileAdminAuditSink,
    url_vm_id: &str,
    body_sha256: &[u8; 32],
    peer_san: Option<&str>,
    peer_serial: Option<&str>,
    outcome: &core::result::Result<AdminActivateOk, AdminActivateErr>,
    now_unix: u64,
) -> Result<[u8; 32]> {
    let (applied, status, reason, vm_id) = match outcome {
        // `cached` ⇒ an idempotent re-drive that wrote nothing; mirror
        // `record_admin_register_outcome`, where `applied` means "this
        // call changed durable state".
        Ok(ok) => (!ok.cached, 200u16, None, Some(ok.vm_id.as_str())),
        Err(e) => (false, e.status_code(), Some(e.reason()), e.vm_id()),
    };
    let record = AdminAuditRecord {
        op: "activate",
        url_vm_id,
        // No signed ticket on this op — it carries plain control-plane
        // fields (`dest_node_id`, `new_gen`), like `seed-boot-counter`.
        ticket_id: None,
        vm_id,
        applied,
        status_code: status,
        reason,
        peer_san,
        peer_serial,
        body_sha256,
    };
    audit.append(&record, now_unix)
}

// ─── boot-counter seed (operator disaster recovery) ──────────────────

/// Outcome of a successful `seed-boot-counter`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminSeedOk {
    pub vm_id: String,
    /// What the KBS had before the seed. ALWAYS 0: the store only
    /// accepts a seed onto a wiped/absent row (guard 1), so a success is
    /// by construction a post-wipe recovery. Kept in the shape as an
    /// explicit confirmation of that to the operator rather than an
    /// implicit one.
    pub previous: u64,
    /// The value now stored — the guest's next boot must submit
    /// `counter + 1`.
    pub counter: u64,
}

/// Discriminated failure shape for `seed-boot-counter`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdminSeedErr {
    /// 400 — the request itself is malformed (empty vm_id, counter 0).
    BadRequest(&'static str),
    /// 409 — **anti-rollback**: the requested counter is `<=` the one
    /// already stored. Nothing was written. This is the whole point of
    /// the endpoint's security contract: a seed may only ever RAISE.
    NotMonotonic {
        vm_id: String,
        stored: u64,
        requested: u64,
    },
    /// 409 — the row is NOT wiped: `vm_id` already has a live counter,
    /// so this is not a recovery. Nothing was written. Distinct from
    /// [`AdminSeedErr::NotMonotonic`] on purpose — this is the benign
    /// "already recovered / duplicate request" case an operator will
    /// actually hit, and burying it under the rollback code would
    /// destroy the rollback code's value as an alert.
    AlreadyRecovered { vm_id: String, stored: u64 },
    /// 400 — the requested counter exceeds
    /// [`crate::boot_counter::MAX_SEED_COUNTER`]. Nothing was written.
    /// Implausible-input, hence 4xx-not-conflict: it is wrong regardless
    /// of what is stored.
    AboveCap {
        vm_id: String,
        requested: u64,
        cap: u64,
    },
    /// 500 — the counter store failed. Retry-safe (a failed seed
    /// writes nothing).
    Internal(String),
}

impl AdminSeedErr {
    pub fn status_code(&self) -> u16 {
        match self {
            AdminSeedErr::BadRequest(_) => 400,
            AdminSeedErr::AboveCap { .. } => 400,
            AdminSeedErr::NotMonotonic { .. } => 409,
            AdminSeedErr::AlreadyRecovered { .. } => 409,
            AdminSeedErr::Internal(_) => 500,
        }
    }

    /// Stable, DISTINCT machine reason per refusal. An operator (and an
    /// alert rule) must be able to tell the three refusals apart; see
    /// [`crate::boot_counter::SeedOutcome`].
    pub fn reason(&self) -> &'static str {
        match self {
            AdminSeedErr::BadRequest(r) => r,
            AdminSeedErr::NotMonotonic { .. } => "seed-not-monotonic",
            AdminSeedErr::AlreadyRecovered { .. } => "seed-already-recovered",
            AdminSeedErr::AboveCap { .. } => "seed-above-cap",
            AdminSeedErr::Internal(_) => "internal-error",
        }
    }

    pub fn vm_id(&self) -> Option<&str> {
        match self {
            AdminSeedErr::NotMonotonic { vm_id, .. }
            | AdminSeedErr::AlreadyRecovered { vm_id, .. }
            | AdminSeedErr::AboveCap { vm_id, .. } => Some(vm_id),
            _ => None,
        }
    }
}

/// Process a `POST /v1/admin/vm/{vm_id}/seed-boot-counter` request.
///
/// ## Why this endpoint exists
///
/// The KBS state directory lives on an `emptyDir`; a pod restart wipes
/// `boot-counters.json`. [`crate::boot_counter::BootCounterStore::
/// check_only`] then expects `1` from every VM, while a guest that has
/// booted N times submits `N + 1` — fail-closed, forever. The
/// authoritative value survives on the miner-side per-VM state disk
/// (`/var/lib/hippius-miner/state/<vm>.raw`), so the operator restores
/// the wiped KBS from it through this endpoint.
///
/// ## Why it is neither a rollback hole nor a DoS lever
///
/// All three guards live inside the store, under the store's own lock,
/// so there is no check-then-write window, and each returns a DISTINCT
/// error having written NOTHING:
///
/// - `stored != 0` → 409 [`AdminSeedErr::AlreadyRecovered`]. The
///   endpoint does exactly one thing — restore a WIPED counter — so
///   against a live VM it is inert. This is what stops admin-listener
///   access from being a fleet-wide denial of service.
/// - `counter > MAX_SEED_COUNTER` → 400 [`AdminSeedErr::AboveCap`].
///   Without it, one request could set a counter the guest can never
///   reach from its own disk, bricking the VM irreversibly.
/// - `counter <= stored` → 409 [`AdminSeedErr::NotMonotonic`]. The
///   invariant of record: a seed may only ever RAISE, so it can never
///   re-admit a snapshot whose boot was already burned.
///
/// The `check_only`/`commit` gate is untouched: seeding to N leaves the
/// store in exactly the state N real boots would have left it in.
pub fn process_admin_seed_boot_counter(
    url_vm_id: &str,
    counter: u64,
    store: &dyn crate::boot_counter::BootCounterStore,
) -> core::result::Result<AdminSeedOk, AdminSeedErr> {
    use crate::boot_counter::SeedOutcome;

    if url_vm_id.is_empty() {
        return Err(AdminSeedErr::BadRequest("vm-id-empty"));
    }
    // 0 is never a legitimate recovered value: a VM that has booted has
    // a counter >= 1, and a VM that has not booted needs no seed. The
    // store would refuse it anyway (`0 <= 0`); rejecting it here gives
    // the operator a 400 ("you sent nonsense") rather than a 409
    // ("someone tried to rewind"), which keeps the 409 signal clean for
    // alerting.
    if counter == 0 {
        return Err(AdminSeedErr::BadRequest("counter-zero"));
    }

    match store
        .seed(url_vm_id, counter)
        .map_err(|e| AdminSeedErr::Internal(format!("boot_counter.seed: {e}")))?
    {
        SeedOutcome::Seeded { previous } => Ok(AdminSeedOk {
            vm_id: url_vm_id.to_string(),
            previous,
            counter,
        }),
        SeedOutcome::Refused { stored } => Err(AdminSeedErr::NotMonotonic {
            vm_id: url_vm_id.to_string(),
            stored,
            requested: counter,
        }),
        SeedOutcome::AlreadyRecovered { stored } => Err(AdminSeedErr::AlreadyRecovered {
            vm_id: url_vm_id.to_string(),
            stored,
        }),
        SeedOutcome::AboveCap { requested, cap } => Err(AdminSeedErr::AboveCap {
            vm_id: url_vm_id.to_string(),
            requested,
            cap,
        }),
    }
}

/// Append the `seed-boot-counter` outcome to the admin hash chain.
/// Mirrors [`record_admin_register_outcome`] field-for-field so the
/// sentinel verifier reads one schema. `applied` is `true` ONLY when
/// the counter actually moved; every refusal is recorded with
/// `applied=false` and its own distinct `reason`
/// (`seed-already-recovered` / `seed-above-cap` / `seed-not-monotonic`),
/// which is what an operator greps for after an incident.
///
/// Note on what a reader can conclude from `applied=true`: because the
/// store admits a seed only onto a wiped/absent row, an applied record
/// ALWAYS carries `previous == 0`. "Applied with a non-zero previous"
/// is not a case to alert on — it is unreachable by construction, and
/// if one ever appears in the chain it means guard 1
/// ([`crate::boot_counter::SeedOutcome::AlreadyRecovered`]) was removed
/// or bypassed, not that an operator did something unusual.
pub fn record_admin_seed_outcome(
    audit: &FileAdminAuditSink,
    url_vm_id: &str,
    body_sha256: &[u8; 32],
    peer_san: Option<&str>,
    peer_serial: Option<&str>,
    outcome: &core::result::Result<AdminSeedOk, AdminSeedErr>,
    now_unix: u64,
) -> Result<[u8; 32]> {
    let (applied, status, reason, vm_id) = match outcome {
        Ok(ok) => (true, 200u16, None, Some(ok.vm_id.as_str())),
        Err(e) => (false, e.status_code(), Some(e.reason()), e.vm_id()),
    };
    let record = AdminAuditRecord {
        op: "seed-boot-counter",
        url_vm_id,
        // No signed ticket on this op (it carries a plain control-plane
        // integer, like `activate`) — the field stays empty so the
        // record shape matches the rest of the chain.
        ticket_id: None,
        vm_id,
        applied,
        status_code: status,
        reason,
        peer_san,
        peer_serial,
        body_sha256,
    };
    audit.append(&record, now_unix)
}

// ─── volume-stamp suppression reset (operator disaster recovery) ─────

/// Outcome of a successful `reset-volume-stamp-suppression`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminResetVolumeStampSuppressionOk {
    pub vm_id: String,
    /// The unconfirmed-release count that was cleared. `0` means the VM
    /// was not blocked — a harmless no-op, not an error.
    pub cleared: u64,
}

/// Discriminated failure shape for `reset-volume-stamp-suppression`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdminResetVolumeStampSuppressionErr {
    /// 400 — the URL's `{vm_id}` was empty.
    BadRequest(&'static str),
    /// 500 — the volume-stamp store failed. Retry-safe.
    Internal(String),
}

impl AdminResetVolumeStampSuppressionErr {
    pub fn status_code(&self) -> u16 {
        match self {
            AdminResetVolumeStampSuppressionErr::BadRequest(_) => 400,
            AdminResetVolumeStampSuppressionErr::Internal(_) => 500,
        }
    }

    pub fn reason(&self) -> &'static str {
        match self {
            AdminResetVolumeStampSuppressionErr::BadRequest(r) => r,
            AdminResetVolumeStampSuppressionErr::Internal(_) => "internal-error",
        }
    }
}

/// Process a `POST /v1/admin/vm/{vm_id}/reset-volume-stamp-suppression`
/// request.
///
/// ## Why this endpoint exists
///
/// `crate::volume_stamp` closes the "miner drops every confirm" gap: a
/// release durably counts itself against a VM's unconfirmed-releases
/// total (`VolumeStampStore::note_release`, called at gate 5c of
/// `crate::release::run`), and once that total exceeds
/// `crate::volume_stamp::MAX_UNCONFIRMED_RELEASES` the KBS refuses
/// further releases for that VM. That refusal must not be permanent —
/// the guest can never clear it itself (a refused release means no boot,
/// which means no confirm), so recovery has to be an operator action.
/// This is that action.
///
/// ## Why this is neither a rollback hole nor a silent-suppression lever
///
/// The write does exactly ONE thing — clear the unconfirmed-releases
/// counter — and it NEVER touches the confirmed volume stamp (the
/// anti-rollback reference itself). Resetting the suppression counter
/// lets releases resume; it does not, and cannot, move the value a
/// rolled-back guest is compared against. An operator who resets this
/// without understanding WHY confirms stopped arriving just re-opens the
/// suppression window (the miner can drop confirms again), but they can
/// never use this route to roll a tenant's disk back — that would
/// require moving `confirmed`, which this route cannot touch.
///
/// A reset against a VM that was never blocked is a harmless no-op
/// (`cleared == 0`), so this is safe to call speculatively/idempotently
/// — unlike `seed-boot-counter`, there is no "already recovered"
/// refusal to protect, because there is nothing here that could brick a
/// live VM.
///
/// Auth: mTLS + network policy at the ADMIN LISTENER, identical to
/// `register-vm` / `activate` / `seed-boot-counter`. This route is
/// registered ONLY on `kbs_transport::admin_handler::build_admin_router`
/// — the public-Ingress release router (which serves
/// `/v1/kbs/volume-stamp/confirm`) does not serve it and never will. A
/// miner reaching this route would be exactly the party the suppression
/// gate exists to constrain.
pub fn process_admin_reset_volume_stamp_suppression(
    url_vm_id: &str,
    store: &dyn crate::volume_stamp::VolumeStampStore,
) -> core::result::Result<AdminResetVolumeStampSuppressionOk, AdminResetVolumeStampSuppressionErr> {
    if url_vm_id.is_empty() {
        return Err(AdminResetVolumeStampSuppressionErr::BadRequest(
            "vm-id-empty",
        ));
    }
    let cleared = store.admin_reset_unconfirmed(url_vm_id).map_err(|e| {
        AdminResetVolumeStampSuppressionErr::Internal(format!(
            "volume_stamp.admin_reset_unconfirmed: {e}"
        ))
    })?;
    Ok(AdminResetVolumeStampSuppressionOk {
        vm_id: url_vm_id.to_string(),
        cleared,
    })
}

/// Append the `reset-volume-stamp-suppression` outcome to the admin hash
/// chain. Mirrors [`record_admin_seed_outcome`] field-for-field.
/// `applied` is `true` whenever the call actually reached the store
/// (even a harmless `cleared == 0` no-op counts — the CALL happened and
/// is worth an attributable record on the mTLS-authenticated admin
/// listener; only a `BadRequest`/`Internal` failure is `applied=false`).
pub fn record_admin_reset_volume_stamp_suppression_outcome(
    audit: &FileAdminAuditSink,
    url_vm_id: &str,
    body_sha256: &[u8; 32],
    peer_san: Option<&str>,
    peer_serial: Option<&str>,
    outcome: &core::result::Result<
        AdminResetVolumeStampSuppressionOk,
        AdminResetVolumeStampSuppressionErr,
    >,
    now_unix: u64,
) -> Result<[u8; 32]> {
    let (applied, status, reason, vm_id) = match outcome {
        Ok(ok) => (true, 200u16, None, Some(ok.vm_id.as_str())),
        Err(e) => (false, e.status_code(), Some(e.reason()), None),
    };
    let record = AdminAuditRecord {
        op: "reset-volume-stamp-suppression",
        url_vm_id,
        ticket_id: None,
        vm_id,
        applied,
        status_code: status,
        reason,
        peer_san,
        peer_serial,
        body_sha256,
    };
    audit.append(&record, now_unix)
}

// ─── boot-counter resync arm (operator disaster recovery) ────────────

/// Outcome of a successful `arm-boot-counter-resync`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminArmResyncOk {
    pub vm_id: String,
    /// The counter the KBS holds. UNCHANGED by this call — arming
    /// writes no counter. Echoed so the operator can see, in the same
    /// response, the value the next boot will be re-baselined to
    /// (`stored + 1`).
    pub stored: u64,
    /// `true` when the VM was already armed — a re-drive that wrote
    /// nothing new. Surfaced rather than hidden so a duplicated
    /// operator action does not read as two separate incidents.
    pub already_armed: bool,
}

/// Discriminated failure shape for `arm-boot-counter-resync`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdminArmResyncErr {
    /// 400 — the URL's `{vm_id}` was empty.
    BadRequest(&'static str),
    /// 409 — the KBS holds NO counter for this `vm_id`, so there is
    /// nothing to resync: a guest with no state disk submits `1`, which
    /// a `stored == 0` row accepts on the normal path. Nothing written.
    /// Distinct from a 400 because the request was well-formed — it is
    /// the STATE that makes it a no-op, and an operator who armed the
    /// wrong `vm_id` needs to be told exactly that.
    NothingToResync { vm_id: String },
    /// 500 — the counter store failed. Retry-safe (a failed arm writes
    /// nothing).
    Internal(String),
}

impl AdminArmResyncErr {
    pub fn status_code(&self) -> u16 {
        match self {
            AdminArmResyncErr::BadRequest(_) => 400,
            AdminArmResyncErr::NothingToResync { .. } => 409,
            AdminArmResyncErr::Internal(_) => 500,
        }
    }

    pub fn reason(&self) -> &'static str {
        match self {
            AdminArmResyncErr::BadRequest(r) => r,
            AdminArmResyncErr::NothingToResync { .. } => "resync-nothing-to-resync",
            AdminArmResyncErr::Internal(_) => "internal-error",
        }
    }

    pub fn vm_id(&self) -> Option<&str> {
        match self {
            AdminArmResyncErr::NothingToResync { vm_id } => Some(vm_id),
            _ => None,
        }
    }
}

/// Process a `POST /v1/admin/vm/{vm_id}/arm-boot-counter-resync`
/// request.
///
/// ## Why this endpoint exists
///
/// [`process_admin_seed_boot_counter`] repairs the KBS's copy of the
/// boot counter from the miner's. Nothing repaired the MINER's copy
/// from the KBS's — and that copy is one unreplicated 1 MiB file
/// (`/var/lib/hippius-miner/state/<vm>.raw`) on the host of the party
/// we explicitly do not trust. Lose it (host rebuild, disk failure, a
/// `state/` sweep, a migration path that forgets to carry it) and the
/// guest submits `1` forever while the KBS holds `N`: `check_only`
/// refuses before any Vault read, `seed` refuses because the row is
/// live, and the counter may never be walked down. The tenant's volume
/// is then never opened again — availability loss that is
/// indistinguishable, for the tenant, from destruction.
///
/// This is the operator's way back, and it is the ONLY one.
///
/// ## Why it is neither a rollback hole nor a DoS lever
///
/// - It writes NO counter. Arming sets a one-shot flag; the release
///   that consumes it commits `stored + 1` — never the submitted value
///   — so the counter moves exactly as one normal boot moves it, and
///   NOTHING here can lower it or re-admit a burned boot.
/// - It cannot brick. The value the guest must next submit is not
///   chosen by the operator at all (contrast `seed`, which needs a
///   `MAX_SEED_COUNTER` cap precisely because a chosen number can be
///   set out of the guest's reach); it is the KBS's own `stored + 1`,
///   echoed to the guest in the SIGNED release response and persisted
///   by the guest to its fresh state disk.
/// - It grants a hostile miner nothing. The submitted counter is read
///   from a file the miner can already read and write, so the miner
///   could always submit the "right" value; what an arm removes is one
///   boot's worth of DETECTION on a signal that was never miner-proof.
///   The gate that actually binds anti-rollback to the encrypted volume
///   is [`crate::volume_stamp`], which this route does not touch.
/// - It is one-shot: consumed by the release that uses it and cleared
///   by any successful commit for that VM, so it cannot linger.
///
/// Auth: mTLS + network policy at the ADMIN LISTENER, identical to
/// `register-vm` / `activate` / `seed-boot-counter`. Registered ONLY on
/// `kbs_transport::admin_handler::build_admin_router` — a miner
/// reaching this route would be exactly the party the counter exists to
/// constrain, which is why the recovery is an operator action and not,
/// say, an automatic re-baseline on a `boot-counter-lost` refusal.
pub fn process_admin_arm_boot_counter_resync(
    url_vm_id: &str,
    store: &dyn crate::boot_counter::BootCounterStore,
) -> core::result::Result<AdminArmResyncOk, AdminArmResyncErr> {
    use crate::boot_counter::ResyncOutcome;

    if url_vm_id.is_empty() {
        return Err(AdminArmResyncErr::BadRequest("vm-id-empty"));
    }
    match store
        .arm_resync(url_vm_id)
        .map_err(|e| AdminArmResyncErr::Internal(format!("boot_counter.arm_resync: {e}")))?
    {
        ResyncOutcome::Armed {
            stored,
            already_armed,
        } => Ok(AdminArmResyncOk {
            vm_id: url_vm_id.to_string(),
            stored,
            already_armed,
        }),
        ResyncOutcome::NothingToResync => Err(AdminArmResyncErr::NothingToResync {
            vm_id: url_vm_id.to_string(),
        }),
    }
}

/// Append the `arm-boot-counter-resync` outcome to the admin hash
/// chain. Mirrors [`record_admin_seed_outcome`] field-for-field.
///
/// `applied` is `true` only when this call actually set an arm that was
/// not already there — a re-drive (`already_armed`) wrote nothing, and
/// recording it as applied would make the chain claim a durable change
/// that did not happen. Same rule as `register-vm`'s `cached`.
///
/// This record is the ONLY durable, attributable trace that a resync
/// was authorised: the release that consumes the arm is recorded by the
/// release audit sink as an ordinary grant. An operator reconstructing
/// an incident reads them in that order.
pub fn record_admin_arm_resync_outcome(
    audit: &FileAdminAuditSink,
    url_vm_id: &str,
    body_sha256: &[u8; 32],
    peer_san: Option<&str>,
    peer_serial: Option<&str>,
    outcome: &core::result::Result<AdminArmResyncOk, AdminArmResyncErr>,
    now_unix: u64,
) -> Result<[u8; 32]> {
    let (applied, status, reason, vm_id) = match outcome {
        Ok(ok) => (!ok.already_armed, 200u16, None, Some(ok.vm_id.as_str())),
        Err(e) => (false, e.status_code(), Some(e.reason()), e.vm_id()),
    };
    let record = AdminAuditRecord {
        op: "arm-boot-counter-resync",
        url_vm_id,
        // No signed ticket on this op — the URL's vm_id is the whole
        // input, like `reset-volume-stamp-suppression`.
        ticket_id: None,
        vm_id,
        applied,
        status_code: status,
        reason,
        peer_san,
        peer_serial,
        body_sha256,
    };
    audit.append(&record, now_unix)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::boot_counter::BootCounterStore;
    use crate::persist::FileVmStateStore;
    use crate::ticket::L1Keyring;
    use ciborium::value::Value;
    use coset::{iana, CborSerializable, CoseSign1Builder, HeaderBuilder};
    use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
    use hippius_types::cbor::to_canonical_vec;
    use hippius_types::ticket::{OrderTicket, VaultRef, SCHEMA_V};
    use serde_bytes::ByteBuf;
    use std::collections::HashMap;
    use tempfile::TempDir;

    struct StaticKeyring(HashMap<Vec<u8>, VerifyingKey>);
    impl L1Keyring for StaticKeyring {
        fn verifying_key(&self, kid: &[u8]) -> Option<VerifyingKey> {
            self.0.get(kid).copied()
        }
    }

    fn mint_ticket(sk: &SigningKey, kid: &[u8], vm_id: &str, gen: u64) -> Vec<u8> {
        let ticket = OrderTicket {
            v: SCHEMA_V,
            ticket_id: "tk-test-1".into(),
            issue_time: 1_000,
            expiry: 100_000,
            nonce: ByteBuf::from(vec![1u8; 32]),
            tenant_id: "tenant-1".into(),
            user_id: "user-1".into(),
            vm_id: vm_id.into(),
            lease_id: "lease-1".into(),
            vm_generation: gen,
            node_id: "node-test".into(),
            platform_id: "chip-aaaa".into(),
            allowed_measurements: vec![ByteBuf::from(vec![0x11u8; 48])],
            userdata_vault_ref: VaultRef {
                path: "secret/u".into(),
                version: 1,
            },
            luks_vault_ref: VaultRef {
                path: "secret/l".into(),
                version: 1,
            },
            allowed_userdata_digest: ByteBuf::from(vec![0x22u8; 32]),
            flavor: hippius_types::flavor::Flavor::Small,
            lifecycle_perms: vec!["launch".into()],
        };
        let payload_value = ticket_to_cbor_value(&ticket);
        let payload = to_canonical_vec(&payload_value).unwrap();
        let protected = HeaderBuilder::new()
            .algorithm(iana::Algorithm::EdDSA)
            .key_id(kid.to_vec())
            .build();
        let sign1 = CoseSign1Builder::new()
            .protected(protected)
            .payload(payload)
            .create_signature(b"", |tbs| {
                let s: Signature = sk.sign(tbs);
                s.to_bytes().to_vec()
            })
            .build();
        sign1.to_vec().unwrap()
    }

    fn ticket_to_cbor_value(t: &OrderTicket) -> Value {
        Value::Map(vec![
            (
                Value::Text("allowed_measurements".into()),
                Value::Array(
                    t.allowed_measurements
                        .iter()
                        .map(|m| Value::Bytes(m.to_vec()))
                        .collect(),
                ),
            ),
            (
                Value::Text("allowed_userdata_digest".into()),
                Value::Bytes(t.allowed_userdata_digest.to_vec()),
            ),
            (
                Value::Text("expiry".into()),
                Value::Integer(t.expiry.into()),
            ),
            (
                Value::Text("issue_time".into()),
                Value::Integer(t.issue_time.into()),
            ),
            (
                Value::Text("lease_id".into()),
                Value::Text(t.lease_id.clone()),
            ),
            (
                Value::Text("lifecycle_perms".into()),
                Value::Array(
                    t.lifecycle_perms
                        .iter()
                        .map(|p| Value::Text(p.clone()))
                        .collect(),
                ),
            ),
            (
                Value::Text("luks_vault_ref".into()),
                Value::Map(vec![
                    (
                        Value::Text("path".into()),
                        Value::Text(t.luks_vault_ref.path.clone()),
                    ),
                    (
                        Value::Text("version".into()),
                        Value::Integer(t.luks_vault_ref.version.into()),
                    ),
                ]),
            ),
            (
                Value::Text("node_id".into()),
                Value::Text(t.node_id.clone()),
            ),
            (Value::Text("nonce".into()), Value::Bytes(t.nonce.to_vec())),
            (
                Value::Text("platform_id".into()),
                Value::Text(t.platform_id.clone()),
            ),
            (
                Value::Text("flavor".into()),
                Value::Text(t.flavor.as_str().into()),
            ),
            (
                Value::Text("tenant_id".into()),
                Value::Text(t.tenant_id.clone()),
            ),
            (
                Value::Text("ticket_id".into()),
                Value::Text(t.ticket_id.clone()),
            ),
            (
                Value::Text("user_id".into()),
                Value::Text(t.user_id.clone()),
            ),
            (Value::Text("v".into()), Value::Integer(t.v.into())),
            (
                Value::Text("vm_generation".into()),
                Value::Integer(t.vm_generation.into()),
            ),
            (Value::Text("vm_id".into()), Value::Text(t.vm_id.clone())),
            (
                Value::Text("userdata_vault_ref".into()),
                Value::Map(vec![
                    (
                        Value::Text("path".into()),
                        Value::Text(t.userdata_vault_ref.path.clone()),
                    ),
                    (
                        Value::Text("version".into()),
                        Value::Integer(t.userdata_vault_ref.version.into()),
                    ),
                ]),
            ),
        ])
    }

    fn fresh_stores() -> (
        TempDir,
        FileVmStateStore,
        crate::persist::FileIdempotencyStore,
    ) {
        let td = TempDir::new().unwrap();
        let vm_states = FileVmStateStore::open(td.path().join("vm-states.json")).unwrap();
        let idem =
            crate::persist::FileIdempotencyStore::open(td.path().join("idem"), 86400).unwrap();
        (td, vm_states, idem)
    }

    fn fresh_keyring() -> (SigningKey, Vec<u8>, StaticKeyring) {
        let sk = SigningKey::from_bytes(&[42u8; 32]);
        let kid = b"l1-test-kid".to_vec();
        let mut map = HashMap::new();
        map.insert(kid.clone(), sk.verifying_key());
        (sk, kid, StaticKeyring(map))
    }

    #[test]
    fn happy_path_inserts_and_returns_not_cached() {
        let (_td, vm_states, idem) = fresh_stores();
        let (sk, kid, keyring) = fresh_keyring();
        let body = mint_ticket(&sk, &kid, "vm-A", 1);

        let ok = process_admin_register(&body, "vm-A", &keyring, &vm_states, &idem, 2_000).unwrap();
        assert_eq!(ok.ticket_id, "tk-test-1");
        assert_eq!(ok.vm_id, "vm-A");
        assert_eq!(ok.vm_generation, 1);
        assert_eq!(ok.host, "chip-aaaa");
        assert!(!ok.cached, "first insert must not be cached");

        // VmState should now be Active{gen=1, ...}.
        let state = vm_states.get("vm-A").unwrap();
        assert!(matches!(state, VmState::Active { gen: 1, .. }));
    }

    #[test]
    fn idempotent_replay_same_body_returns_cached() {
        let (_td, vm_states, idem) = fresh_stores();
        let (sk, kid, keyring) = fresh_keyring();
        let body = mint_ticket(&sk, &kid, "vm-B", 2);

        let _ = process_admin_register(&body, "vm-B", &keyring, &vm_states, &idem, 2_000).unwrap();
        let ok2 =
            process_admin_register(&body, "vm-B", &keyring, &vm_states, &idem, 2_001).unwrap();
        assert!(ok2.cached, "second apply with same body must be cached");
    }

    #[test]
    fn url_mismatch_rejected() {
        let (_td, vm_states, idem) = fresh_stores();
        let (sk, kid, keyring) = fresh_keyring();
        let body = mint_ticket(&sk, &kid, "vm-C", 3);

        let err = process_admin_register(&body, "vm-WRONG", &keyring, &vm_states, &idem, 2_000)
            .unwrap_err();
        assert!(matches!(err, AdminRegisterErr::UrlVmIdMismatch { .. }));
        assert_eq!(err.status_code(), 400);
        assert_eq!(err.reason(), "url-vm-id-mismatch");
    }

    #[test]
    fn bad_signature_rejected_400() {
        let (_td, vm_states, idem) = fresh_stores();
        let (sk, kid, keyring) = fresh_keyring();
        let mut body = mint_ticket(&sk, &kid, "vm-D", 1);
        // Flip a byte deep in the signature region — last bytes of
        // the COSE envelope. The exact offset is encoding-dependent;
        // mutating the very last byte (or the kid prefix length etc.)
        // typically lands in the signature or breaks canonical-CBOR.
        let last = body.len() - 1;
        body[last] ^= 0x01;
        let err =
            process_admin_register(&body, "vm-D", &keyring, &vm_states, &idem, 2_000).unwrap_err();
        assert!(
            matches!(
                err,
                AdminRegisterErr::TicketInvalid(_) | AdminRegisterErr::TicketDecode(_)
            ),
            "got {err:?}"
        );
        assert_eq!(err.status_code(), 400);
    }

    #[test]
    fn body_too_large_rejected() {
        let (_td, vm_states, idem) = fresh_stores();
        let (_sk, _kid, keyring) = fresh_keyring();
        let body = vec![0u8; MAX_ADMIN_BODY_BYTES + 1];
        let err =
            process_admin_register(&body, "vm-E", &keyring, &vm_states, &idem, 2_000).unwrap_err();
        assert!(matches!(err, AdminRegisterErr::BodyTooLarge));
        assert_eq!(err.status_code(), 413);
    }

    #[test]
    fn state_conflict_when_existing_state_differs() {
        let (_td, vm_states, idem) = fresh_stores();
        let (sk, kid, keyring) = fresh_keyring();
        let body = mint_ticket(&sk, &kid, "vm-F", 1);

        // Seed an Active state with a different gen.
        vm_states
            .put(
                "vm-F",
                VmState::Active {
                    gen: 999,
                    host: "different-chip".into(),
                    lease_id: "different-lease".into(),
                },
            )
            .unwrap();

        let err =
            process_admin_register(&body, "vm-F", &keyring, &vm_states, &idem, 2_000).unwrap_err();
        assert!(matches!(err, AdminRegisterErr::StateConflict { .. }));
        assert_eq!(err.status_code(), 409);
        assert_eq!(err.reason(), "state-conflict");
    }

    #[test]
    fn state_divergent_when_ticket_id_replays_with_different_body() {
        let (_td, vm_states, idem) = fresh_stores();
        let (sk, kid, keyring) = fresh_keyring();
        // First ticket: vm-G, gen=1.
        let body1 = mint_ticket(&sk, &kid, "vm-G", 1);
        let _ok =
            process_admin_register(&body1, "vm-G", &keyring, &vm_states, &idem, 2_000).unwrap();

        // Mint a second ticket with the SAME ticket_id (handler test
        // primitive `mint_ticket` always uses "tk-test-1") but a
        // different `vm_generation` ⇒ different body bytes.
        let body2 = mint_ticket(&sk, &kid, "vm-G", 7);
        assert_ne!(body1, body2);
        let err =
            process_admin_register(&body2, "vm-G", &keyring, &vm_states, &idem, 2_001).unwrap_err();
        assert!(matches!(err, AdminRegisterErr::StateDivergent { .. }));
        assert_eq!(err.status_code(), 409);
        assert_eq!(err.reason(), "state-divergent");
    }

    // ── §25 activate (Active → Migrating) tests ─────────────────────

    /// Register an `Active{gen,host,lease}` directly (skips the
    /// ticket-verify path; we only need the lifecycle row to exist).
    fn seed_active(vm_states: &FileVmStateStore, vm_id: &str, gen: u64, host: &str, lease: &str) {
        let outcome = vm_states
            .register(
                vm_id,
                VmState::Active {
                    gen,
                    host: host.into(),
                    lease_id: lease.into(),
                },
            )
            .unwrap();
        assert_eq!(outcome, RegisterOutcome::Inserted);
    }

    #[test]
    fn activate_transitions_active_to_migrating_and_fences_source() {
        let (_td, vm_states, _idem) = fresh_stores();
        seed_active(&vm_states, "vm-mig", 5, "src-node", "lease-9");

        let ok = process_admin_activate("vm-mig", 6, "dst-node", &vm_states).unwrap();
        assert!(!ok.cached);
        assert_eq!(ok.old_gen, 5);
        assert_eq!(ok.new_gen, 6);
        assert_eq!(ok.dest, "dst-node");
        assert_eq!(ok.lease_id, "lease-9");

        // The durable state is now Migrating — and `check_releasable`
        // (the actual fence) lets ONLY dest@new_gen unlock, denying the
        // source at old_gen. This is the split-brain guarantee.
        let state = vm_states.get("vm-mig").unwrap();
        assert!(matches!(
            state,
            VmState::Migrating {
                old_gen: 5,
                new_gen: 6,
                ..
            }
        ));
        // Destination at new_gen unlocks; source at old_gen is fenced.
        crate::lifecycle::check_releasable(&state, 6, "lease-9", "dst-node").unwrap();
        assert!(crate::lifecycle::check_releasable(&state, 5, "lease-9", "src-node").is_err());
        // A stale generation (replay/rollback) can never unlock, even on
        // the destination node.
        assert!(crate::lifecycle::check_releasable(&state, 5, "lease-9", "dst-node").is_err());
    }

    #[test]
    fn activate_is_idempotent_on_redrive() {
        let (_td, vm_states, _idem) = fresh_stores();
        seed_active(&vm_states, "vm-idem", 1, "src", "lease-1");

        let first = process_admin_activate("vm-idem", 2, "dst", &vm_states).unwrap();
        assert!(!first.cached);
        // Re-drive with the SAME (new_gen, dest) — idempotent cached hit.
        let second = process_admin_activate("vm-idem", 2, "dst", &vm_states).unwrap();
        assert!(second.cached);
        assert_eq!(second.old_gen, 1);
        assert_eq!(second.lease_id, "lease-1");
    }

    #[test]
    fn activate_redrive_with_divergent_target_is_conflict() {
        let (_td, vm_states, _idem) = fresh_stores();
        seed_active(&vm_states, "vm-div", 1, "src", "lease-1");
        process_admin_activate("vm-div", 2, "dst-a", &vm_states).unwrap();

        // A second activate that would re-target a DIFFERENT dest must
        // NOT silently re-point the migration — it is a 409 conflict.
        let err = process_admin_activate("vm-div", 2, "dst-b", &vm_states).unwrap_err();
        assert_eq!(err.status_code(), 409);
        assert_eq!(err.reason(), "activate-conflict");
        // A different new_gen is likewise a conflict.
        let err2 = process_admin_activate("vm-div", 3, "dst-a", &vm_states).unwrap_err();
        assert_eq!(err2.status_code(), 409);
    }

    #[test]
    fn activate_unknown_vm_is_conflict_not_silent_insert() {
        let (_td, vm_states, _idem) = fresh_stores();
        // No register-vm first ⇒ no Active row ⇒ activate must NOT
        // fabricate a Migrating state (which would open the release
        // path for an unregistered VM). 409.
        let err = process_admin_activate("vm-ghost", 2, "dst", &vm_states).unwrap_err();
        assert_eq!(err.status_code(), 409);
    }

    #[test]
    fn activate_rejects_empty_dest_and_vm_id() {
        let (_td, vm_states, _idem) = fresh_stores();
        seed_active(&vm_states, "vm-x", 1, "src", "l");
        assert!(matches!(
            process_admin_activate("vm-x", 2, "", &vm_states).unwrap_err(),
            AdminActivateErr::BadRequest("dest-empty")
        ));
        assert!(matches!(
            process_admin_activate("", 2, "dst", &vm_states).unwrap_err(),
            AdminActivateErr::BadRequest("vm-id-empty")
        ));
    }

    #[test]
    fn activate_over_decommissioning_is_conflict() {
        let (_td, vm_states, _idem) = fresh_stores();
        // A VM mid-decommission must never be re-activated for migration.
        vm_states
            .register("vm-dec", VmState::Decommissioning)
            .unwrap();
        let err = process_admin_activate("vm-dec", 2, "dst", &vm_states).unwrap_err();
        assert_eq!(err.status_code(), 409);
    }

    #[test]
    fn activate_at_the_same_generation_is_refused_and_writes_nothing() {
        // CLAIM: `new_gen == old_gen` must be refused. The fence flips
        // `check_releasable` to admit exactly `new_gen`, so activating
        // at the SOURCE's own generation would leave the source
        // releasable on the destination host — the split-brain the whole
        // §25 fence exists to prevent.
        let (_td, vm_states, _idem) = fresh_stores();
        seed_active(&vm_states, "vm-same", 5, "src-node", "lease-9");

        let err = process_admin_activate("vm-same", 5, "dst-node", &vm_states).unwrap_err();
        assert_eq!(err.status_code(), 409);
        assert_eq!(err.reason(), "activate-not-monotonic");
        assert!(matches!(
            err,
            AdminActivateErr::NonMonotonic {
                old_gen: 5,
                requested: 5,
                ..
            }
        ));

        // Nothing written: the row is still the untouched Active, and
        // the SOURCE — not a destination — is who can unlock.
        let cur = vm_states.get("vm-same").unwrap();
        assert_eq!(
            cur,
            VmState::Active {
                gen: 5,
                host: "src-node".into(),
                lease_id: "lease-9".into()
            }
        );
        assert!(crate::lifecycle::check_releasable(&cur, 5, "lease-9", "dst-node").is_err());
    }

    #[test]
    fn activate_at_a_lower_generation_is_refused_and_writes_nothing() {
        // CLAIM: `new_gen < old_gen` is a rollback — it would re-admit a
        // generation that has already been burned.
        let (_td, vm_states, _idem) = fresh_stores();
        seed_active(&vm_states, "vm-back", 7, "src-node", "lease-7");

        for bad in [6u64, 1, 0] {
            let err = process_admin_activate("vm-back", bad, "dst", &vm_states).unwrap_err();
            assert_eq!(err.reason(), "activate-not-monotonic", "new_gen={bad}");
            assert_eq!(err.status_code(), 409);
        }
        assert_eq!(
            vm_states.get("vm-back").unwrap(),
            VmState::Active {
                gen: 7,
                host: "src-node".into(),
                lease_id: "lease-7".into()
            }
        );
    }

    #[test]
    fn activate_one_past_the_current_generation_still_applies() {
        // Guard against over-tightening the monotonic gate: the normal
        // §25 step (old_gen + 1) must still go through.
        let (_td, vm_states, _idem) = fresh_stores();
        seed_active(&vm_states, "vm-fwd", 5, "src", "lease-5");
        let ok = process_admin_activate("vm-fwd", 6, "dst", &vm_states).unwrap();
        assert_eq!(ok.old_gen, 5);
        assert_eq!(ok.new_gen, 6);
        assert!(!ok.cached);
    }

    #[test]
    fn activate_audit_records_both_outcomes_with_peer_attribution() {
        // CLAIM: every activate — applied AND refused — lands in the
        // hash-chained admin log carrying the mTLS peer that drove it.
        // Before this the §25 fence wrote NO audit record at all.
        let td = TempDir::new().unwrap();
        let audit = FileAdminAuditSink::open(td.path().join("audit")).unwrap();
        let (_td2, vm_states, _idem) = fresh_stores();
        seed_active(&vm_states, "vm-a", 1, "src", "lease-1");
        let sha = [9u8; 32];

        let applied = process_admin_activate("vm-a", 2, "dst", &vm_states);
        record_admin_activate_outcome(
            &audit,
            "vm-a",
            &sha,
            Some("spiffe://hippius.network/vali"),
            Some("0a1b"),
            &applied,
            1_000,
        )
        .unwrap();

        let refused = process_admin_activate("vm-a", 2, "other-dst", &vm_states);
        assert!(refused.is_err());
        record_admin_activate_outcome(&audit, "vm-a", &sha, None, None, &refused, 1_001).unwrap();

        let verified = audit.verify().unwrap();
        assert_eq!(verified.records, 2, "both outcomes are in the chain");
    }

    // ── seed-boot-counter (operator disaster recovery) ──────────────

    #[test]
    fn seed_boot_counter_recovers_a_wiped_store() {
        // CLAIM: the recovery path works — a wiped (== absent) counter
        // is raised to the value read off the miner's state disk, and
        // the guest's next boot (N+1) is then accepted.
        let store = crate::boot_counter::InMemoryBootCounterStore::default();
        let ok = process_admin_seed_boot_counter("vm-r", 12, &store).unwrap();
        assert_eq!(ok.vm_id, "vm-r");
        assert_eq!(ok.previous, 0);
        assert_eq!(ok.counter, 12);
        assert_eq!(store.get("vm-r").unwrap(), 12);
        assert_eq!(store.check_only("vm-r", 13).unwrap(), 13);
        assert!(store.check_only("vm-r", 12).is_err());
    }

    #[test]
    fn seed_boot_counter_refuses_a_live_counter_409_and_writes_nothing() {
        // CLAIM (guard 1, the DoS closure at the API layer): once a VM
        // has a counter, EVERY seed — down, equal or up — is a 409
        // `seed-already-recovered` that leaves the store untouched. Both
        // halves are asserted: an error that still wrote would be the
        // exact hole (downward = rollback, upward = brick).
        let store = crate::boot_counter::InMemoryBootCounterStore::default();
        process_admin_seed_boot_counter("vm-r", 10, &store).unwrap();

        for attempt in [10u64, 9, 1, 11, crate::boot_counter::MAX_SEED_COUNTER] {
            let err = process_admin_seed_boot_counter("vm-r", attempt, &store).unwrap_err();
            assert_eq!(err.status_code(), 409, "attempt {attempt}");
            assert_eq!(err.reason(), "seed-already-recovered", "attempt {attempt}");
            assert_eq!(
                err,
                AdminSeedErr::AlreadyRecovered {
                    vm_id: "vm-r".into(),
                    stored: 10,
                }
            );
            assert_eq!(
                store.get("vm-r").unwrap(),
                10,
                "a refused seed must not mutate (attempt {attempt})"
            );
        }
        // The gate is still where 10 real boots would have left it.
        assert!(store.check_only("vm-r", 10).is_err());
        assert_eq!(store.check_only("vm-r", 11).unwrap(), 11);
    }

    #[test]
    fn seed_boot_counter_rejects_zero_and_empty_vm_id_400() {
        let store = crate::boot_counter::InMemoryBootCounterStore::default();
        assert!(matches!(
            process_admin_seed_boot_counter("vm-r", 0, &store).unwrap_err(),
            AdminSeedErr::BadRequest("counter-zero")
        ));
        assert!(matches!(
            process_admin_seed_boot_counter("", 5, &store).unwrap_err(),
            AdminSeedErr::BadRequest("vm-id-empty")
        ));
        // Neither created a row.
        assert_eq!(store.get("vm-r").unwrap(), 0);
        assert_eq!(store.get("").unwrap(), 0);
    }

    #[test]
    fn seed_boot_counter_rejects_above_cap_400_and_accepts_the_cap_itself() {
        // CLAIM (guard 2): an implausible counter is a 400 with its OWN
        // reason — distinguishable from both the 409s — and writes
        // nothing; the boundary value itself is accepted.
        let store = crate::boot_counter::InMemoryBootCounterStore::default();
        let cap = crate::boot_counter::MAX_SEED_COUNTER;
        for attempt in [cap + 1, u64::MAX] {
            let err = process_admin_seed_boot_counter("vm-cap", attempt, &store).unwrap_err();
            assert_eq!(err.status_code(), 400, "attempt {attempt}");
            assert_eq!(err.reason(), "seed-above-cap", "attempt {attempt}");
            assert_eq!(
                err,
                AdminSeedErr::AboveCap {
                    vm_id: "vm-cap".into(),
                    requested: attempt,
                    cap,
                }
            );
            assert_eq!(store.get("vm-cap").unwrap(), 0, "attempt {attempt}");
        }
        assert_eq!(
            process_admin_seed_boot_counter("vm-cap", cap, &store)
                .unwrap()
                .counter,
            cap
        );
    }

    #[test]
    fn seed_boot_counter_refusals_are_three_distinct_codes() {
        // CLAIM: an operator can tell the three refusals apart. Collapsing
        // any two would hide the only alarming one (a rollback attempt)
        // inside the noise of the benign ones.
        let live = AdminSeedErr::AlreadyRecovered {
            vm_id: "v".into(),
            stored: 3,
        };
        let cap = AdminSeedErr::AboveCap {
            vm_id: "v".into(),
            requested: 9_999_999,
            cap: crate::boot_counter::MAX_SEED_COUNTER,
        };
        let mono = AdminSeedErr::NotMonotonic {
            vm_id: "v".into(),
            stored: 3,
            requested: 1,
        };
        let reasons = [live.reason(), cap.reason(), mono.reason()];
        assert_eq!(
            reasons,
            [
                "seed-already-recovered",
                "seed-above-cap",
                "seed-not-monotonic"
            ]
        );
        assert_eq!(
            reasons
                .iter()
                .collect::<std::collections::HashSet<_>>()
                .len(),
            3,
            "the refusal reasons must not collapse"
        );
        // …and each attributes the VM, so the audit line names it.
        for e in [&live, &cap, &mono] {
            assert_eq!(e.vm_id(), Some("v"), "{e:?}");
        }
    }

    #[test]
    fn a_store_level_monotonic_refusal_still_maps_to_409_not_monotonic() {
        // CLAIM: guard 3's mapping is intact. With guard 1 in place the
        // real store can only return `Refused` for counter 0, which this
        // layer rejects earlier as a 400 — so the mapping is unreachable
        // through the production store and would rot silently. Pin it
        // with a stub: if guard 1 is ever relaxed, monotonicity must
        // still surface as its own 409, not as a success.
        struct AlwaysRefuses;
        impl crate::boot_counter::BootCounterStore for AlwaysRefuses {
            fn check_only(&self, _: &str, _: u64) -> Result<u64> {
                unreachable!("not exercised by seed")
            }
            fn commit(&self, _: &str, _: u64) -> Result<()> {
                unreachable!("not exercised by seed")
            }
            fn get(&self, _: &str) -> Result<u64> {
                Ok(4)
            }
            fn seed(&self, _: &str, _: u64) -> Result<crate::boot_counter::SeedOutcome> {
                Ok(crate::boot_counter::SeedOutcome::Refused { stored: 4 })
            }
            fn arm_resync(&self, _: &str) -> Result<crate::boot_counter::ResyncOutcome> {
                unreachable!("not exercised by seed")
            }
            fn resync_armed(&self, _: &str) -> Result<bool> {
                unreachable!("not exercised by seed")
            }
        }
        let err = process_admin_seed_boot_counter("vm-m", 2, &AlwaysRefuses).unwrap_err();
        assert_eq!(err.status_code(), 409);
        assert_eq!(err.reason(), "seed-not-monotonic");
        assert_eq!(
            err,
            AdminSeedErr::NotMonotonic {
                vm_id: "vm-m".into(),
                stored: 4,
                requested: 2,
            }
        );
    }

    #[test]
    fn seed_outcome_is_written_to_the_admin_audit_chain() {
        // CLAIM: the applied seed AND BOTH refusals land in the
        // hash-chained admin log, each under its own reason — those are
        // the lines an operator greps for after an incident.
        let td = TempDir::new().unwrap();
        let audit = FileAdminAuditSink::open(td.path().join("admin-audit")).unwrap();
        let store = crate::boot_counter::InMemoryBootCounterStore::default();
        let sha = [0x5au8; 32];

        let ok = process_admin_seed_boot_counter("vm-a", 6, &store);
        record_admin_seed_outcome(
            &audit,
            "vm-a",
            &sha,
            Some("spiffe://x/vali"),
            None,
            &ok,
            1_000,
        )
        .unwrap();
        let refused = process_admin_seed_boot_counter("vm-a", 2, &store);
        record_admin_seed_outcome(
            &audit,
            "vm-a",
            &sha,
            Some("spiffe://x/vali"),
            None,
            &refused,
            1_001,
        )
        .unwrap();
        let capped = process_admin_seed_boot_counter(
            "vm-b",
            crate::boot_counter::MAX_SEED_COUNTER + 1,
            &store,
        );
        record_admin_seed_outcome(
            &audit,
            "vm-b",
            &sha,
            Some("spiffe://x/vali"),
            None,
            &capped,
            1_002,
        )
        .unwrap();

        // Three records, chain intact.
        let v = audit.verify().unwrap();
        assert_eq!(v.records, 3);

        // And the content is legible: op + applied flag + the 409.
        let log = std::fs::read_to_string(td.path().join("admin-audit").join("admin.log")).unwrap();
        let lines: Vec<&str> = log.lines().collect();
        assert_eq!(lines.len(), 3);
        let decoded: Vec<String> = lines
            .iter()
            .map(|l| {
                let body_hex = l.split(':').nth(1).unwrap();
                let bytes = hex::decode(body_hex).unwrap();
                format!(
                    "{:?}",
                    ciborium::de::from_reader::<ciborium::value::Value, _>(bytes.as_slice())
                        .unwrap()
                )
            })
            .collect();
        assert!(decoded[0].contains("seed-boot-counter"), "{}", decoded[0]);
        assert!(decoded[0].contains("Bool(true)"), "{}", decoded[0]);
        assert!(
            decoded[1].contains("seed-already-recovered"),
            "{}",
            decoded[1]
        );
        assert!(decoded[1].contains("Bool(false)"), "{}", decoded[1]);
        assert!(decoded[2].contains("seed-above-cap"), "{}", decoded[2]);
        assert!(decoded[2].contains("Bool(false)"), "{}", decoded[2]);
    }

    // ── reset-volume-stamp-suppression (operator recovery) ──────────

    #[test]
    fn reset_volume_stamp_suppression_clears_a_blocked_vm() {
        use crate::volume_stamp::VolumeStampStore;
        let store = crate::volume_stamp::InMemoryVolumeStampStore::default();
        // Drive the suppression counter past what `crate::release::run`
        // would tolerate — the exact count doesn't matter to THIS
        // endpoint, only that it is non-zero.
        store.note_release("vm-a").unwrap();
        store.note_release("vm-a").unwrap();
        store.note_release("vm-a").unwrap();

        let ok = process_admin_reset_volume_stamp_suppression("vm-a", &store).unwrap();
        assert_eq!(ok.vm_id, "vm-a");
        assert_eq!(ok.cleared, 3);
        // Confirmed stamp is untouched — this endpoint can only ever
        // unblock releases, never move the anti-rollback reference.
        assert_eq!(store.get("vm-a").unwrap(), 0);
    }

    #[test]
    fn reset_volume_stamp_suppression_on_an_unblocked_vm_is_a_harmless_200() {
        let store = crate::volume_stamp::InMemoryVolumeStampStore::default();
        let ok = process_admin_reset_volume_stamp_suppression("vm-fresh", &store).unwrap();
        assert_eq!(ok.cleared, 0, "nothing was blocking this VM");
    }

    #[test]
    fn reset_volume_stamp_suppression_rejects_empty_vm_id() {
        let store = crate::volume_stamp::InMemoryVolumeStampStore::default();
        let err = process_admin_reset_volume_stamp_suppression("", &store).unwrap_err();
        assert_eq!(err.status_code(), 400);
        assert_eq!(err.reason(), "vm-id-empty");
    }

    #[test]
    fn reset_volume_stamp_suppression_is_per_vm() {
        use crate::volume_stamp::VolumeStampStore;
        let store = crate::volume_stamp::InMemoryVolumeStampStore::default();
        store.note_release("vm-a").unwrap();
        store.note_release("vm-a").unwrap();
        store.note_release("vm-b").unwrap();

        let ok = process_admin_reset_volume_stamp_suppression("vm-b", &store).unwrap();
        assert_eq!(ok.cleared, 1);
        // `vm-a`'s count is untouched by `vm-b`'s reset.
        assert_eq!(store.note_release("vm-a").unwrap(), (0, 3));
    }

    #[test]
    fn reset_volume_stamp_suppression_outcome_is_written_to_the_admin_audit_chain() {
        // CLAIM: both the applied reset AND a refusal land in the
        // hash-chained admin log, attributed to the mTLS peer — the
        // same discipline every other admin op gets.
        use crate::volume_stamp::VolumeStampStore;
        let td = TempDir::new().unwrap();
        let audit = FileAdminAuditSink::open(td.path().join("admin-audit")).unwrap();
        let store = crate::volume_stamp::InMemoryVolumeStampStore::default();
        store.note_release("vm-a").unwrap();
        let sha = [0x5au8; 32];

        let ok = process_admin_reset_volume_stamp_suppression("vm-a", &store);
        record_admin_reset_volume_stamp_suppression_outcome(
            &audit,
            "vm-a",
            &sha,
            Some("spiffe://x/operator"),
            None,
            &ok,
            1_000,
        )
        .unwrap();
        let refused = process_admin_reset_volume_stamp_suppression("", &store);
        record_admin_reset_volume_stamp_suppression_outcome(
            &audit,
            "",
            &sha,
            Some("spiffe://x/operator"),
            None,
            &refused,
            1_001,
        )
        .unwrap();

        let v = audit.verify().unwrap();
        assert_eq!(v.records, 2);
        let log = std::fs::read_to_string(td.path().join("admin-audit").join("admin.log")).unwrap();
        let lines: Vec<&str> = log.lines().collect();
        assert_eq!(lines.len(), 2);
        let decoded: Vec<String> = lines
            .iter()
            .map(|l| {
                let body_hex = l.split(':').nth(1).unwrap();
                let bytes = hex::decode(body_hex).unwrap();
                format!(
                    "{:?}",
                    ciborium::de::from_reader::<ciborium::value::Value, _>(bytes.as_slice())
                        .unwrap()
                )
            })
            .collect();
        assert!(
            decoded[0].contains("reset-volume-stamp-suppression"),
            "{}",
            decoded[0]
        );
        assert!(decoded[0].contains("Bool(true)"), "{}", decoded[0]);
        assert!(decoded[1].contains("vm-id-empty"), "{}", decoded[1]);
        assert!(decoded[1].contains("Bool(false)"), "{}", decoded[1]);
    }

    // ── arm-boot-counter-resync (operator recovery, other direction) ──

    #[test]
    fn arm_resync_arms_a_live_counter_without_moving_it() {
        // CLAIM: the endpoint's whole write is the arm. It reports the
        // stored counter so the operator can see what the next boot
        // will be re-baselined to, and it does NOT change that counter
        // — this route has no path to a counter write at all.
        let store = crate::boot_counter::InMemoryBootCounterStore::default();
        store.check_and_advance("vm-a", 1).unwrap();
        store.check_and_advance("vm-a", 2).unwrap();

        let ok = process_admin_arm_boot_counter_resync("vm-a", &store).unwrap();
        assert_eq!(
            ok,
            AdminArmResyncOk {
                vm_id: "vm-a".into(),
                stored: 2,
                already_armed: false,
            }
        );
        assert_eq!(store.get("vm-a").unwrap(), 2);
        assert!(store.resync_armed("vm-a").unwrap());
        // The gate itself is untouched at this layer.
        assert!(store.check_only("vm-a", 1).is_err());
        assert_eq!(store.check_only("vm-a", 3).unwrap(), 3);
    }

    #[test]
    fn arm_resync_re_drive_reports_already_armed_and_is_not_recorded_as_applied() {
        // CLAIM: a duplicate arm wrote nothing, so the audit chain must
        // not claim a durable change. `applied` is the field an operator
        // counts incidents by.
        let td = TempDir::new().unwrap();
        let audit = FileAdminAuditSink::open(td.path().join("admin-audit")).unwrap();
        let store = crate::boot_counter::InMemoryBootCounterStore::default();
        store.check_and_advance("vm-a", 1).unwrap();
        let sha = [0x5au8; 32];

        let first = process_admin_arm_boot_counter_resync("vm-a", &store);
        assert!(matches!(
            first,
            Ok(AdminArmResyncOk {
                already_armed: false,
                ..
            })
        ));
        record_admin_arm_resync_outcome(&audit, "vm-a", &sha, None, None, &first, 1_000).unwrap();

        let second = process_admin_arm_boot_counter_resync("vm-a", &store);
        assert!(matches!(
            second,
            Ok(AdminArmResyncOk {
                already_armed: true,
                ..
            })
        ));
        record_admin_arm_resync_outcome(&audit, "vm-a", &sha, None, None, &second, 1_001).unwrap();

        let decoded = decode_admin_log(td.path());
        assert_eq!(decoded.len(), 2);
        assert!(
            decoded[0].contains("arm-boot-counter-resync"),
            "{}",
            decoded[0]
        );
        assert!(decoded[0].contains("Bool(true)"), "{}", decoded[0]);
        assert!(
            decoded[1].contains("Bool(false)"),
            "a re-drive wrote nothing and must not be recorded as applied: {}",
            decoded[1]
        );
    }

    #[test]
    fn arm_resync_refuses_a_vm_the_kbs_never_counted() {
        // CLAIM (guard 1): a `stored == 0` row is a 409, not a silent
        // no-op arm. A guest with no state disk submits 1, which that
        // row already accepts — so arming one can only be a mistake, and
        // an arm left on a row that later becomes a real VM's FIRST boot
        // is a one-shot bypass nobody knows is there.
        let store = crate::boot_counter::InMemoryBootCounterStore::default();
        let err = process_admin_arm_boot_counter_resync("vm-fresh", &store).unwrap_err();
        assert_eq!(err.status_code(), 409);
        assert_eq!(err.reason(), "resync-nothing-to-resync");
        assert_eq!(err.vm_id(), Some("vm-fresh"));
        assert!(!store.resync_armed("vm-fresh").unwrap());
        assert_eq!(store.get("vm-fresh").unwrap(), 0);
    }

    #[test]
    fn arm_resync_rejects_an_empty_vm_id_400() {
        let store = crate::boot_counter::InMemoryBootCounterStore::default();
        let err = process_admin_arm_boot_counter_resync("", &store).unwrap_err();
        assert_eq!(err.status_code(), 400);
        assert_eq!(err.reason(), "vm-id-empty");
        assert_eq!(err.vm_id(), None);
    }

    #[test]
    fn arm_resync_surfaces_a_store_failure_as_500_not_as_a_refusal() {
        // CLAIM: a broken store must not masquerade as "nothing to
        // resync" — the operator would conclude the VM is fine when the
        // recovery never landed. Retry-safe: a failed arm writes
        // nothing.
        struct Broken;
        impl crate::boot_counter::BootCounterStore for Broken {
            fn check_only(&self, _: &str, _: u64) -> Result<u64> {
                unreachable!("not exercised by arm")
            }
            fn commit(&self, _: &str, _: u64) -> Result<()> {
                unreachable!("not exercised by arm")
            }
            fn get(&self, _: &str) -> Result<u64> {
                Ok(3)
            }
            fn seed(&self, _: &str, _: u64) -> Result<crate::boot_counter::SeedOutcome> {
                unreachable!("not exercised by arm")
            }
            fn arm_resync(&self, _: &str) -> Result<crate::boot_counter::ResyncOutcome> {
                Err(crate::error::KbsError::Vault("disk on fire".into()))
            }
            fn resync_armed(&self, _: &str) -> Result<bool> {
                unreachable!("not exercised by arm")
            }
        }
        let err = process_admin_arm_boot_counter_resync("vm-x", &Broken).unwrap_err();
        assert_eq!(err.status_code(), 500);
        assert_eq!(err.reason(), "internal-error");
    }

    #[test]
    fn arm_resync_refusals_land_in_the_admin_audit_chain() {
        // CLAIM: the arm is the ONLY durable trace that a resync was
        // authorised (the release that consumes it is recorded as an
        // ordinary grant), so every call — applied or refused — has to
        // be in the hash chain, attributed to the mTLS peer.
        let td = TempDir::new().unwrap();
        let audit = FileAdminAuditSink::open(td.path().join("admin-audit")).unwrap();
        let store = crate::boot_counter::InMemoryBootCounterStore::default();
        let sha = [0x5au8; 32];

        let refused = process_admin_arm_boot_counter_resync("vm-fresh", &store);
        record_admin_arm_resync_outcome(
            &audit,
            "vm-fresh",
            &sha,
            Some("spiffe://x/operator"),
            None,
            &refused,
            1_000,
        )
        .unwrap();
        let bad = process_admin_arm_boot_counter_resync("", &store);
        record_admin_arm_resync_outcome(
            &audit,
            "",
            &sha,
            Some("spiffe://x/operator"),
            None,
            &bad,
            1_001,
        )
        .unwrap();

        assert_eq!(audit.verify().unwrap().records, 2);
        let decoded = decode_admin_log(td.path());
        assert!(
            decoded[0].contains("resync-nothing-to-resync"),
            "{}",
            decoded[0]
        );
        assert!(decoded[0].contains("Bool(false)"), "{}", decoded[0]);
        assert!(decoded[1].contains("vm-id-empty"), "{}", decoded[1]);
        assert!(
            decoded[0].contains("spiffe://x/operator"),
            "the peer must be attributable: {}",
            decoded[0]
        );
    }

    /// Decode every record in the admin log under `dir` to its debug
    /// CBOR rendering — the same hex-body-after-the-colon shape the
    /// seed/suppression audit tests parse inline.
    fn decode_admin_log(dir: &std::path::Path) -> Vec<String> {
        let log = std::fs::read_to_string(dir.join("admin-audit").join("admin.log")).unwrap();
        log.lines()
            .map(|l| {
                let body_hex = l.split(':').nth(1).unwrap();
                let bytes = hex::decode(body_hex).unwrap();
                format!(
                    "{:?}",
                    ciborium::de::from_reader::<ciborium::value::Value, _>(bytes.as_slice())
                        .unwrap()
                )
            })
            .collect()
    }
}
