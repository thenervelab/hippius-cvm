"""§24/§25 orchestrators — the bounded, idempotent state machines.

Spec of record: ARCHITECTURE.md §24 / §25.

`tick_once()` is one cycle of the `vali_orchestration_tick` daemon: it
advances every non-terminal job by **one bounded step**. Each step is

  - **CAS-guarded** — the job advances only via an optimistic
    compare-and-swap on `(id, version, state)`, so a crashed-then-
    retried tick (or a second tick process) cannot double-advance;
  - **idempotency-guarded** — every external side-effect is wrapped
    `recall`-before / `record`-after against the §14 store. `record`
    follows the effect, so a crash in the sub-second window between
    the two can still re-run the effect on retry: the store removes
    the *common-case* re-run, and every peer effect is **required to
    be idempotent** (§24 crypto-erase is "already destroyed ⇒
    success"; the KBS release is a CAS; quiesce / snapshot-trigger /
    NetBird-revoke all tolerate a repeat). Peer-idempotency — not the
    store — is the crash-window guarantee;
  - **deadline-bounded** — a step that keeps failing, or a poll that
    never completes, is abandoned once `phase_started_at` ages past
    the per-phase timeout.

**Split-brain (§25).** `AwaitingSourceAck` advances to
`DestActivating` ONLY on a cryptographically verified source-stopped
ack. On a timeout it fails closed — Job → `Failed`, source
§13-quarantined, **destination never activated**. There is no code
path that activates the destination without that verified ack.

**Data death (§24).** `CryptoErasing` (erasable-KEK destroy) is
reached unconditionally — on a verified EOL ack OR on an ack timeout
(forced reclaim). Crypto-erase never depends on miner cooperation.
"""

from __future__ import annotations

import logging
import math
import secrets
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import timedelta
from typing import Any

from django.conf import settings
from django.db import IntegrityError, transaction
from django.db.models import Case, DateTimeField, F, Q, Value, When
from django.db.models.functions import Coalesce
from django.utils import timezone

from apps.lifecycle import boot_stall, guest_liveness
from apps.lifecycle import validator as lifecycle_validator
from apps.lifecycle.models import (
    StoppedAckIngest,
    Vm,
    VmBootPhase,
    VmNetbirdStatus,
    VmPowerState,
    VmState,
    destroyed_power_fields,
)
from apps.storage import s3

from . import effects, idempotency
from .effects import EffectError, EffectUnavailable
from .idempotency import IdempotencyUnavailable
from .models import (
    TERMINAL_DECOMMISSION_STATES,
    TERMINAL_MIGRATION_STATES,
    TERMINAL_RESIZE_STATES,
    DataDeath,
    DecommissionJob,
    DecommissionState,
    KbsFence,
    MigrationJob,
    MigrationKind,
    MigrationState,
    ResizeJob,
    SourceReclaimState,
    StrandRecoveryState,
)
from .services import customer_keys

log = logging.getLogger("apps.orchestration.service")

# Golden dm-verity-overlay disk mode (mirrors `launch_jobs._DISK_MODE_
# GOLDEN_VERITY` / `TenantBakeDiskMode.GOLDEN_VERITY_OVERLAY`). A golden VM's
# tenant KEK is a Vault-Transit key with NO KBS record, so its §24 crypto-
# erase differs from a legacy VM's KBS admin `crypto-erase`.
_DISK_MODE_GOLDEN_VERITY = "golden_verity_overlay"

# Exceptions that mean "this step failed THIS tick" — the driver
# retries the step until the phase deadline, then fails the job.
_RETRYABLE: tuple[type[Exception], ...] = (
    EffectError,
    IdempotencyUnavailable,
    s3.S3ClientUnavailable,
)


class _StepFailed(Exception):
    """A step's outcome is definitive failure — no retry can change it (e.g.
    the source miner's snapshot task ended `failed`). The driver fails the
    job at once instead of re-polling until the phase deadline."""


# A handler returns the next state + a field patch, or `None` to mean
# "still polling — stay in this state".
StepResult = "tuple[str, dict[str, Any]] | None"


class StartError(Exception):
    """A job could not be started (bad VM state, conflict). The view
    maps `category` to a 409/400.
    """

    def __init__(self, message: str, category: str) -> None:
        super().__init__(message)
        self.message = message
        self.category = category


class _AckInvalid(Exception):
    """A delivered guest ack failed verification. Fail-closed: the
    orchestrator does NOT advance — it keeps polling for a valid ack
    until the phase deadline.
    """


# ─── tuning knobs ────────────────────────────────────────────────────


def _step_timeout() -> float:
    return float(getattr(settings, "VALI_ORCHESTRATION_STEP_TIMEOUT_S", 300.0))


def _ack_timeout() -> float:
    return float(getattr(settings, "VALI_ORCHESTRATION_ACK_TIMEOUT_S", 600.0))


def _activate_timeout() -> float:
    # §25 dest-activation is a multi-GB snapshot download + boot on the dest
    # miner; the poll must tolerate the whole restore window (default 45 min).
    return float(getattr(settings, "VALI_ORCHESTRATION_ACTIVATE_TIMEOUT_S", 2700.0))


#: How long before vali's `DestActivating` deadline the destination must
#: have settled an activation: one poll tick to read the outcome, plus
#: clock skew between vali and the miner.
_ACTIVATE_SETTLE_SAFETY_S = 60

#: The least time before its settle-by a destination accepts an activation
#: in — the miner-agent's `DEST_LAUNCH_MARGIN` (orders/migration.rs), which
#: covers the launch's own ticket push. Less than that left, it refuses the
#: order before any download or launch (`dest-settle-by-passed`).
_DEST_SETTLE_WINDOW_S = 240


def _activate_settle_by_unix(job: MigrationJob) -> int:
    """The unix instant a `migrate-activate` order tells the destination to
    have settled by: this phase's deadline (`phase_started_at` +
    `_activate_timeout()`), less `_ACTIVATE_SETTLE_SAFETY_S`.

    `phase_started_at` moves only on a state change, so every attempt of
    one `DestActivating` phase carries the SAME value — the miner's clock
    no longer restarts with each retry and outlives vali's.
    """
    timeout = _activate_timeout()
    if job.kind == MigrationKind.FAILOVER.value:
        timeout = _restore().activate_timeout_s(job, timeout)
    deadline = job.phase_started_at.timestamp() + timeout
    return int(deadline) - _ACTIVATE_SETTLE_SAFETY_S


_warned_activate_timeout: float | None = None


def _warn_if_activate_timeout_too_small() -> None:
    """Say so, once per value, when `VALI_ORCHESTRATION_ACTIVATE_TIMEOUT_S`
    leaves a destination no room at all: every activate would arrive with
    less than `_DEST_SETTLE_WINDOW_S` before its settle-by, so none is sent
    and every migration fails at the phase deadline."""
    global _warned_activate_timeout
    timeout = _activate_timeout()
    if timeout > _ACTIVATE_SETTLE_SAFETY_S + _DEST_SETTLE_WINDOW_S:
        return
    if _warned_activate_timeout == timeout:
        return
    _warned_activate_timeout = timeout
    log.error(
        "VALI_ORCHESTRATION_ACTIVATE_TIMEOUT_S=%.0f leaves no room for a §25 "
        "destination to restore and settle (needs > %d s): no migrate-activate "
        "will be sent",
        timeout,
        _ACTIVATE_SETTLE_SAFETY_S + _DEST_SETTLE_WINDOW_S,
    )


def _upload_timeout() -> float:
    # §25 snapshot upload — multi-GB, sequential parts on the source miner.
    return float(getattr(settings, "VALI_ORCHESTRATION_UPLOAD_TIMEOUT_S", 3600.0))


def _presign_ttl() -> int:
    return int(getattr(settings, "VALI_ORCHESTRATION_PRESIGN_TTL_SECS", 3600))


def _snapshot_bucket() -> str:
    return str(
        getattr(
            settings,
            "VALI_ORCHESTRATION_SNAPSHOT_BUCKET",
            "hippius-compute-migrations",
        )
    )


def _phase_timed_out(phase_started_at: Any, timeout_s: float) -> bool:
    return timezone.now() - phase_started_at > timedelta(seconds=timeout_s)


# ─── reboot-recovery tuning knobs (k8s-config only) ──────────────────


def _reboot_recovery_enabled() -> bool:
    """Master switch — DEFAULT FALSE (dark launch). When off,
    `reboot_recovery_once` is a no-op."""
    return bool(getattr(settings, "VALI_REBOOT_RECOVERY_ENABLED", False))


def _reboot_recovery_debounce_polls() -> int:
    """Consecutive `down` polls required before a relaunch fires — filters a
    guest soft-reboot / the host-up→re-adopt window from a genuine
    powered-off CVM."""
    return max(1, int(getattr(settings, "VALI_REBOOT_RECOVERY_DEBOUNCE_POLLS", 3)))


def _reboot_recovery_max_attempts() -> int:
    """Relaunch attempt cap per VM — a VM that will not come back is not
    relaunched forever (dispatch-health backstop)."""
    return max(1, int(getattr(settings, "VALI_REBOOT_RECOVERY_MAX_ATTEMPTS", 5)))


def _reboot_recovery_stable_s() -> float:
    """How long after its last relaunch a VM must be seen up and not
    wedged before its incident counts as over. Default 1800 s. A VM that
    goes down again sooner is the SAME incident and spends from the same
    budget; the reset is only ever evaluated while the domain is up, so
    the backoff between attempts does not enter into it."""
    return float(getattr(settings, "VALI_REBOOT_RECOVERY_STABLE_S", 1800.0))


def _reboot_recovery_incident_over(rec: Any, *, now: Any) -> bool:
    """Whether the incident `rec.attempts` counts is over: the caller has
    just seen the domain up and the guest not wedged, and the last relaunch
    is at least `_reboot_recovery_stable_s()` old.

    Time, not a first in-guest signal: a guest that boots, emits one
    receipt and dies (a panic after boot, a tenant unit that powers off,
    or a relaunch false positive) would otherwise reset every cycle and be
    relaunched forever — the cap is there to bound exactly that. A guest
    that was heard from before the relaunch and not since reads `wedged`
    within the liveness bound (600 s) and never gets here.

    A VM that dies after staying up longer than the window starts a new
    incident each time: at most one relaunch per window, each after a
    genuinely healthy run.
    """
    if not rec.attempts:
        return False
    since = rec.last_relaunch_at
    if since is None:
        return True  # counted before the relaunch was timestamped
    return (now - since).total_seconds() >= _reboot_recovery_stable_s()


def _reboot_recovery_backoff_base_s() -> float:
    """Exponential-backoff base between relaunch attempts."""
    return float(getattr(settings, "VALI_REBOOT_RECOVERY_BACKOFF_BASE_S", 120.0))


def _reboot_recovery_on_wedged_guest() -> bool:
    """Second trigger — act on a WEDGED guest (domain running, nothing
    answering inside it), not just a down domain. DEFAULT FALSE.

    Off by default because the signal is guest-controllable: root inside a
    CVM can stop its own telemetry agent, which is indistinguishable from
    a wedge and would relaunch a VM the tenant is happily using. The
    OBSERVABILITY (the API field, the admin column, the per-tick sweep
    warning) ships armed regardless — only the automated action is gated
    here."""
    return bool(getattr(settings, "VALI_REBOOT_RECOVERY_ON_WEDGED_GUEST", False))


def _short(exc: Exception, limit: int = 180) -> str:
    return str(exc)[:limit]


# ─── public API: start jobs ──────────────────────────────────────────


def _has_active_job(
    vm: Vm, *, ignore_resize: bool = False, ignore_guest_upgrade: bool = False
) -> bool:
    """True iff the VM already has an in-flight migration, decommission,
    resize, or a guest upgrade that holds it (past `pending`; a pending
    upgrade waits for its window and re-checks everything when it leaves
    it — `apps.orchestration.guest_upgrade`).

    Same-kind double-starts are closed at the database by each
    model's partial unique index. A cross-kind race (a migration and
    a decommission started for the same VM in the same instant) can
    slip past this application-level check — but it is **bounded and
    safe**: the §24/§25 VM-state CAS is the real serialization point.
    Only one job can transition the `Vm` out of `Active`
    (`_fence_vm` vs `_decommission_vm`); the loser's CAS finds a
    non-Active VM and fails closed (and `_migration_guard` fails a
    pre-fence migration fast). The VM is never simultaneously
    Migrating and Decommissioning — the worst case is one redundant
    Failed job.
    """
    if MigrationJob.objects.filter(vm=vm).exclude(state__in=TERMINAL_MIGRATION_STATES).exists():
        return True
    if (
        DecommissionJob.objects.filter(vm=vm)
        .exclude(state__in=TERMINAL_DECOMMISSION_STATES)
        .exists()
    ):
        return True
    # A resize owns the VM's power state and placement until it ends. The
    # one caller that passes `ignore_resize` is the resize itself, starting
    # the §25 migration its new flavor needs.
    if (
        not ignore_resize
        and ResizeJob.objects.filter(vm=vm).exclude(state__in=TERMINAL_RESIZE_STATES).exists()
    ):
        return True
    # A guest upgrade owns the VM's power state and launch record from the
    # moment it leaves `pending` until it ends.
    from .models import HOLDING_GUEST_UPGRADE_STATES, GuestUpgradeJob

    return (
        not ignore_guest_upgrade
        and GuestUpgradeJob.objects.filter(vm=vm, state__in=HOLDING_GUEST_UPGRADE_STATES).exists()
    )


def _snp_generation(node_id: str) -> str:
    """Resolve a miner's SNP vCPU model (`EpycTurin` / `EpycGenoa` /
    `EpycMilan`) from its registered `snp_generation` + CHIP_ID — the SAME
    mapping the launch digest uses (`services/launch_digest.
    _vcpu_type_for_platform`; NULL generation ⇒ 8-byte=Turin, 64-byte=Genoa).
    Milan and Genoa share a CHIP_ID length but are DIFFERENT generations here.
    Raises `StartError` on an unknown miner / non-hex or unknown-length
    platform_id / a generation inconsistent with the CHIP_ID (fail closed — a
    migration whose generation cannot be determined must not start)."""
    from apps.miners.models import MinerIdentity
    from apps.orchestration.services.launch_digest import _vcpu_type_for_platform

    try:
        miner = MinerIdentity.objects.get(miner_id=node_id)
    except MinerIdentity.DoesNotExist as exc:
        raise StartError(f"miner {node_id!r} has no MinerIdentity", "miner-unknown") from exc
    try:
        return _vcpu_type_for_platform(miner.platform_id, miner.snp_generation)
    except EffectError as exc:
        raise StartError(f"miner {node_id!r}: {exc}", "platform-id-invalid") from exc


def _cross_gen_chain_ids(source_chain_node_id: str, candidates: Any) -> frozenset[str]:
    """The `chain_node_id`s in `candidates` whose SNP generation DIFFERS from
    the source's — added to `decide_placement`'s `excluded` so auto-migration
    (graceful-exit / §13 drain) never picks a cross-gen dest (which would fail
    the KBS release, same reason as the manual `start_migration` gate).
    Resolved from `snp_generation` + CHIP_ID like `_snp_generation`. Fail-OPEN
    on an unresolvable source gen (returns empty): the manual per-VM gate + the
    KBS fence remain the hard guarantees; this only trims the auto-picker. An
    unresolvable CANDIDATE is excluded (its gen != the source's)."""
    from apps.miners.models import MinerIdentity
    from apps.orchestration.services.launch_digest import _vcpu_type_for_platform

    plat = {
        m.chain_node_id: (m.platform_id, m.snp_generation)
        for m in MinerIdentity.objects.filter(chain_node_id__in={source_chain_node_id, *candidates})
    }

    def _gen(cnid: str) -> str | None:
        pid, snp_gen = plat.get(cnid, ("", None))
        if not pid:
            return None
        try:
            return _vcpu_type_for_platform(pid, snp_gen)
        except EffectError:
            return None

    src = _gen(source_chain_node_id)
    if src is None:
        return frozenset()
    return frozenset(c for c in candidates if _gen(c) != src)


def _reject_cvm_incapable_dest(dest_node_id: str) -> None:
    """Raise `StartError` if `dest_node_id` (a human `miner_id`) is
    currently classified `INCAPABLE` by the §23 observed SEV-SNP
    start-capability ledger — i.e. it has a STREAK of observed
    start failures, not merely one.

    Only `INCAPABLE` blocks. A `DEGRADED` destination (one recent,
    probably-transient failure) is allowed through: a soft signal must
    not veto an explicit operator action, and the §25 activation now
    retries, which is the right response to an intermittent fault.

    The join `miner_id → chain_node_id` mirrors `_dest_chain_node_id`. A
    destination with no registered `chain_node_id` has no ledger row and
    is therefore UNKNOWN — allowed, per the fail-safe default.
    """
    from apps.miners.models import MinerIdentity
    from apps.scheduler import cvm_capability

    chain_node_id = (
        MinerIdentity.objects.filter(miner_id=dest_node_id)
        .values_list("chain_node_id", flat=True)
        .first()
        or ""
    )
    if cvm_capability.capability_of(chain_node_id) != cvm_capability.INCAPABLE:
        return
    raise StartError(
        f"destination {dest_node_id!r} has failed "
        f"{cvm_capability.fail_threshold()} consecutive OBSERVED attempts to "
        "start a confidential guest, with no success in between — refusing "
        "to quiesce and fence the source for a destination that is not "
        "currently booting guests",
        "dest-cvm-incapable",
    )


def _reject_zombie_quarantined_dest(dest_node_id: str) -> None:
    """Refuse an EXPLICIT §25 destination that is zombie-quarantined —
    still running a VM whose §24 crypto-erase already ran
    (`apps.lifecycle.zombie`). The API and the CLI name the destination
    directly, so the scheduler's gate never sees this move."""
    from apps.lifecycle.zombie import miner_is_quarantined

    if miner_is_quarantined(dest_node_id):
        raise StartError(
            f"destination {dest_node_id!r} is zombie-quarantined: it is still "
            "running a VM whose §24 crypto-erase already ran",
            "dest-zombie-quarantined",
        )


def _reject_cordoned_dest(dest_node_id: str) -> None:
    """Refuse an EXPLICIT §25 destination the operator has cordoned
    (`MinerCapacity.cordoned_at`): a cordoned miner takes no new work, and
    the API / CLI name the destination directly, so gate (h) never sees
    this move. Uncordon first to move a VM there on purpose."""
    from apps.scheduler import service as sched

    reason = sched.miner_cordon_reason(dest_node_id)
    if reason is not None:
        raise StartError(
            f"destination {dest_node_id!r} is cordoned ({reason or 'no reason given'})",
            "dest-cordoned",
        )


def _reject_disk_full_dest(vm: Vm, dest_node_id: str) -> None:
    """Refuse an EXPLICIT §25 destination with no room for the VM's DATA
    disk, under `VALI_SCHEDULER_DISK_GATE=enforce` (record: logged and
    allowed; off: nothing). Like gate (e) above, the API / CLI name the
    destination directly, so `decide_placement`'s disk gate never sees it —
    and a dest refusing the restore for space is only discovered after the
    source was quiesced and fenced. The VM's size is read from its active
    `Placement` (vali's own record), never from the miner."""
    from apps.miners.models import MinerIdentity
    from apps.scheduler import service as sched
    from apps.scheduler.models import ACTIVE_PLACEMENT_STATES, Placement

    chain_node_id = (
        MinerIdentity.objects.filter(miner_id=dest_node_id)
        .values_list("chain_node_id", flat=True)
        .first()
        or ""
    )
    row = (
        Placement.objects.filter(vm=vm, status__in=ACTIVE_PLACEMENT_STATES)
        .values_list("resource_class", "data_disk_gb")
        .first()
    )
    if not chain_node_id or row is None:
        return  # nothing vali can size — the miner's own gate decides
    resource_class, data_disk_gb = row
    reason = sched.disk_gate_refusal(
        chain_node_id, resource_class, context="migration-dest", data_disk_gb=data_disk_gb
    )
    if reason:
        raise StartError(
            f"destination {dest_node_id!r} has no room for the vm's data disk ({reason})",
            "dest-insufficient-disk",
        )


def start_migration(
    *,
    vm: Vm,
    dest_node_id: str,
    decided_by: Any,
    cold: bool = False,
    resize_to_flavor: str = "",
) -> MigrationJob:
    """Create a §25 `MigrationJob` in `Draining`. Raises `StartError`.

    `cold=True` migrates a tenant-STOPPED VM: the job starts in
    `SourceStarting` (the VM is started on its source until its guest proves
    it booted), runs the warm §25, and `settle_cold_migrations` stops the VM
    again once it is done. Ignored for a VM that is running.

    `resize_to_flavor` is set only by a `ResizeJob` (which is itself the
    in-flight job this would otherwise refuse): the destination placement
    opens at that flavor — see `MigrationJob.resize_to_flavor`."""
    if vm.state != VmState.ACTIVE:
        raise StartError(f"vm is {vm.state!r}, not Active", "vm-not-active")
    cold = cold and vm.power_state == VmPowerState.STOPPED
    if vm.power_state != VmPowerState.RUNNING and not cold:
        # §25 needs the running source guest: its graceful quiesce produces
        # the signed stopped-ack the destination is activated on, and the
        # snapshot needs the miner's live handle for the disk path. A VM the
        # tenant stopped has neither — the job fences it into `Migrating`,
        # fails (`disk-missing` at the snapshot, or the ack timeout if a
        # handle survived), and the VM sits down and unstartable until the
        # stranded-migration sweep restores it, only to be re-enrolled on
        # the next tick of a departing miner's drain. Refuse up front.
        raise StartError(
            f"vm is {vm.power_state!r}, not running — §25 needs the running "
            "source guest to sign its stopped-ack; start the VM first",
            "vm-not-running",
        )
    if dest_node_id == vm.host:
        raise StartError("dest_node_id is the VM's current host", "same-node")
    if _has_active_job(vm, ignore_resize=bool(resize_to_flavor)):
        raise StartError("vm already has an in-flight orchestration job", "job-in-flight")
    # GOLDEN migration is now ENABLED. The earlier intake guard (#859) refused
    # it because the golden source-stopped-ack was believed undeliverable —
    # that was mis-diagnosed. The ack path is the SAME for golden + legacy and
    # is fully wired: §25 quiesce does a graceful `lifecycle.stop(graceful=true)`
    # → `virsh shutdown` → the guest's baked `hippius-eol-sign.service` signs
    # the StoppedAck from its measured cmdline + pushes it over the vsock
    # lifecycle relay → vali `StoppedAckIngest` → `poll_source_ack` verifies →
    # the fence clears → dest activates. Proven live: a golden guest delivers a
    # 220-byte SignedStoppedAck on a graceful shutdown. With the dest fixes
    # (#857) + the same-gen gate (#858) + the §24 graceful-stop fix (#861), a
    # golden migration completes end-to-end. (The AwaitingSourceAck-timeout
    # golden-no-quarantine defense-in-depth below stays, harmless.)
    # SAME-CPU-GEN gate. The dest re-mints the OrderTicket at `new_gen`
    # reusing the SOURCE's `measurement_hex` (`migration_ticket.remint_dest_
    # ticket`), so a dest of a DIFFERENT SNP generation (Turin / Genoa / Milan) boots
    # a different launch measurement → the KBS refuses the KEK → the dest
    # never unlocks (a silent stuck migration). Reject a cross-gen dest at
    # intake. NOTE: this is an availability/correctness gate, not a
    # confidentiality one — a cross-gen dest fails CLOSED at the KBS anyway;
    # this just surfaces it as a clean 4xx instead of a hung job.
    src_gen = _snp_generation(vm.host)
    dst_gen = _snp_generation(dest_node_id)
    if src_gen != dst_gen:
        raise StartError(
            f"cross-generation migration refused: source {vm.host!r} is "
            f"{src_gen}, dest {dest_node_id!r} is {dst_gen} — a cross-gen dest "
            "boots a different SNP measurement and the KBS would refuse the KEK",
            "cross-gen",
        )
    # §23 gate (e) at §25 INTAKE — refuse a destination vali has OBSERVED
    # fail to start a confidential guest.
    #
    # `decide_placement` cannot cover this call: the API + the CLI name the
    # destination EXPLICITLY, so the scheduler is never consulted and every
    # §23 admission gate is bypassed. And a migration is the worst place to
    # learn a host cannot boot a CVM, because the discovery happens at
    # `DestActivating` — i.e. AFTER the source has been quiesced, stopped
    # and KBS-fenced. Recovery from there is forward-only by design, so the
    # tenant's VM is simply down until an operator intervenes. Checking here
    # costs one indexed read and converts that outage into a clean 4xx with
    # the source still running.
    #
    # Fail-SAFE, in the same direction as everything else in this module: an
    # unknown / unmirrored destination is ALLOWED (absence of evidence must
    # not block a legitimate move, and a fresh miner has no evidence by
    # definition). Only a positive, recent, vali-OBSERVED failure blocks.
    _reject_cvm_incapable_dest(dest_node_id)
    _reject_zombie_quarantined_dest(dest_node_id)
    _reject_cordoned_dest(dest_node_id)
    _reject_disk_full_dest(vm, dest_node_id)
    # §24/§25 GAP-3 — the EOL nonce is NOT (re-)minted for a migration.
    # For a COLD migration the source guest signs its `stopped{}` ack from
    # its ALREADY-BAKED, MEASURED cmdline (`hippius.eol_nonce`), which
    # `launch.launch_on_miner` set at launch AND persisted onto
    # `Vm.eol_nonce`. The running guest has no way to learn a freshly-
    # minted nonce (no live channel delivers one — the locked COLD-
    # migration design), so minting a new value here would make
    # `_verify_ack` check the ack against a nonce the guest never saw →
    # fail closed forever → spurious quarantine (exactly the #536-flagged
    # bug). The per-migration replay guard is the GENERATION, not the
    # nonce: each migration runs the source at a distinct `source_gen`,
    # and the KBS fence forever denies an already-migrated generation, so
    # re-using the launch nonce at a NEW generation is not a replay. Fail
    # closed if the launch never stamped a nonce — a migration whose ack
    # can never verify must not start.
    if not vm.eol_nonce:
        raise StartError(
            "vm has no eol_nonce (launch did not bake hippius.eol_nonce) "
            "— cannot start a migration whose stopped-ack can never verify",
            "no-eol-nonce",
        )
    # Intake preflight — refuse a migration we already KNOW will fail at
    # DestActivating, BEFORE the quiesce fences + stops the source and
    # `kbs_activate_dest` denies the old generation (both mid-flight and
    # forward-only — a late refusal would strand the VM: source KBS-fenced,
    # dest unable to boot). The case that matters is a GOLDEN VM launched
    # BEFORE the measured cmdline was persisted: `_launch_paths` fails closed
    # for it (the dest would misclassify golden→legacy + boot a mismatched
    # measurement). Resolving the dest boot tuple here surfaces it as a clean
    # 4xx at intake (relaunch to make it migratable). Gated on `_is_golden`
    # so a legacy VM with no launch record (e.g. in tests) is unaffected —
    # legacy migration never depended on this tuple at intake.
    if _is_golden(vm):
        try:
            effects._launch_paths(vm)
        except effects.EffectError as exc:
            raise StartError(f"vm not migratable: {exc}", "not-migratable") from exc
    # Same intake-preflight logic, for the OTHER thing a destination ticket
    # needs: the §6 userdata digest. It is taken over the cloud-init
    # plaintext and binds a fresh ticket_id, so the dest mint re-derives it
    # — from the canonical copy when that is a legacy plaintext value, or
    # from vali's working copy at the same version when it is wrapped. A VM
    # with neither (staged by hand, or launched in the window between the
    # canonical wrapping and the working copy) can never have a dest ticket
    # minted, and discovering that at `DestActivating` strands it: source
    # quiesced, stopped and KBS-fenced, dest unable to boot, recovery
    # forward-only. Check it while the source is still running.
    from apps.orchestration.services import migration_ticket as _mig

    try:
        _mig.assert_userdata_rebindable(vm)
    except _mig.UserdataNotRebindable as exc:
        raise StartError(f"vm not migratable: {exc}", "not-migratable") from exc
    except (effects.EffectError, effects.EffectUnavailable) as exc:
        # The probe itself failed (Vault down / unconfigured / denied) —
        # not a verdict about this VM, but not a licence to proceed
        # either: the KBS activation fences the source BEFORE the dest
        # ticket is minted, so starting blind risks quiescing a VM whose
        # ticket then cannot be built. Refuse under a DISTINCT category so
        # the caller can tell "retry this later" from "this VM will never
        # migrate".
        raise StartError(
            f"userdata re-bindability could not be verified: {exc}",
            "vault-unavailable",
        ) from exc
    now = timezone.now()
    try:
        with transaction.atomic():
            # The cross-kind one-active-job check again, under the VM's row
            # lock the resize intake takes too: a resize (which never moves
            # `Vm.state`, so no lifecycle CAS serialises it) and a migration
            # can never both start.
            Vm.objects.select_for_update().filter(pk=vm.pk).first()
            if _has_active_job(vm, ignore_resize=bool(resize_to_flavor)):
                raise StartError("vm already has an in-flight orchestration job", "job-in-flight")
            job = MigrationJob.objects.create(
                job_id=secrets.token_hex(16),
                vm=vm,
                source_node_id=vm.host,
                dest_node_id=dest_node_id,
                source_gen=vm.generation,
                # Forward-only: the destination runs one generation up.
                new_gen=vm.generation + 1,
                state=(
                    MigrationState.SOURCE_STARTING.value if cold else MigrationState.DRAINING.value
                ),
                phase_started_at=now,
                decided_by=decided_by,
                cold=cold,
                resize_to_flavor=resize_to_flavor,
            )
            # The EOL nonce is PRESERVED (see the precondition above): the
            # launch-baked `Vm.eol_nonce` is exactly what the source guest
            # signs; we neither re-mint nor clear it here.
    except IntegrityError as exc:
        # Lost the partial-unique race — a concurrent migrate won.
        raise StartError("vm already has an in-flight migration", "job-in-flight") from exc
    log.info(
        "migration started: job=%s vm=%s %s→%s gen %d→%d",
        job.job_id,
        vm.vm_id,
        job.source_node_id,
        dest_node_id,
        job.source_gen,
        job.new_gen,
    )
    return job


# Only `Draining` runs with the `Vm` still `Active` and the source guest
# still RUNNING, so it is the sole state a migration can be cleanly cancelled
# in — the VM simply stays put and the source "drain" is released by not
# advancing. From `Quiescing` on, the fence has flipped the VM to `Migrating`
# AND the guest has been gracefully stopped (it signed its stopped-ack), so a
# cancel would orphan a powered-off VM; recovery there is forward-only (§25)
# or an operator relaunch of the intact source disk.
_CANCELLABLE_MIGRATION_STATES = frozenset(
    {
        MigrationState.DRAINING.value,
    }
)


def cancel_migration(*, job: MigrationJob, decided_by: Any) -> MigrationJob:
    """Abort an in-flight §25 migration that is still pre-`Fencing`,
    transitioning it to `Failed` with a `cancelled by …` reason (#587
    Phase 3). The `Vm` stays `Active` on the source (it was never
    transitioned pre-fence), so this is a clean no-op for the workload.

    Raises [`StartError`]:

    - `already-terminal` — the job already reached `Done`/`Failed`.
    - `past-fence` — the job has passed `Fencing`; §25 recovery is
      forward-only, so the migration can no longer be cancelled.

    Race-safe: the cancellable-state set is in the CAS `WHERE`, so a
    concurrent worker advance past the fence makes the update a no-op; we
    then re-read the row and report the real (terminal or past-fence)
    state rather than a stale decision.
    """
    name = getattr(decided_by, "name", None) or "operator"
    now = timezone.now()
    updated = MigrationJob.objects.filter(
        id=job.id,
        state__in=_CANCELLABLE_MIGRATION_STATES,
    ).update(
        state=MigrationState.FAILED.value,
        # A cancel is only legal pre-fence (`_CANCELLABLE_MIGRATION_STATES`
        # is `{Draining}`), so the VM is still `Active` and never stranded.
        # Recorded anyway so every terminal job carries the column.
        failed_from_state=MigrationState.DRAINING.value,
        version=F("version") + 1,
        phase_started_at=now,
        finished_at=now,
        reason=f"cancelled by {name}"[:256],
    )
    refreshed = MigrationJob.objects.select_related("vm", "decided_by").get(id=job.id)
    if not updated:
        if refreshed.state in TERMINAL_MIGRATION_STATES:
            raise StartError("migration already terminal", "already-terminal")
        raise StartError(
            "migration has passed the KBS fence — §25 recovery is "
            "forward-only, it can no longer be cancelled",
            "past-fence",
        )
    log.info("migration %s CANCELLED by %s", refreshed.job_id, name)
    return refreshed


def start_decommission(*, vm: Vm, decided_by: Any) -> DecommissionJob:
    """Create a §24 `DecommissionJob` in `Draining`. Raises `StartError`."""
    if vm.state != VmState.ACTIVE:
        raise StartError(f"vm is {vm.state!r}, not Active", "vm-not-active")
    if _has_active_job(vm):
        raise StartError("vm already has an in-flight orchestration job", "job-in-flight")
    now = timezone.now()
    try:
        with transaction.atomic():
            # Re-checked under the VM's row lock (see `start_migration`).
            Vm.objects.select_for_update().filter(pk=vm.pk).first()
            if _has_active_job(vm):
                raise StartError("vm already has an in-flight orchestration job", "job-in-flight")
            job = DecommissionJob.objects.create(
                job_id=secrets.token_hex(16),
                vm=vm,
                state=DecommissionState.DRAINING.value,
                phase_started_at=now,
                decided_by=decided_by,
            )
    except IntegrityError as exc:
        raise StartError("vm already has an in-flight decommission", "job-in-flight") from exc
    log.info("decommission started: job=%s vm=%s", job.job_id, vm.vm_id)
    return job


# ─── the tick driver ─────────────────────────────────────────────────


@dataclass(frozen=True)
class TickReport:
    """Outcome of one `tick_once()` — for logging + tests."""

    migration_jobs: int
    decommission_jobs: int
    # In-flight VM resizes advanced this tick (`resize.tick_resizes`).
    resize_jobs: int = 0
    reboot_recovery_relaunches: int = 0
    # Active VMs reboot-recovery stopped relaunching because their bound
    # host does not hold their disks (`sweep_relaunch_disks_missing`). Any
    # non-zero value is a tenant DOWN with its data elsewhere.
    relaunch_disks_missing: int = 0
    netbird_checks: int = 0
    # Active VMs whose libvirt domain is up but whose GUEST has gone
    # silent past the staleness bound (`sweep_guest_liveness`).
    wedged_guests: int = 0
    # Active VMs with no in-guest signal since their current boot began,
    # past the per-flavor deadline (`sweep_boot_stalls`).
    boot_stalls: int = 0
    source_reclaims: int = 0
    # vm_ids vali launched but has no `Vm` row for — outside every
    # control-plane sweep, and un-crypto-erasable (`sweep_unbound_launches`).
    unbound_launches: int = 0
    # VMs fenced in `migrating` with a TERMINAL migration job — down, and
    # outside every automatic path until this counter existed
    # (`sweep_stranded_migrations`).
    stranded_migrations: int = 0
    # §24 jobs re-opened for VMs left in `decommissioning` behind a FAILED
    # job (`sweep_stranded_decommissions`).
    stranded_decommissions: int = 0
    # `Vm` rows an abandoned launch left `active` with an empty host and a
    # LIVE per-VM KEK — phantoms (`sweep_abandoned_launches`). Should
    # settle back to 0 as each is reaped or cleared by an operator.
    abandoned_launches: int = 0
    # Public IPs whose target moved to a new NetBird address this tick
    # (migration, relaunch, first enrolment) — `network.service.reconcile`.
    public_ip_retargets: int = 0
    # Backup runs started this tick (`apps.backup.service.tick`).
    backup_runs_started: int = 0
    # VMs past their §24 crypto-erase that a miner is STILL running (a
    # fresh guest frame arrived for them), and the miners that are
    # therefore zombie-quarantined — `apps.lifecycle.zombie`. Any non-zero
    # value is a live data-death gap.
    zombie_vms: int = 0
    zombie_quarantined_miners: int = 0
    # §24 jobs whose KBS fence/tombstone is still waiting for the sweep
    # (`sweep_pending_kbs_fences`). Non-zero ⇒ the KBS may still treat a
    # decommissioned VM as live. Always 0 with `VALI_KBS_FENCE_ENABLED` off.
    kbs_fence_pending: int = 0
    # Live VMs whose placement was missing or on another miner and was
    # re-bound to the host they run on (`sweep_live_vm_placements`). Each
    # one is an admission under-count that existed until this tick; ANY
    # non-zero value means some path lost a running VM's reservation.
    placements_repaired: int = 0
    # Stale `Pending` placements promoted to `Bound` / cancelled
    # (`sweep_stale_pending_placements`) — each one a launch that crashed
    # between dispatch and bind, or a reservation for a VM elsewhere.
    pending_promoted: int = 0
    pending_cancelled: int = 0
    # `running` launch jobs whose worker died, resolved from the facts
    # (`launch_jobs.reap_orphaned_launch_jobs`).
    orphan_launches_completed: int = 0
    orphan_launches_failed: int = 0
    # KBS audit records copied out of the KBS CVM this tick, and the chain
    # breaks found in them (`kbs_audit.ingest_tick`). ANY non-zero break
    # count is a KBS audit log that does not verify — the detail line is
    # the ERROR from `kbs_audit`. Both 0 with the ingest flag off.
    kbs_audit_ingested: int = 0
    kbs_audit_breaks: int = 0
    # Tenant NetBird peers of gone VMs deleted by the janitor
    # (`netbird_janitor.sweep_orphan_tenant_peers`). Non-zero means a §24
    # revoke was missed or failed; the detail lines are its WARNINGs.
    netbird_orphan_peers_deleted: int = 0


# Well-known system principal credited with auto-enrolled graceful-exit
# migrations (mirrors the price-watch system actor).
_GRACEFUL_EXIT_ACTOR = "system:graceful-exit-migrator"

# System principal credited with placements re-bound to the host a live VM
# already runs on — by reboot-recovery and by the invariant sweep. It
# decides nothing new: it records where the VM IS.
_PLACEMENT_RECONCILER_ACTOR = "system:placement-reconciler"


def _placement_reconciler() -> Any:
    from apps.identity.models import PrincipalScope, ServiceClient

    actor, _ = ServiceClient.objects.get_or_create(
        name=_PLACEMENT_RECONCILER_ACTOR,
        defaults={
            "description": "Re-binds a live VM's placement to the host it runs on (§13/§23).",
            # Holds no token (never authenticated over HTTP); like the
            # graceful-exit actor it acts across every tenant.
            "scope": PrincipalScope.OPERATOR.value,
        },
    )
    return actor


def rebind_placement_to_host(vm: Vm, *, node_id: str, reason: str) -> Any:
    """Give a VM that holds NO active placement a `Bound` one on `node_id`
    (a chain `node_id`), the miner the caller has just seen it running on.
    A NO-OP when it holds any active placement — on that miner or another
    (`open_placement_on_node` never moves a row) — so every caller may run
    it unconditionally.

    `node_id` is re-checked against the VM row LOCKED inside the
    transaction: the caller's `vm` may be a snapshot taken before a §25
    activation moved `Vm.host`, and opening a row from that snapshot would
    put the placement back on the source. If the fresh row no longer
    resolves to `node_id` (moved, not live, or its host went dark),
    nothing is written.

    Returns the new `Placement`, or `None` when nothing was written.
    """
    from apps.scheduler.service import hosting_node_ids, open_placement_on_node

    if not node_id:
        return None
    with transaction.atomic():
        fresh = Vm.objects.select_for_update().get(pk=vm.pk)
        if hosting_node_ids([fresh]).get(fresh.pk, "") != node_id:
            log.info(
                "placement re-bind: vm=%s is no longer live on %s — skipped",
                vm.vm_id,
                node_id[:12],
            )
            return None
        return open_placement_on_node(
            fresh, node_id=node_id, decided_by=_placement_reconciler(), reason=reason
        )


def sweep_superseded_measurements() -> int:
    """Retry `allowlist_pin.evict_superseded_measurements` — a no-op (no
    install) when nothing is pending. Returns the rows evicted."""
    from apps.orchestration.services import allowlist_pin

    try:
        return allowlist_pin.evict_superseded_measurements()
    except allowlist_pin.AllowlistPinBusy:
        log.info("allowlist: eviction sweep skipped — pin lock busy, next tick")
        return 0
    except (EffectError, EffectUnavailable) as exc:
        log.error(
            "allowlist: %d superseded launch(es) still releasable — eviction failed: %s",
            len(allowlist_pin.pending_superseded_pins()),
            exc,
        )
        return 0


#: An `already-launched` record still unsettled after this long is logged
#: as an error each tick: its guest is not attesting.
_UNVERIFIED_BOOT_ALARM_S = 3600


def sweep_unverified_boots() -> int:
    """Settle every launch record an `already-launched` answer left
    unverified (`launch_record.mark_boot_unverified`) from its guest's own
    KBS-attested measurement — the boot on record, or the earlier dispatch
    that is up (recorded, and made the VM's current launch). Returns the
    records settled."""
    import math
    from datetime import datetime

    from apps.telemetry.models import VmLiveAttestation
    from apps.telemetry.vm_liveness import _skew_seconds

    from .models import LaunchJob, LaunchJobState
    from .services import launch_record

    settled = 0
    records = LaunchJob.objects.filter(
        state=LaunchJobState.SUCCEEDED.value,
        result_json__emit__has_key=launch_record.BOOT_UNVERIFIED_KEY,
    ).values_list("vm_id", flat=True)
    for vm_id in sorted(set(records)):
        record = launch_record.latest_record(vm_id)
        since_iso = launch_record.boot_unverified(record) if record is not None else ""
        if not since_iso:
            continue
        since = datetime.fromisoformat(since_iso)
        # Verified after the answer by more than the clock skew ingest
        # tolerates (`vm_liveness`): no body taken before it — by the boot
        # on record before it stopped, say — can pass.
        after = math.ceil(since.timestamp()) + _skew_seconds()
        attested = (
            VmLiveAttestation.objects.filter(vm_id=vm_id, verified_at_unix__gt=after)
            .order_by("-verified_at_unix")
            .values_list("measurement", flat=True)
            .first()
        )
        if attested is None:
            if (timezone.now() - since).total_seconds() > _UNVERIFIED_BOOT_ALARM_S:
                log.error(
                    "launch record: vm=%s answered already-launched at %s and its guest "
                    "has not attested since — no KBS recovery of it until it does; "
                    "vali_backfill_launch_measurement if it never will",
                    vm_id,
                    since_iso,
                )
            continue
        before = launch_record.recorded_measurement(vm_id)
        now = launch_record.resolve_unverified_boot(vm_id, attested)
        if now is None:
            log.error(
                "launch record: vm=%s attests %s… — neither its recorded boot nor any "
                "dispatch vali kept; left unverified (vali_backfill_launch_measurement)",
                vm_id,
                attested[:16],
            )
            continue
        settled += 1
        log.warning(
            "launch record: vm=%s settled from its attestation: %s… runs%s",
            vm_id,
            now[:16],
            "" if now == before else f" (was recording {before[:16]}…)",
        )
        if now != before:
            _placement_follows_settled_boot(vm_id)
    return settled


def _placement_follows_settled_boot(vm_id: str) -> None:
    from apps.miners.models import MinerIdentity

    from .services import launch_record

    vm = Vm.objects.filter(vm_id=vm_id).first()
    record = launch_record.latest_record(vm_id)
    if vm is None or record is None or not vm.host:
        return
    node_id = (
        MinerIdentity.objects.filter(miner_id=vm.host)
        .values_list("chain_node_id", flat=True)
        .first()
    )
    if node_id:
        _placement_follows_boot(vm, node_id=node_id, flavor=launch_record.booted_flavor(record))


def sweep_live_vm_placements() -> int:
    """Repair the placement invariant: every live VM holds exactly one
    active placement, on the host it runs on. Returns how many were
    repaired this tick.

    Admission counts ONLY active placements, so a running VM without one
    is RAM/CPU the scheduler cannot see and will sell again. Found live
    2026-09-24: three VMs on two hosts whose placements the §13 re-eval
    had drained while the hosts' heartbeats were stale during a reboot;
    reboot-recovery then relaunched them on the same hosts and nothing
    re-opened a placement. The drain now holds such a placement, and the
    relaunch re-binds — this sweep is the net under both, and under any
    future writer that forgets.

    Repairs only the MISSING case, and only on an UP host
    (`hosting_node_ids`). A placement BOUND on another miner is reported
    (the synthetic `live_vms_placed` check) but not moved: the root-only
    `/fail` → re-place → `/bind` flow binds the destination before
    `Vm.host` follows, and which host won is not something this sweep can
    prove. Skips a VM with an in-flight migration / decommission / launch:
    those own the VM's placement for their duration.

    One ERROR per repair — each is a real under-count that existed until
    now, and a path somewhere that produced it.
    """
    from apps.scheduler.service import live_vm_placement_drift

    from .models import TERMINAL_LAUNCH_STATES, LaunchJob

    repaired = 0
    for drift in live_vm_placement_drift():
        vm = drift.vm
        if _has_active_job(vm) or (
            LaunchJob.objects.filter(vm_id=vm.vm_id)
            .exclude(state__in=TERMINAL_LAUNCH_STATES)
            .exists()
        ):
            continue
        placement = rebind_placement_to_host(
            vm, node_id=drift.host_node_id, reason="reconciled:vm-live-on-host"
        )
        if placement is None:
            continue
        repaired += 1
        log.error(
            "placement invariant: vm=%s is %s on miner=%s but held NO active "
            "placement — re-bound (placement=%s, %s). Until now admission did "
            "not count this VM against the host it runs on.",
            vm.vm_id,
            vm.state,
            drift.host_node_id[:12],
            placement.id,
            placement.resource_class,
        )
    return repaired


def sweep_stale_pending_placements() -> tuple[int, int]:
    """Resolve every `Pending` placement too old to be a launch in flight
    (`scheduler.service.stale_pending_verdicts`). Returns
    `(promoted, cancelled)`.

    The gap: `launch_on_miner` stamps `Vm.host` on the accepted dispatch,
    and only then does its caller CAS the placement `Pending → Bound`. A
    vali crash between the two leaves a running VM whose placement stays
    `Pending` for ever — counted by admission, but missing from every
    consumer that selects `Bound`. Promote it when the VM runs on that
    very (up) host; cancel it when the VM is destroyed or provably runs on
    another miner; leave every uncertain case alone (see
    `stale_pending_verdicts`). A `Pending` row younger than
    `stale_pending_after_s` is never touched — that is a launch working.

    Each row is re-judged with its VM row LOCKED and written with a CAS on
    `(id, version, status=pending)`, so a launch that binds it (or a
    `/fail`) in the meantime simply wins. One ERROR per resolution: each
    is a placement a crash left wrong.
    """
    from apps.scheduler.models import (
        Placement,
        PlacementFailureSource,
        PlacementStatus,
    )
    from apps.scheduler.service import (
        PENDING_PROMOTE,
        stale_pending_verdicts,
    )

    promoted = 0
    cancelled = 0
    for candidate in stale_pending_verdicts():
        row = candidate.placement
        with transaction.atomic():
            Vm.objects.select_for_update().filter(pk=row.vm_id).first()
            fresh = Placement.objects.select_related("vm").filter(pk=row.pk).first()
            if fresh is None or fresh.status != PlacementStatus.PENDING:
                continue
            judged = stale_pending_verdicts([fresh])
            if not judged:
                continue
            verdict = judged[0]
            now = timezone.now()
            cas = Placement.objects.filter(
                id=fresh.id, version=fresh.version, status=PlacementStatus.PENDING
            )
            if verdict.verdict == PENDING_PROMOTE:
                if not cas.update(
                    status=PlacementStatus.BOUND,
                    version=fresh.version + 1,
                    bound_at=now,
                    kbs_release_ref="reconciled:stale-pending",
                ):
                    continue
                promoted += 1
                log.error(
                    "placement invariant: vm=%s runs on miner=%s but its placement=%s "
                    "was still PENDING %s after it was decided — promoted to Bound",
                    fresh.vm.vm_id,
                    fresh.miner_node_id[:12],
                    fresh.id,
                    now - fresh.decided_at,
                )
            else:
                if not cas.update(
                    status=PlacementStatus.FAILED,
                    version=fresh.version + 1,
                    failed_at=now,
                    reason=f"released:stale-pending:{verdict.why}",
                    # Not a judgement about the node: the VM is not there.
                    failure_source=PlacementFailureSource.RELEASE,
                ):
                    continue
                cancelled += 1
                log.error(
                    "placement invariant: stale PENDING placement=%s vm=%s on miner=%s "
                    "cancelled (%s) — it reserved capacity for a VM that is not there",
                    fresh.id,
                    fresh.vm.vm_id,
                    fresh.miner_node_id[:12],
                    verdict.why,
                )
    return promoted, cancelled


# On-chain statuses that mean a miner is GRACEFULLY leaving — it is still
# reachable, so its running VMs can be snapshotted + warm-migrated. A
# miner that has gone missing/dark is deliberately NOT here: there is
# nothing to snapshot, so those VMs fall to the §13 cold drain (the
# scheduler reeval marks the placement Failed → fresh re-placement).
_GRACEFUL_DEPARTURE_STATUSES = ("quarantined", "decommissioned")


def enroll_departing_miner_migrations() -> int:
    """Auto-create a warm §25 `MigrationJob` for every Active VM still
    bound to a miner that has gone Quarantined/Decommissioned on-chain.

    Closes the gap where a gracefully-departing miner's VMs were only
    cold-re-placed (§13 drain → `Failed` → fresh placement, losing the
    running state) unless an operator manually hit `MigrateStartView`.
    The orchestration loop now enrols a state-preserving migration
    automatically — off the departing miner, onto a healthy dispatchable
    destination — so a miner can request unstake, its VMs vacate warm,
    and the stake unbonds once they are gone.

    Fail-closed + idempotent:
    - a chain-read failure enrols nothing (never migrate on an RPC blip);
    - a VM not `Active`, or one that already has an in-flight
      orchestration job, is skipped (one-active-job-per-vm invariant);
    - if no healthy destination is currently dispatchable the VM is left
      for a later tick — no half-migration is ever started.

    Returns the number of migrations enrolled this call.

    Enrols nothing while `VALI_MIGRATION_AUTO_ENROL_ENABLED` is off.
    """
    if not getattr(settings, "VALI_MIGRATION_AUTO_ENROL_ENABLED", True):
        return 0
    # Local imports: the scheduler app + identity model are only needed
    # here; a module-level import would couple orchestration to scheduler
    # at load time (and risk an import cycle).
    from apps.identity.models import PrincipalScope, ServiceClient
    from apps.scheduler import chain
    from apps.scheduler import service as sched
    from apps.scheduler.models import Placement, PlacementStatus
    from apps.scheduler.placement import (
        PlacementError,
        SelectionWeights,
        decide_placement,
    )

    try:
        snapshot = chain.read_miner_status()
    except chain.ChainReadUnavailable:
        return 0

    from apps.miners.models import MinerIdentity, MinerStatus

    departing = {m.node_id for m in snapshot.miners if m.status in _GRACEFUL_DEPARTURE_STATUSES}
    # Also honour a LOCAL departure signal: a miner that has been
    # quarantined/decommissioned in vali's own `MinerIdentity` registry —
    # by an operator (`POST /v1/admin/miner/<id>/quarantine`) or by the
    # miner itself (the self-service graceful-exit endpoint) — even if its
    # on-chain status still reads Active. This is the network-uniform
    # trigger: it does NOT depend on the on-chain stake/unstake machinery
    # (which may be disabled) nor on an authority writing the chain
    # status, so a miner can signal "I am leaving, vacate my VMs" the same
    # way on testnet and mainnet.
    departing |= {
        nid
        for nid in MinerIdentity.objects.exclude(status=MinerStatus.ACTIVE)
        .exclude(chain_node_id__isnull=True)
        .values_list("chain_node_id", flat=True)
        if nid
    }
    if not departing:
        return 0

    sched.refresh_miner_capacity(snapshot)
    dispatchable = sched.dispatchable_node_ids()
    system, _ = ServiceClient.objects.get_or_create(
        name=_GRACEFUL_EXIT_ACTOR,
        defaults={
            "description": "Auto-enrolled graceful-exit VM migrations (§13/§25).",
            # P2: this synthetic principal is the `decided_by` on migrations
            # it opens across EVERY tenant on a departing miner — that is an
            # operator action by definition. It holds no token (it is never
            # authenticated over HTTP); the scope makes its reach explicit.
            "scope": PrincipalScope.OPERATOR.value,
        },
    )

    enrolled = 0
    # Gate (f) input, built ONCE per tick and only if some departing VM
    # was launched with a region: most ticks enrol nothing region-bound,
    # and the map is one query per VM otherwise.
    region_map: dict[str, str] | None = None
    bound = Placement.objects.filter(
        status=PlacementStatus.BOUND, miner_node_id__in=departing
    ).select_related("vm")
    for placement in bound:
        vm = placement.vm
        if vm.state != VmState.ACTIVE:
            continue
        if vm.power_state not in (VmPowerState.RUNNING, VmPowerState.STOPPED):
            continue  # a power op in flight — next tick
        # A STOPPED VM migrates COLD: started on its source for the warm
        # §25, stopped again at the destination (#1150) — but not again right
        # after a cold attempt failed (each one relaunches the guest).
        cold = vm.power_state == VmPowerState.STOPPED
        if (
            cold
            and MigrationJob.objects.filter(
                vm=vm,
                cold=True,
                state=MigrationState.FAILED.value,
                finished_at__gte=timezone.now() - _cold_retry_backoff(),
            ).exists()
        ):
            continue
        if _has_active_job(vm):
            continue
        # The region the VM was sold in. An auto-migration is the one path
        # where nobody is watching the destination get chosen, so it is
        # exactly where a "FR" VM would otherwise quietly end up in "DE".
        region = sched.launch_region_for_vm(vm.vm_id)
        if region and region_map is None:
            region_map = sched.region_by_node()
        # (Golden VMs are auto-migrated too now — the golden intake guard was
        # lifted once the golden guest ack was proven to deliver; §25 quiesce +
        # the same-gen gate handle them like legacy.)
        # A healthy destination != the departing source. `decide_placement`
        # already drops the quarantined source (status != Active) AND
        # applies the dispatchability gate; `excluded` makes it explicit.
        cap, load, family = sched.decision_inputs(placement.vm_family)
        try:
            dest = decide_placement(
                snapshot=snapshot,
                capacity_by_node=cap,
                load_by_node=load,
                family_load_by_node=family,
                max_epoch_lag=sched.max_epoch_lag(),
                # Exclude the departing source AND every cross-generation
                # candidate (a cross-gen dest fails the KBS release, §25).
                excluded=frozenset({placement.miner_node_id})
                | _cross_gen_chain_ids(placement.miner_node_id, dispatchable),
                dispatchable=dispatchable,
                region=region,
                region_by_node=region_map if region else None,
                weights=SelectionWeights.from_settings(),
                max_host_share=sched.max_host_share(),
                price_by_node=sched.price_by_node(snapshot),
                # RA-M3 — auto-migration must respect the same spread: the
                # owner is on the source Placement, so a graceful-exit /
                # §13 drain does not stack one owner's VMs onto one dest.
                recent_failures_by_node=sched.recent_failures_by_node(),
                max_recent_failures=sched.max_recent_failures(),
                owner_load_by_node=sched.owner_load_by_node(placement.owner),
                max_owner_placements_per_miner=(sched.max_owner_placements_per_miner()),
                # Gate (e) — an auto-migration off a departing miner must
                # never pick a destination vali has OBSERVED fail to
                # start a confidential guest: unlike a launch, that
                # failure is only discovered AFTER the source has been
                # quiesced and fenced, so it costs the tenant its VM.
                cvm_capability_by_node=sched.cvm_capability_by_node(),
                # Never move a tenant onto a miner still running a VM
                # whose §24 crypto-erase already ran.
                zombie_quarantined=sched.zombie_quarantined_node_ids(),
                cordoned=sched.cordoned_node_ids(),
                # Capacity v2 — the destination must fit THIS VM's flavor.
                # No shadow line: this runs per VM per tick.
                # A resized VM carries its own (launch) disk.
                resource_fit=sched.resource_fit(
                    placement.resource_class,
                    shadow_log=False,
                    disk_gb=sched.placement_disk_gb(
                        placement.resource_class, placement.data_disk_gb
                    ),
                ),
            )
        except PlacementError:
            continue
        # `decide_placement` returns a chain `node_id`, but `start_migration`
        # + the downstream dispatch/KBS release all key on the human
        # `miner_id` (`vm.host` / `MigrateActivateOrder.dest_node_id`). Bridge
        # chain_node_id → miner_id (mirrors the launch path's join,
        # `launch.py`), skipping if the chosen dest is not a resolvable
        # registered miner. Without this, `start_migration`'s same-gen gate
        # (and the pre-existing dispatch) would fail to resolve the dest.
        try:
            dest_miner_id = MinerIdentity.objects.get(chain_node_id=dest).miner_id
        except MinerIdentity.DoesNotExist:
            continue
        try:
            job = start_migration(vm=vm, dest_node_id=dest_miner_id, decided_by=system, cold=cold)
        except StartError:
            continue
        enrolled += 1
        log.warning(
            "§25 graceful-exit migration enrolled: vm=%s %s→%s job=%s",
            vm.vm_id,
            placement.miner_node_id,
            dest,
            job.job_id,
        )
    return enrolled


# ─── reboot-recovery — relaunch a down VM on its still-alive miner ────


def reboot_recovery_once() -> int:
    """Scan `Active` VMs and relaunch any that are DOWN on a still-ALIVE
    bound miner (e.g. after a host reboot powered the tenant CVM off).

    Returns the number of relaunches DISPATCHED this tick. A no-op unless
    `VALI_REBOOT_RECOVERY_ENABLED` (default False).

    SAFETY — this NEVER fights §25 migration. §25 owns a DEAD / departing
    miner (Quarantined/Decommissioned or dark); reboot-recovery acts ONLY
    when the miner is on-chain-Active AND heart-beating (`_reboot_recovery_
    step`'s alive-gate) yet its tenant domain is confirmed down. The two
    trigger sets are disjoint. Each VM is isolated in its own `try` so one
    failure never breaks the tick.

    UNTRUSTED-MINER SAFETY — the only miner-supplied input is the
    `domain-state` signal, and a miner can only make it say "down" (or
    withhold it → `None` → no action). A forced relaunch is a full attested
    boot: the KBS re-register is idempotent-cached for the SAME host (a
    different host trips the anti-migration fence), the SAME per-VM KEK is
    re-released, and dm-integrity + attestation + the boot-counter still
    gate the disk. A malicious miner gains only a re-attested boot of the
    same VM on itself — it cannot swap disks or strand the KEK.
    """
    if not _reboot_recovery_enabled():
        return 0
    now = timezone.now()
    cutoff = now - timedelta(seconds=_scheduler_liveness_timeout_s())
    relaunched = 0
    for vm in Vm.objects.filter(state=VmState.ACTIVE).iterator():
        try:
            if _reboot_recovery_step(vm, now=now, cutoff=cutoff):
                relaunched += 1
        except Exception:  # noqa: BLE001 — one VM must not kill the tick.
            log.exception("reboot-recovery: unhandled error for vm=%s", vm.vm_id)
    return relaunched


def _scheduler_liveness_timeout_s() -> int:
    # The SAME cutoff `scheduler.dispatchable_node_ids` uses — a miner is
    # "alive" for reboot-recovery iff it would still be a placement candidate.
    from apps.scheduler import service as scheduler_service

    return scheduler_service.miner_liveness_timeout_s()


# `last_outcome` written when a row's counters are re-scoped to a new
# host. Recorded rather than blanked: it is the audit line that says WHY
# an attempt budget went back to zero, and it clears the
# "attempts-exhausted" log-once latch so a fresh exhaustion on the new
# host is reported again.
RESCOPED_OUTCOME = "host-changed"


def _rescope_fields(new_host: str) -> dict[str, Any]:
    """The host-scoped half of a `RebootRecovery` row, reset for
    `new_host`.

    `seen_running` is ABSENT on purpose — it records that this VM's domain
    was once observed running, a fact about the VM's past that a host
    change does not falsify (see the model docstring).

    `version` is bumped so an in-flight relaunch claim is FENCED: a
    reboot-recovery tick that read the row before the move and is about to
    `_reboot_recovery_fire` loses its CAS and dispatches nothing —
    otherwise it would both resurrect the pre-move `attempts` count from
    its stale read and aim a relaunch at the host the VM just left.
    """
    return {
        "host": new_host,
        "attempts": 0,
        "next_attempt_at": None,
        "consecutive_down": 0,
        "consecutive_wedged": 0,
        "last_relaunch_at": None,
        "last_outcome": RESCOPED_OUTCOME,
        "version": F("version") + 1,
    }


def rescope_reboot_recovery_to_host(vm: Vm, *, new_host: str) -> bool:
    """Re-scope a VM's reboot-recovery bookkeeping to the host it now runs
    on. Returns True iff a row was reset.

    THE DEFECT THIS CLOSES: `RebootRecovery` is a per-VM row holding
    HOST-scoped state — the relaunch cap, the backoff window, the
    down/wedged debounces — and no migration path touched it. A VM that
    burned its relaunch budget on a flaky SOURCE arrived at a healthy
    DESTINATION already at the cap, with `last_outcome=
    "attempts-exhausted"`, and could never be reboot-recovered there. It
    runs fine until the destination reboots — at which point the recovery
    that exists for exactly that event refuses to act.

    RESET IN PLACE, not append-only — the opposite call from the §23
    `Placement` (#942) and the billing binding (#938), and for reasons
    that are visible in the code rather than stylistic:

    - it GATES nothing. `Placement` gates one authorization fallback and
      `VmBillingBinding` is a gate proper (the guest declares that
      identity from its SNP-measured cmdline). `RebootRecovery` is read by
      exactly one caller — the scan below, in this module. Nothing else in
      the codebase reads the row: not the API serializers, not the KBS
      release path, not §23/§24/§25.
    - it is not EVIDENCE. `Placement` carries `decided_by`, `chain_epoch`
      and `kbs_release_ref` — a decision that was TAKEN, which an in-place
      rewrite would leave describing a decision that never happened. Every
      field here is a live counter the scan already overwrites on nearly
      every poll (`consecutive_down` back to 0 on any healthy signal,
      `next_attempt_at` back to None). A row whose whole contract is
      "current debounce/backoff state" cannot be an audit ledger.
    - the schema says so: `vm` is the PRIMARY KEY (`OneToOneField`), so
      there is exactly one row per VM for life. Append-only would mean a
      new table for bookkeeping nobody reads twice.

    So: reset the host-scoped fields, PRESERVE `seen_running`, and record
    the reason in `last_outcome`.
    """
    from .models import RebootRecovery

    rec = RebootRecovery.objects.filter(vm_id=vm.pk).first()
    if rec is None:
        # No bookkeeping to re-scope. The scan creates the row stamped
        # with the host it first sees, so there is nothing to repair.
        return False
    if rec.host == new_host:
        # NOT a host change. This is what keeps the cap capping across
        # reboot-recovery's OWN relaunch, which re-runs `launch_on_miner`
        # on the SAME host: re-scoping there would zero `attempts` between
        # every attempt and the cap would never be reached.
        return False
    log.info(
        "reboot-recovery: re-scoping vm=%s bookkeeping %s → %s "
        "(attempts %d → 0, backoff cleared, seen_running=%s preserved)",
        vm.vm_id,
        rec.host or "<unstamped>",
        new_host,
        rec.attempts,
        rec.seen_running,
    )
    return bool(RebootRecovery.objects.filter(vm_id=rec.vm_id).update(**_rescope_fields(new_host)))


def _reboot_recovery_row(vm: Vm, node_id: str) -> Any:
    """Fetch (or create) this VM's `RebootRecovery` row, re-scoped to the
    miner it is CURRENTLY bound to.

    A LAZY backstop for [`rescope_reboot_recovery_to_host`], which the two
    writers of `Vm.host` call eagerly inside their own CAS. This makes the
    invariant a property of the DATA rather than of remembering to call
    something: a future third writer of `Vm.host` gets correct counters
    here even if it never learns this row exists.

    An UNSTAMPED row (`host == ""` — written before the stamp existed, and
    left that way by the 0012 backfill wherever the evidence was
    ambiguous) is ADOPTED without resetting: it cannot be known whether
    its counters describe this host or another, and the fail-safe
    direction for an attempt CAP under uncertainty is to keep it.
    """
    from .models import RebootRecovery

    rec, created = RebootRecovery.objects.get_or_create(vm=vm, defaults={"host": node_id})
    if created or rec.host == node_id:
        return rec
    if not rec.host:
        RebootRecovery.objects.filter(vm_id=rec.vm_id, host="").update(host=node_id)
        rec.host = node_id
        return rec
    log.warning(
        "reboot-recovery: vm=%s bookkeeping names host=%s but the VM is "
        "bound to %s — re-scoping (a writer of Vm.host did not)",
        vm.vm_id,
        rec.host,
        node_id,
    )
    RebootRecovery.objects.filter(vm_id=rec.vm_id).update(**_rescope_fields(node_id))
    rec.refresh_from_db()
    return rec


def _settle_abandoned_power_marker(vm: Vm, *, now: Any, cutoff: Any) -> None:
    """Settle a `starting`/`stopping` marker abandoned by a request that
    died (worker killed past dispatch) to what the miner actually runs:
    domain running ⇒ `running`, domain down ⇒ `stopped`.

    Left alone, the power API lets the tenant override a marker older than
    `STALE_POWER_MARKER` — and a `start` over a domain that is in fact
    running (a start that landed, or a stop that never did) relaunches on
    top of it, minting a second EOL nonce. Settling first means the
    tenant's next action starts from the truth.

    Only a STALE marker (a live one is its request's to settle), only on a
    definite reading from an ALIVE bound miner (unknown ⇒ leave it), and a
    CAS on the exact marker read, so a tenant action meanwhile wins.
    `power_state_at` = now: nothing was known about the domain before this
    reading."""
    from apps.miners.models import MinerIdentity

    from .services.power import STALE_POWER_MARKER

    if (
        vm.power_state not in (VmPowerState.STARTING, VmPowerState.STOPPING)
        or vm.power_state_at is None
        or now - vm.power_state_at < STALE_POWER_MARKER
    ):
        return
    # A fresh heartbeat is enough: settling only READS what the miner runs,
    # so a departing (quarantined, still heart-beating) miner can answer too
    # — its VMs are exactly the ones §25 now refuses while a marker stands.
    node_id = effects._bound_miner_id(vm)
    if (
        not node_id
        or not MinerIdentity.objects.filter(miner_id=node_id, last_seen_at__gte=cutoff).exists()
    ):
        return
    running = effects.poll_domain_running(vm)
    if running is None:
        return
    truth = VmPowerState.RUNNING if running else VmPowerState.STOPPED
    settled = Vm.objects.filter(
        pk=vm.pk, power_state=vm.power_state, power_state_at=vm.power_state_at
    ).update(
        power_state=truth,
        power_state_at=now,
        # One "down" reading is not a stop order: the miner may restart it.
        power_stop_ordered_at=None,
        # A proof only ever describes a stop that settled to `stopped`.
        **({} if truth == VmPowerState.STOPPED else {"power_stop_proof": None}),
    )
    if settled:
        log.warning(
            "power: vm=%s abandoned `%s` settled to %s — what its miner reports",
            vm.vm_id,
            vm.power_state,
            truth,
        )


#: `RebootRecovery.last_outcome` while a relaunch is being dispatched — the
#: power API refuses a stop until it clears (see `_reboot_recovery_fire`).
RELAUNCH_IN_FLIGHT = "relaunching"

#: The miner-agent's class for a relaunch refused because the VM's per-VM
#: disks are not on that host (`MinerAgentError::RelaunchDisksMissing`).
RELAUNCH_DISKS_MISSING_CLASS = "relaunch-disks-missing"

#: `RebootRecovery.last_outcome` once a relaunch was refused for missing
#: disks. STICKY: `_reboot_recovery_fire` never relaunches a VM carrying it
#: — the host does not hold the VM, so every retry is the same refusal (or,
#: on an agent without the guard, a blank-disk boot). Cleared only by a
#: host change (`_rescope_fields`), by observing the domain running again,
#: or by an operator (`vali_reboot_recovery_clear_disks_missing`).
DISKS_MISSING_OUTCOME = "disks-missing"


class RelaunchDisksMissing(Exception):
    """The bound miner refused a relaunch: it does not hold the VM's disks.

    Raised by `_reboot_recovery_relaunch` so its two callers — the
    reboot-recovery scan and the power API's `start` — can each stop
    instead of treating it as a retryable rejection.
    """


#: `RebootRecovery.last_outcome` for a relaunch that waited out the §22
#: pin lock behind other pins. Retried on the backoff; not an attempt.
PIN_BUSY_OUTCOME = "relaunch-pin-busy"


class RelaunchPinBusy(Exception):
    """The relaunch's allowlist pin waited out `PIN_LOCK_TIMEOUT_S` behind
    other pins (`allowlist-pin-busy`). Nothing was pinned or dispatched,
    so both callers retry it — unlike a miner's refusal it says nothing
    about the VM or its host."""


def _reboot_recovery_step(vm: Vm, *, now: Any, cutoff: Any) -> bool:
    """Evaluate ONE Active VM. Returns True iff a relaunch was dispatched.

    Order of gates (all fail-safe — any uncertainty ⇒ do nothing):
      0. the tenant wants it RUNNING (`power_state`) — a VM stopped through
         the power API is down ON PURPOSE,
      1. resolvable bound miner,
      2. miner ALIVE (on-chain-Active + fresh heartbeat) — else §25's job,
      3. no competing migration/decommission/launch job,
      4. domain-state probe: None/True ⇒ reset debounce, no action,
      5. debounce: only past N consecutive `down` polls,
      6. attempt cap + backoff gate,
      7. claim (CAS) + relaunch on the SAME miner.
    """
    from apps.miners.models import MinerIdentity, MinerStatus

    from .models import TERMINAL_LAUNCH_STATES, LaunchJob, RebootRecovery

    # (0) Power intent. A stopped VM stays `Active` (the KBS release gate —
    # it must unlock again on `start`), so the `state` filter above does not
    # exclude it; without this gate the scan saw its domain down and
    # relaunched it ~3 polls after every API stop. `stopping`/`starting`
    # are the power API's own in-flight operations: a relaunch here would
    # race `start_vm`'s, and the loser's freshly minted EOL nonce can end up
    # persisted for a guest booted by the winner (live: every later §24 ack
    # then failed `stopped-body-mismatch`). The debounce is reset so a real
    # outage after the next `start` is counted from zero.
    if vm.power_state != VmPowerState.RUNNING:
        RebootRecovery.objects.filter(vm=vm).exclude(
            consecutive_down=0, consecutive_wedged=0
        ).update(consecutive_down=0, consecutive_wedged=0)
        _settle_abandoned_power_marker(vm, now=now, cutoff=cutoff)
        return False

    node_id = effects._bound_miner_id(vm)
    if not node_id:
        return False

    # (2) Miner-ALIVE gate — disjoint from §25 (which owns dead/departing
    # miners). A miner that is quarantined/decommissioned or has gone dark is
    # NOT relaunched here; its VMs are §25 migration's responsibility.
    try:
        miner = MinerIdentity.objects.get(miner_id=node_id)
    except MinerIdentity.DoesNotExist:
        return False
    if (
        miner.status != MinerStatus.ACTIVE.value
        or miner.last_seen_at is None
        or miner.last_seen_at < cutoff
    ):
        return False

    # (3) No competing lifecycle job for this VM.
    if _has_active_job(vm):
        return False
    if LaunchJob.objects.filter(vm_id=vm.vm_id).exclude(state__in=TERMINAL_LAUNCH_STATES).exists():
        return False

    # (4) Probe the ACTUAL domain state on the miner.
    running = effects.poll_domain_running(vm)
    rec = _reboot_recovery_row(vm, node_id)
    if running is None:
        # Signal UNAVAILABLE (miner unreachable / libvirt unqueryable) ⇒
        # reset the debounce and take NO action — the fail-safe boundary.
        # `seen_running` is left untouched (absence of signal is not
        # evidence the VM is down).
        if rec.consecutive_down or rec.consecutive_wedged or rec.next_attempt_at is not None:
            RebootRecovery.objects.filter(pk=rec.pk).update(
                consecutive_down=0, consecutive_wedged=0, next_attempt_at=None
            )
        return False
    if running is True:
        # The libvirt domain is up. That is NOT the same as the guest
        # being alive — a VM wedged in its initramfs (refused KEK release,
        # corrupt overlay, unreachable KBS) keeps a running QEMU process
        # forever. Ask for positive evidence from INSIDE the guest.
        return _reboot_recovery_wedged_step(vm, rec, node_id, now=now)

    # running is False → the VM is DOWN on an alive miner.
    #
    # (4b) SEEN-RUNNING gate — only recover a VM we have PREVIOUSLY observed
    # running. A VM that has been down for every poll (a stale/zombie
    # `Active` row, or a launch that never came up) is NOT resurrected here
    # — that is an operator / §25 concern, not a reboot to recover from.
    # This makes reboot-recovery safe on a fleet that carries Active-but-
    # long-down rows: enabling it never mass-resurrects zombies.
    if not rec.seen_running:
        if rec.consecutive_down:
            RebootRecovery.objects.filter(pk=rec.pk).update(consecutive_down=0)
        return False

    down = rec.consecutive_down + 1
    RebootRecovery.objects.filter(pk=rec.pk).update(consecutive_down=down)

    # (5) Debounce — wait for the down signal to persist.
    if down < _reboot_recovery_debounce_polls():
        return False

    # (6) + (7) attempt cap, backoff, CAS, relaunch.
    return _reboot_recovery_fire(vm, rec, node_id, now=now, reason="DOWN", polls=down)


def _reboot_recovery_wedged_step(vm: Vm, rec: Any, node_id: str, *, now: Any) -> bool:
    """The `running is True` branch — the domain exists, so ask whether
    anything INSIDE it still answers. Returns True iff a relaunch was
    dispatched.

    This is the hole the whole change exists to close: `poll_domain_running`
    reports a QEMU process, not a guest. A VM wedged in its initramfs
    (proved live on a production host 2026-08-12: allowlist eviction → KEK release
    403 → LUKS overlay never opened) keeps its libvirt domain `running`
    indefinitely, so the old code took this branch, reset the debounce, and
    reported healthy forever.

    Fail-SAFE ordering — every uncertainty does NOTHING:

      * `alive` or `unknown` ⇒ healthy-as-far-as-we-can-tell. `unknown`
        (never emitted an in-guest signal — no telemetry agent baked into
        the image, or still on its first boot) is explicitly NOT an
        automated-action trigger: `tenant-ubuntu-1` is live proof that
        a perfectly healthy tenant can be missing a signal class.
      * `wedged` and the action flag OFF ⇒ observability only. The
        per-tick `sweep_guest_liveness` warning and the `guest_liveness`
        API field already surface it; nothing is relaunched.
      * `wedged` fleet-wide on this miner ⇒ do nothing (see
        `_guest_relay_suspect`): that pattern is a broken guest→host relay,
        not N independently hung guests.
      * otherwise the SAME debounce / attempt cap / backoff / CAS as the
        domain-down path, on its OWN counter.

    `seen_running` is set here exactly as before: the domain IS running,
    which is what that flag records.
    """
    from .models import RebootRecovery

    verdict = vm.guest_liveness(now=now)
    if verdict.state != guest_liveness.WEDGED:
        # Healthy ⇒ record that we HAVE observed this VM running (arms
        # recovery for a later reboot) and reset the debounces/backoff.
        #
        # `attempts` is the budget of ONE incident (one host-down episode).
        # It used to survive the recovery it paid for, so a VM that needed
        # 4 attempts after one reboot met the next reboot with 1 left
        # (live: two VMs on one host at 4/5, carried over from weeks before).
        # Once the relaunched VM is proven healthy the incident is over
        # and the budget resets; inside an incident — a VM that keeps
        # going down again — it still accumulates to the cap.
        incident_over = _reboot_recovery_incident_over(rec, now=now)
        if (
            not rec.seen_running
            or rec.consecutive_down
            or rec.consecutive_wedged
            or rec.next_attempt_at is not None
            or rec.last_outcome == DISKS_MISSING_OUTCOME
            or incident_over
        ):
            fields: dict[str, Any] = {
                "seen_running": True,
                "consecutive_down": 0,
                "consecutive_wedged": 0,
                "next_attempt_at": None,
            }
            if incident_over:
                log.info(
                    "reboot-recovery: vm=%s healthy after its relaunch — incident over, "
                    "attempts %d → 0",
                    vm.vm_id,
                    rec.attempts,
                )
                fields["attempts"] = 0
                if rec.last_outcome == "attempts-exhausted":
                    fields["last_outcome"] = ""
            if rec.last_outcome == DISKS_MISSING_OUTCOME:
                # Someone brought it back on this host (its disks are here
                # after all) — recovery may act on it again.
                fields["last_outcome"] = ""
            rows = RebootRecovery.objects.filter(pk=rec.pk)
            if incident_over:
                # A claim or a host re-scope since this tick read the row
                # bumps `version`: never refund that attempt, never
                # overwrite its outcome.
                rows = rows.filter(version=rec.version)
            rows.update(**fields)
        return False

    # WEDGED — the domain is up but the guest inside it has gone silent.
    # The domain-down debounce is meaningless here (the domain is UP), so
    # clear it; `seen_running` is armed because we just observed the
    # domain running.
    if not rec.seen_running or rec.consecutive_down:
        RebootRecovery.objects.filter(pk=rec.pk).update(seen_running=True, consecutive_down=0)
        rec.seen_running = True
        rec.consecutive_down = 0

    if not _reboot_recovery_on_wedged_guest():
        # Default posture: OBSERVE, never act. Root inside a guest can
        # stop its own telemetry agent, which reads exactly like a wedge —
        # relaunching on that would disrupt a tenant who is fine.
        if rec.consecutive_wedged:
            RebootRecovery.objects.filter(pk=rec.pk).update(consecutive_wedged=0)
        return False

    from apps.lifecycle import guardian_wait

    if guardian_wait.holds_back_recovery(vm, now=now):
        # Customer-held keys: the guest is not hung, it is waiting in its
        # initramfs on the customer's key guardian (design §6) — before any
        # KBS release, with no KBS state moving. A relaunch would only boot
        # it into the same wait (and cost an attempt); the customer
        # unblocks it by bringing the guardian back. Capped at
        # `VALI_GUARDIAN_WAIT_MAX_PAUSE_S` from the wait's start, like the
        # restore timer: a forged wait cannot switch recovery off for good.
        if rec.consecutive_wedged:
            RebootRecovery.objects.filter(pk=rec.pk).update(consecutive_wedged=0)
        log.info(
            "reboot-recovery: vm=%s reads WEDGED but is waiting on its key guardian "
            "(%s) — NOT relaunching",
            vm.vm_id,
            vm.guardian_wait_reason,
        )
        return False

    if _guest_relay_suspect(node_id, now=now):
        if rec.consecutive_wedged:
            RebootRecovery.objects.filter(pk=rec.pk).update(consecutive_wedged=0)
        log.warning(
            "reboot-recovery: vm=%s reads WEDGED but EVERY Active VM on "
            "miner=%s does too — treating as a guest→host telemetry relay "
            "fault, NOT relaunching",
            vm.vm_id,
            node_id,
        )
        return False

    wedged = rec.consecutive_wedged + 1
    RebootRecovery.objects.filter(pk=rec.pk).update(consecutive_wedged=wedged)
    if wedged < _reboot_recovery_debounce_polls():
        return False

    return _reboot_recovery_fire(
        vm, rec, node_id, now=now, reason="WEDGED (guest silent)", polls=wedged
    )


def _guest_relay_suspect(node_id: str, *, now: Any) -> bool:
    """True when EVERY Active VM bound to `node_id` reads `wedged` AND
    there is more than one of them.

    The dominant false-positive mode for the wedged verdict is not a hung
    guest at all: a served receipt travels guest → vsock → miner-agent →
    Edge → vali, so a miner-agent whose vsock relay is broken silences
    EVERY guest on that host at once while its own heartbeat (which does
    not ride vsock) keeps the miner "alive". N guests hanging in the same
    poll is not a thing; a broken relay is. Refuse to act on that shape.

    Requires > 1 VM: with a single VM on the host the two hypotheses are
    indistinguishable, and the wedged verdict is then the more likely one.
    """
    cohort = [
        vm
        for vm in Vm.objects.filter(
            state=VmState.ACTIVE, power_state=VmPowerState.RUNNING
        ).iterator()
        if effects._bound_miner_id(vm) == node_id
    ]
    if len(cohort) < 2:
        return False
    return all(vm.guest_liveness(now=now).is_wedged for vm in cohort)


def _reboot_recovery_fire(
    vm: Vm, rec: Any, node_id: str, *, now: Any, reason: str, polls: int
) -> bool:
    """Gates (6) + (7) shared by BOTH triggers (domain down / guest
    wedged): attempt cap → backoff → CAS claim → relaunch.

    Kept in one place on purpose — the cap and the backoff are what bound
    the blast radius of a false positive, and a second trigger that
    re-implemented them could drift out of that bound.
    """
    from .models import RebootRecovery

    # (5b) The host does not hold this VM's disks — a relaunch here can
    # only be refused again (or, on an agent without the guard, boot on
    # BLANK disks). Stop; the refusal already logged and the per-tick
    # `sweep_relaunch_disks_missing` keeps surfacing it.
    if rec.last_outcome == DISKS_MISSING_OUTCOME:
        return False

    # (6) Attempt cap + backoff.
    if rec.attempts >= _reboot_recovery_max_attempts():
        if rec.last_outcome != "attempts-exhausted":
            RebootRecovery.objects.filter(pk=rec.pk).update(last_outcome="attempts-exhausted")
            log.error(
                "reboot-recovery: vm=%s %s on alive miner=%s but exhausted "
                "%d relaunch attempts — giving up (manual intervention needed)",
                vm.vm_id,
                reason,
                node_id,
                rec.attempts,
            )
        return False
    if rec.next_attempt_at is not None and now < rec.next_attempt_at:
        return False

    # (7) Claim — ONE transaction holding the Vm row lock that the power
    # API's `_claim` also takes first. Inside it: re-read the power intent
    # (a stop/start issued since the scan owns the VM now — checked before
    # spending an attempt), then CAS the attempt AND mark the relaunch
    # `relaunching`. The power API refuses a stop while that mark stands,
    # so a stop can never land between "we decided to relaunch" and "the
    # miner has the domain" — where it would find nothing to stop, record
    # `stopped`, and the relaunch would boot the guest anyway.
    # Bump attempts + arm the next backoff window BEFORE dispatch, so an
    # overlapping tick that lost the CAS does nothing.
    attempt_no = rec.attempts + 1
    backoff_s = min(
        _reboot_recovery_backoff_base_s() * (2 ** (attempt_no - 1)),
        _reboot_recovery_backoff_base_s() * 32,
    )
    with transaction.atomic():
        row = (
            Vm.objects.select_for_update()
            .filter(pk=vm.pk)
            .values_list("power_state", "power_state_at", "host", "generation")
            .first()
        )
        power = row[0] if row else None
        if row is not None and (row[1], row[2], row[3]) != (
            vm.power_state_at,
            vm.host,
            vm.generation,
        ):
            # Something moved the VM since the scan read it — a power op, a
            # job that started AND finished meanwhile, a §25 hop: the
            # scan's verdict is about a VM that no longer is.
            log.info(
                "reboot-recovery: vm=%s changed since the scan — not relaunching",
                vm.vm_id,
            )
            return False
        if power != VmPowerState.RUNNING:
            log.info(
                "reboot-recovery: vm=%s power state changed since the scan — "
                "not relaunching (the power API owns it)",
                vm.vm_id,
            )
            return False
        # Re-checked under the row lock every other operation decides
        # under: a job (a guest upgrade above all) that took the VM since
        # the scan owns its relaunch.
        from .models import TERMINAL_LAUNCH_STATES, LaunchJob

        if (
            _has_active_job(vm)
            or LaunchJob.objects.filter(vm_id=vm.vm_id)
            .exclude(state__in=TERMINAL_LAUNCH_STATES)
            .exists()
        ):
            log.info(
                "reboot-recovery: vm=%s was taken by another operation since the scan — "
                "not relaunching",
                vm.vm_id,
            )
            return False
        # Stamped with the CLAIM time, not the tick's `now`: after a host
        # reboot one tick relaunches VM after VM, and a tick-start stamp
        # would make the later in-flight marks look abandoned to the power
        # API before their dispatch even began.
        claimed_at = timezone.now()
        claimed = RebootRecovery.objects.filter(pk=rec.pk, version=rec.version).update(
            version=rec.version + 1,
            attempts=attempt_no,
            last_relaunch_at=claimed_at,
            next_attempt_at=claimed_at + timedelta(seconds=backoff_s),
            last_outcome=RELAUNCH_IN_FLIGHT,
        )
    if not claimed:
        return False  # lost the claim to a concurrent tick

    log.warning(
        "reboot-recovery: vm=%s %s on alive miner=%s (%d consecutive polls) "
        "— relaunching (attempt %d) reusing the existing encrypted overlay",
        vm.vm_id,
        reason,
        node_id,
        polls,
        attempt_no,
    )
    try:
        ok = _reboot_recovery_relaunch(vm, node_id)
    except RelaunchPinBusy:
        # vali's own pin queue, not a failed relaunch: hand the attempt
        # back (the backoff it armed still spaces the retry).
        RebootRecovery.objects.filter(pk=rec.pk, version=rec.version + 1).update(
            attempts=rec.attempts, last_outcome=PIN_BUSY_OUTCOME
        )
        return False
    except RelaunchDisksMissing:
        # CAS on the version our claim wrote: a §25 activation that re-scoped
        # the row mid-relaunch bumped it, and the refusal says nothing about
        # the VM's new host (nor about a new stint back on this one).
        _latch_disks_missing(
            vm, node_id, RebootRecovery.objects.filter(pk=rec.pk, version=rec.version + 1)
        )
        return False
    except Exception:
        # Never leave the in-flight mark behind: it refuses the tenant's stop.
        RebootRecovery.objects.filter(pk=rec.pk).update(last_outcome="relaunch-failed")
        raise
    # On a dispatched relaunch, reset the debounce so the next healthy poll
    # is the confirmation; on failure KEEP this trigger's count (already
    # persisted by the caller) so the backoff — not a re-armed debounce —
    # gates the retry. Only the firing trigger's counter is touched; the
    # other is already 0 (the two conditions are mutually exclusive).
    fields: dict[str, Any] = {"last_outcome": "relaunched" if ok else "relaunch-failed"}
    if ok:
        fields["consecutive_down"] = 0
        fields["consecutive_wedged"] = 0
    RebootRecovery.objects.filter(pk=rec.pk).update(**fields)
    return ok


def _latch_disks_missing(vm: Vm, node_id: str, rows: Any) -> bool:
    """Set the sticky `disks-missing` outcome on `rows` — already narrowed
    by the caller's version CAS — and log the refusal. Returns True iff the
    latch was written.

    Shared by the reboot-recovery scan and the power API's `start`, so a
    refused start is surfaced by the same per-tick sweep.
    """
    latched = bool(
        rows.update(
            last_outcome=DISKS_MISSING_OUTCOME,
            consecutive_down=0,
            consecutive_wedged=0,
            next_attempt_at=None,
        )
    )
    if not latched:
        log.warning(
            "reboot-recovery: vm=%s relaunch refused by miner=%s for missing disks, "
            "but its bookkeeping moved to another host meanwhile — NOT latching",
            vm.vm_id,
            node_id,
        )
        return False
    _log_disks_missing(vm, node_id)
    return True


def mark_power_start_disks_missing(vm: Vm, node_id: str) -> bool:
    """The power API's `start` was refused for missing disks on `node_id`:
    latch it exactly as the scan would, so the sweep surfaces it too."""
    from .models import RebootRecovery

    # Re-scoped to `node_id` first (the lazy backstop the scan uses), then
    # CAS'd on the version read here, like the scan's latch.
    rec = _reboot_recovery_row(vm, node_id)
    rec.refresh_from_db(fields=["version"])
    return _latch_disks_missing(
        vm, node_id, RebootRecovery.objects.filter(pk=rec.pk, version=rec.version)
    )


def _log_disks_missing(vm: Vm, node_id: str) -> None:
    """The ERROR for a relaunch refused for missing disks, naming where the
    VM's data most plausibly is.

    The shape this exists for (seen 2026-09-25): a §25 migration
    reported `Done` onto a destination that never restored anything, so
    reboot-recovery then relaunched the VM on a host that had never held
    it. The only copy is on the migration SOURCE — kept there only because
    the source-reclaim liveness gate refuses to destroy it until the
    destination proves the guest alive, which it never will.
    """
    job = (
        MigrationJob.objects.filter(vm=vm, state=MigrationState.DONE.value, dest_node_id=node_id)
        .order_by("-finished_at")
        .first()
    )
    hint = (
        f"a §25 migration ({job.job_id}) reported Done onto this host from "
        f"source={job.source_node_id} (source_reclaim_state="
        f"{job.source_reclaim_state}) — the data is most likely still on the "
        "source; do NOT let it be reclaimed"
        if job is not None
        else "no §25 migration landed it here — check where its disks are"
    )
    log.error(
        "reboot-recovery: vm=%s REFUSED by miner=%s — the host does NOT hold "
        "the VM's disks (%s). Not relaunching again: this needs an operator "
        "(vali_migration_recover / a §25 re-drive from the host that holds "
        "the data); once fixed, re-arm with "
        "`manage.py vali_reboot_recovery_clear_disks_missing --vm-id %s --commit`",
        vm.vm_id,
        node_id,
        hint,
        vm.vm_id,
    )


def sweep_relaunch_disks_missing() -> int:
    """Count — and LOG — the `Active` VMs reboot-recovery has stopped
    relaunching because their bound host does not hold their disks.

    Pure observability, runs every tick: the refusal itself logs once, and
    after that the VM is outside every automatic path (the sticky
    `disks-missing` outcome keeps reboot-recovery off it). ONE aggregate
    ERROR per tick while any remain, because each one is a tenant that is
    down with its data somewhere other than where vali thinks it runs.
    """
    from .models import RebootRecovery

    stuck = sorted(
        RebootRecovery.objects.filter(
            last_outcome=DISKS_MISSING_OUTCOME, vm__state=VmState.ACTIVE
        ).values_list("vm__vm_id", flat=True)
    )
    if stuck:
        shown = stuck[:20]
        log.error(
            "reboot-recovery: %d Active VM(s) DOWN with their disks missing "
            "on the bound host — relaunch refused, operator action needed: %s%s",
            len(stuck),
            ", ".join(shown),
            "" if len(shown) == len(stuck) else f" (+{len(stuck) - len(shown)} more)",
        )
    return len(stuck)


def sweep_guest_liveness() -> int:
    """Count — and LOG — the `Active` VMs whose guest has gone silent.

    Pure observability: reads only `Vm.guest_signal_at`, dispatches
    nothing, and runs on EVERY tick regardless of any feature flag. This
    is what turns the silent green into a page: before it, a VM wedged in
    its initramfs was indistinguishable from a healthy one anywhere an
    operator looked (`state=active`, `boot_phase=running`, libvirt domain
    `running`).

    ONE aggregate WARNING per tick, not one per VM: the tick runs every
    10 s, so per-VM lines would drown the log for exactly the condition
    that needs to stand out. Returns the wedged count (surfaced on
    `TickReport`).

    `unknown` VMs are NOT counted — never emitted an in-guest signal is
    not the same as stopped emitting one.
    """
    now = timezone.now()
    wedged = [
        vm.vm_id
        for vm in Vm.objects.filter(state=VmState.ACTIVE, power_state=VmPowerState.RUNNING)
        .only("vm_id", "guest_signal_at", "guest_signal_kind")
        .iterator()
        if vm.guest_liveness(now=now).is_wedged
    ]
    if wedged:
        shown = sorted(wedged)[:20]
        log.warning(
            "guest-liveness: %d Active VM(s) WEDGED — libvirt domain up but "
            "NO in-guest signal within %ds (a guest hung in its initramfs "
            "looks healthy to every other probe): %s%s",
            len(wedged),
            guest_liveness.staleness_bound_s(),
            ", ".join(shown),
            "" if len(shown) == len(wedged) else f" (+{len(wedged) - len(shown)} more)",
        )
    return len(wedged)


# In-process memo for the boot-stall ERROR: `(ids, logged_at)`. A stall
# persists until an operator acts and the tick runs every ~10 s, so the
# line is re-emitted only when the SET of stalled vm_ids changes or
# `VALI_BOOT_STALL_WARN_INTERVAL_S` lapses. The count is reported every tick.
_boot_stall_warn_memo: tuple[frozenset[str], float] = (frozenset(), 0.0)


def _boot_stall_warn_interval_s() -> float:
    return float(getattr(settings, "VALI_BOOT_STALL_WARN_INTERVAL_S", 3600.0))


def sweep_boot_stalls() -> int:
    """Count and LOG the `Active` VMs whose current boot never came up.

    A guest that never received its ticket never unlocks, and on its first
    boot `sweep_guest_liveness` reads it `unknown` and says nothing; on a
    relaunch it reads the PREVIOUS boot's signal. This catches both: no
    in-guest signal since `Vm.boot_started_at` for longer than the
    per-flavor deadline (`apps.lifecycle.boot_stall`).

    Observability only: dispatches nothing, and does not feed the
    reboot-recovery WEDGED trigger. One aggregate ERROR, re-emitted only
    when the stalled set changes (see `_boot_stall_warn_memo`). Returns the
    stalled count every tick (surfaced on `TickReport`).
    """
    global _boot_stall_warn_memo

    now = timezone.now()
    stalled: list[tuple[str, str, int, int]] = []
    candidates = list(
        Vm.objects.filter(state=VmState.ACTIVE, power_state=VmPowerState.RUNNING)
        .exclude(host="")
        .annotate(stall_clock=Coalesce("boot_started_at", "created_at"))
        .filter(Q(guest_signal_at__isnull=True) | Q(guest_signal_at__lt=F("stall_clock")))
        .only(
            "vm_id",
            "host",
            "state",
            "power_state",
            "boot_started_at",
            "created_at",
            "guest_signal_at",
        )
    )
    disks = boot_stall.disk_gb_by_vm_id(vm.vm_id for vm in candidates)
    for vm in candidates:
        verdict = vm.boot_stall(now=now, disk_gb_by_vm_id=disks)
        if verdict.stalled:
            stalled.append((vm.vm_id, vm.host, verdict.elapsed_s or 0, verdict.deadline_s))
    ids = frozenset(row[0] for row in stalled)
    last_ids, last_at = _boot_stall_warn_memo
    mono = time.monotonic()
    if not ids:
        _boot_stall_warn_memo = (frozenset(), mono)
    elif ids != last_ids or (mono - last_at) >= _boot_stall_warn_interval_s():
        _boot_stall_warn_memo = (ids, mono)
        stalled.sort()
        shown = stalled[:20]
        log.error(
            "boot-stall: %d Active VM(s) STALLED — domain up but NO in-guest "
            "signal since the current boot began, past the per-flavor "
            "deadline (the guest never came up — e.g. its ticket was never "
            "delivered): %s%s",
            len(stalled),
            ", ".join(
                f"{vm_id} host={host} for={age}s deadline={deadline}s"
                for vm_id, host, age, deadline in shown
            ),
            "" if len(shown) == len(stalled) else f" (+{len(stalled) - len(shown)} more)",
        )
    return len(stalled)


# ─── unbound-launch detection (P9/#18) ───────────────────────────────

# In-process memo for the unbound-launch warning: `(ids, warned_at)`.
# The condition is PERMANENT until an operator acts, and the tick runs
# every ~10 s, so an unthrottled WARNING would emit thousands of
# identical lines a day and bury the one that changed. Re-warn when the
# SET changes (a new orphan appeared, or one was cleared) or when the
# interval lapses.
_unbound_warn_memo: tuple[frozenset[str], float] = (frozenset(), 0.0)


def _unbound_warn_interval_s() -> float:
    from django.conf import settings

    return float(getattr(settings, "VALI_UNBOUND_LAUNCH_WARN_INTERVAL_S", 3600))


def sweep_unbound_launches() -> int:
    """Count — and LOG — the vm_ids vali LAUNCHED but has no `Vm` row for.

    DETECTION ONLY. This sweep reads, counts and warns. It creates no
    `Vm` row, adopts nothing, and dispatches nothing. That asymmetry is
    deliberate: a `Vm` row is what makes a VM ELIGIBLE FOR §24
    CRYPTO-ERASE, so auto-adopting a vm_id vali cannot fully account for
    would hand a destructive capability to a heuristic. Surfacing is the
    half that is safe unconditionally; adopting is not, and is not done
    here.

    The evidence is vali's OWN ledger — no miner input, no new protocol,
    nothing an untrusted miner can inject:

    - `scheduler.VmBillingBinding` and `telemetry.TelemetrySource`
      (`tenant_vm`) are written by `launch._persist_billing_binding` /
      `_persist_telemetry_source`, both inside `launch_on_miner`, and
      NEITHER needs a `Vm` row to land. So their union is "every vm_id
      vali ever staged a launch identity for".
    - Subtracting the `Vm` table leaves exactly the launches the control
      plane cannot see. Every sweep that matters — `sweep_guest_liveness`,
      `reboot_recovery_once`, `verify_netbird_enrolments`,
      `reclaim_migrated_sources` — iterates `Vm`, and §24/§25 both resolve
      through a non-null FK to it. A vm_id in this set is outside all of
      them, and its Vault-Transit KEK can never be destroyed by the
      normal path.

    `launch_on_miner` now creates the row for every caller, so this count
    should be a FLAT HISTORICAL NUMBER: it can only grow if something
    reintroduces the hole (or an operator hard-deletes a `Vm` row out
    from under a live VM, which this catches too).
    """
    global _unbound_warn_memo

    from apps.lifecycle.models import Vm
    from apps.scheduler.models import VmBillingBinding
    from apps.telemetry.models import SourceType, TelemetrySource

    launched = set(VmBillingBinding.objects.values_list("vm_id", flat=True))
    launched |= set(
        TelemetrySource.objects.filter(source=SourceType.TENANT_VM.value).values_list(
            "source_id", flat=True
        )
    )
    if not launched:
        return 0
    # Bounded by `launched`, never a full-table scan of `Vm`.
    known = set(Vm.objects.filter(vm_id__in=launched).values_list("vm_id", flat=True))
    unbound = launched - known
    if not unbound:
        _unbound_warn_memo = (frozenset(), time.monotonic())
        return 0

    ids = frozenset(unbound)
    last_ids, last_at = _unbound_warn_memo
    now = time.monotonic()
    if ids != last_ids or (now - last_at) >= _unbound_warn_interval_s():
        _unbound_warn_memo = (ids, now)
        shown = sorted(ids)[:20]
        log.warning(
            "unbound-launch: %d vm_id(s) have a vali-provisioned launch "
            "identity but NO Vm row — invisible to §24 decommission (their "
            "Vault-Transit KEK is never destroyed and their overlay is "
            "never unlinked), to the guest-liveness sweep, to "
            "reboot-recovery and to §25. NOT auto-adopted: adoption makes "
            "a VM crypto-erasable, which is not a heuristic's call. "
            "Operator action required per vm_id: %s%s",
            len(ids),
            ", ".join(shown),
            "" if len(shown) == len(ids) else f" (+{len(ids) - len(shown)} more)",
        )
    return len(ids)


# ─── abandoned-launch reap (the phantom leak) ────────────────────────

# Well-known system principal credited with the automatic reap. Mirrors
# `_GRACEFUL_EXIT_ACTOR`: it owns `DecommissionJob.decided_by` so the §24
# audit trail says truthfully WHO tore the VM down, and it holds no
# credential (it is never authenticated over HTTP).
_ABANDONED_REAP_ACTOR = "system:abandoned-launch-reaper"

# In-process memo for the abandoned-launch warning — same throttle, same
# reason, as `_unbound_warn_memo`.
_abandoned_warn_memo: tuple[frozenset[str], float] = (frozenset(), 0.0)


def _abandoned_grace_s() -> float:
    """How long an abandoned launch must sit before it may be reaped."""
    return float(getattr(settings, "VALI_ABANDONED_LAUNCH_GRACE_S", 900.0))


def _abandoned_reap_enabled() -> bool:
    """Kill switch for the ACTION half. Detection is unconditional."""
    return bool(getattr(settings, "VALI_ABANDONED_LAUNCH_REAP_ENABLED", True))


def _abandoned_warn_interval_s() -> float:
    return float(getattr(settings, "VALI_ABANDONED_LAUNCH_WARN_INTERVAL_S", 3600.0))


def _abandoned_probe_target(vm: Vm) -> str:
    """The one miner that could conceivably be running a domain for this
    abandoned VM — `MinerIdentity` primary key, or `""`.

    `effects.destroy_target_miner_id` first (`vm.host`, else the latest
    `LaunchJob` naming a miner — the SAME resolver §24's destroy uses, so
    the host we ask about liveness is the host we would send the destroy
    to). Then the VM's latest `Placement`, bridged chain `node_id` →
    `MinerIdentity`: a forced/CLI launch writes a `Placement` but no
    `LaunchJob`, and its phantom would otherwise have no probe target at
    all.

    Every source is an authoritative vali placement record; nothing here
    is request-, tenant- or miner-supplied.
    """
    node_id = effects.destroy_target_miner_id(vm)
    if node_id:
        return node_id
    from apps.miners.models import MinerIdentity
    from apps.scheduler.models import Placement

    chain_node_id = (
        Placement.objects.filter(vm=vm)
        .exclude(miner_node_id="")
        .order_by("-decided_at")
        .values_list("miner_node_id", flat=True)
        .first()
    )
    if not chain_node_id:
        return ""
    miner_id = (
        MinerIdentity.objects.filter(chain_node_id=chain_node_id)
        .values_list("miner_id", flat=True)
        .first()
    )
    return str(miner_id) if miner_id else ""


def no_miner_was_ever_chosen(vm: Vm) -> bool:
    """True iff NO vali record has EVER named a miner for this VM — i.e.
    the launch was refused at PLACEMENT and no order was addressed
    anywhere.

    This is the difference between the two ways
    [`_abandoned_probe_target`] returns `""`, and they are opposite
    facts:

      * a miner WAS chosen but cannot be resolved right now (a
        `Placement` whose chain `node_id` has no `MinerIdentity` mirror)
        — an unanswerable question, which must stay a veto;
      * no miner was ever chosen at all — an ANSWER. There is no host
        that could be running a guest for this VM, because no host was
        ever told about it.

    §24 already acts on exactly this fact one step later: its
    `CryptoErasing` handler skips the destroy order with
    `destroy-skipped:no-miner-ever-recorded` when
    `effects.destroy_target_miner_id` is empty, precisely because "there
    is genuinely nowhere to send it". This is the same reading, applied
    to the liveness probe instead of the destroy.

    Every source is an authoritative vali placement record (`Vm.host`,
    `LaunchJob.miner_id`, `Placement.miner_node_id`) — never request-,
    tenant- or miner-supplied data. Conservative on purpose: ANY record
    naming a miner, in ANY state, makes this `False`.
    """
    from apps.orchestration.models import LaunchJob
    from apps.scheduler.models import Placement

    if vm.host:
        return False
    if LaunchJob.objects.filter(vm_id=vm.vm_id).exclude(miner_id="").exists():
        return False
    return not Placement.objects.filter(vm=vm).exclude(miner_node_id="").exists()


def cmdline_was_baked(vm: Vm) -> bool:
    """Whether a MEASURED cmdline was ever built for this VM.

    `Vm.eol_nonce` is the marker, and it is a sound one because of WHERE
    it is written: `launch.launch_on_miner` step **4b** bakes
    `hippius.eol_nonce=` into the cmdline and persists the same bytes
    onto the row in the same breath (`_persist_eol_nonce`) — before the
    preflight (step 5), before the KBS `register-vm` (step 8) and before
    the dispatch (step 9). So an empty `eol_nonce` says the launch never
    reached step 4b, hence never registered, never dispatched, and no
    guest anywhere was ever handed a cmdline for this vm_id.

    That is STRICTLY STRONGER than `launch_abandoned_registered=False`
    (which only rules out the register) and stronger than #968's
    never-ran evidence (which rules out a guest that was dispatched to a
    miner). It is not, on its own, licence to act: `_persist_eol_nonce`
    skips a malformed operator-supplied nonce token with a warning while
    the launch proceeds, so this is always ANDed with [`never_ran_veto`],
    which would refuse such a VM on `host-bound` / `launch-succeeded` /
    the live domain probe.
    """
    return bool(vm.eol_nonce)


def never_ran_veto(vm: Vm) -> str | None:
    """Why vali CANNOT prove that **no guest was ever created** for `vm` —
    or `None` when every piece of evidence says one never was.

    This is the single definition of "this VM never ran", shared by the
    two places that need it: the abandoned-launch reap
    (`_abandoned_reap_veto`) and §24's EOL-ack wait
    (`_h_dec_awaiting_eol_ack`). One definition, so the two can never
    drift into disagreeing about the same VM.

    FAIL-CLOSED: an unanswerable question is a veto. The question is not
    "did the launch report failure" (it did, by construction) but **"can
    a guest be alive?"**, and the launch outcome cannot decide it:

      `dispatch-failed-after-register` includes an Edge **502**, which the
      Edge returns when its 30 s forward to the miner does not complete —
      and the miner's `/v1/miner/order/launch` AWAITS domain creation. A
      host that is merely slow returns 502 to a guest that goes on to boot
      and release its KEK. `edge-unreachable` is the same shape at vali's
      own 45 s client timeout. So there IS a real timed-out-but-actually-
      started window, and gating on the error string would erase the KEK
      of a running tenant VM. Everything below is evidence instead.

    Every check is a POSITIVE record that a guest existed — not the
    absence of one — except the last two, which demand the positive
    record that the launch gave up and the miner's own answer:

    1. `host-bound` — `vm.host` is stamped ONLY on an ACCEPTED dispatch
       (`launch._bind_vm_host`), i.e. only once a miner confirmed it
       created the domain. A bound VM ran, full stop. §24 PRESERVES it
       through the whole teardown (`_decommission_vm` does not clear it;
       only the `_destroy_vm` tombstone does), so it is a stable gate for
       the entire ack wait.
    2. `boot-phase` — the miner relayed a signed `booting` /
       `kek-released` / `running` milestone. For an unbound VM the
       vm-progress ingress authorizes the reporter against the VM's
       latest `Placement` (#930), so this signal DOES land for a phantom
       whose guest really started — it is the earliest positive evidence
       there is, and it arrives seconds after the domain starts.
    3. `guest-signal` — a §23 served receipt or §322 live attestation was
       ingested, i.e. something spoke from INSIDE the guest.
    4. `seen-running` — reboot-recovery's `seen_running` (#854): the
       reconcile loop OBSERVED this VM's domain running at least once.
       It is the flag that already exists to tell "was actually running"
       from "we hoped it was", which is exactly this question.
    5. `generation` — a generation past 1 means a §25 migration or a
       relaunch, neither of which is reachable without a guest.
    6. `launch-in-flight` — a queued/running `LaunchJob`. THE cross-call
       re-placement guard: an operator who cleared the KBS registration
       and re-launched has a live launch in progress whose guest will use
       this very KEK, and the row still looks abandoned until that launch
       binds a host (which can be 30 min of preflight away).
    7. `launch-succeeded` — some launch for this vm_id DID bind once.
    8. `placement-active` — the same as 6, for the forced/CLI path, which
       records a Pending placement and no `LaunchJob`.
    9. `no-abandoned-launch-record` — the marker
       (`launch._mark_launch_abandoned`) is the positive record that the
       last launch for this row TERMINATED without a host. Without it the
       row is merely one whose launch has not finished yet, which looks
       identical for the whole (up to 30 min) preflight window. Requiring
       it is what keeps this a proof rather than an inference from
       silence.
    10. `domain-unproven` / `domain-running` — the live probe. Only an
       affirmative `False` from the miner (no live domain) clears it;
       `True` (a domain is up) and `None` (miner unreachable) both veto.
       This is the check that makes a dark miner mean "wait", never
       "erase" — and the one that closes the window where a guest started
       seconds ago and its first milestone has not landed.

       ⚠️ EXCEPT when there is no miner to ask because none was ever
       chosen ([`no_miner_was_ever_chosen`]). A launch refused at
       PLACEMENT (`no-eligible-miner`) writes no `Placement` and its
       `LaunchJob` names no miner, so `_abandoned_probe_target` is `""`,
       `poll_domain_running_on` short-circuits to `None`, and the probe
       vetoed FOREVER — a VM that provably never reached any miner was
       the one shape this function could never clear. That conflated "the
       host did not answer" with "there is no host"; only the first is an
       unanswerable question. §24's own crypto-erase already reads the
       same emptiness as an answer (`destroy-skipped:no-miner-ever-
       recorded`).

    1-9 are pure DB reads and run first, so the network probe only fires
    for a VM that has already survived every free objection.
    """
    from apps.orchestration.models import (
        TERMINAL_LAUNCH_STATES,
        LaunchJob,
        LaunchJobState,
        RebootRecovery,
    )
    from apps.scheduler.models import ACTIVE_PLACEMENT_STATES, Placement

    if vm.host:
        return f"host-bound:{vm.host}"
    if vm.boot_phase:
        return f"boot-phase:{vm.boot_phase}"
    if vm.guest_signal_at is not None:
        return "guest-signal"
    if RebootRecovery.objects.filter(vm=vm, seen_running=True).exists():
        return "seen-running"
    generation = max(int(vm.generation or 1), int(vm.signing_generation or 1))
    if generation > 1:
        return f"generation:{generation}"
    launches = LaunchJob.objects.filter(vm_id=vm.vm_id)
    if launches.exclude(state__in=list(TERMINAL_LAUNCH_STATES)).exists():
        return "launch-in-flight"
    if launches.filter(state=LaunchJobState.SUCCEEDED.value).exists():
        return "launch-succeeded"
    if Placement.objects.filter(vm=vm, status__in=list(ACTIVE_PLACEMENT_STATES)).exists():
        return "placement-active"
    if vm.launch_abandoned_at is None:
        return "no-abandoned-launch-record"
    target = _abandoned_probe_target(vm)
    if not target and no_miner_was_ever_chosen(vm):
        # Nothing to probe BECAUSE nothing was ever chosen — see item 10.
        return None
    running = effects.poll_domain_running_on(vm, target)
    if running is not False:
        return "domain-unproven" if running is None else "domain-running"
    return None


def _abandoned_reap_veto(vm: Vm) -> str | None:
    """Why this abandoned VM must NOT be reaped — or `None` if every
    check passes. FAIL-CLOSED: an unanswerable question is a veto.

    ONE job-scoped check, then [`never_ran_veto`] — the reap ends in a
    §24 crypto-erase, so "no guest was ever created" is precisely the
    thing it has to establish, and it is established in ONE place. Before
    this was factored out, §24 waited the full ack timeout on VMs this
    very function had already PROVED could not be running.

    There used to be a second job-scoped check here — a `no-eol-nonce`
    VETO, justified by "`_decommission_vm` fails closed on a VM whose
    stopped-ack could never verify, so a reap could only open a job that
    fails on every tick". That justification was correct AND the veto was
    the wrong conclusion: it left a VM refused at PLACEMENT
    (`no-eligible-miner`, no cmdline ever baked, hence no nonce)
    `state=active` forever with a LIVE per-VM Vault-Transit KEK and no
    automated path anywhere — the §24 job an operator opened by hand
    failed at `draining`, and nothing else reconciled it. Live on
    2026-08-13: `vm-fedora-3`. `_decommission_vm` now accepts exactly
    when `never_ran_veto` clears (and ONLY then), so the check below is
    the same gate and the two can never disagree about the same VM.
    """
    if _has_active_job(vm):
        return "orchestration-job-in-flight"
    return never_ran_veto(vm)


def _reap_abandoned_launch(vm: Vm) -> bool:
    """Open a §24 `DecommissionJob` for one proven-phantom VM. Returns
    True iff a job was opened.

    §24 — not a bespoke erase — because §24 is already the hardened,
    audited answer to "this VM must cease to exist", and every one of its
    steps is the step a phantom needs:

      * the crypto-erase destroys the per-VM Vault-Transit key, which is
        the whole point (the leak is a live KEK with no VM);
      * the destroy order goes to `destroy_target_miner_id` — the SAME
        widened resolver `_abandoned_probe_target` just probed — so if the
        failed dispatch DID leave a domain the miner never told us about,
        it is force-stopped rather than orphaned;
      * `_destroy_vm` tombstones the row `destroyed` AFTER the erase (never
        before) and releases the placements, so the phantom leaves every
        sweep that filters `exclude(state='destroyed')`;
      * it fails LOUD. If the miner cannot be reached the job fails and the
        VM is left visibly stuck rather than silently tombstoned.

    Writing a second erase path would mean a second copy of all of that.

    IDEMPOTENT at the database: `DecommissionJob` carries a partial unique
    index on `vm` for non-terminal states, and `start_decommission` also
    refuses a non-Active VM — so a second sweep (or a second tick process)
    racing this one opens nothing. `StartError` is swallowed for exactly
    that reason: losing the race is the expected outcome, not a fault.
    """
    from apps.identity.models import PrincipalScope, ServiceClient

    system, _ = ServiceClient.objects.get_or_create(
        name=_ABANDONED_REAP_ACTOR,
        defaults={
            "description": (
                "Auto-reap of abandoned post-register launches (§24) — the "
                'phantom `active host=""` rows a failed launch leaves '
                "behind, each holding a live per-VM Vault-Transit KEK."
            ),
            # P2: it opens teardowns across every tenant, which is an
            # operator action by definition. It holds no token.
            "scope": PrincipalScope.OPERATOR.value,
        },
    )
    try:
        job = start_decommission(vm=vm, decided_by=system)
    except StartError as exc:
        log.info("abandoned-launch: vm=%s reap not started (%s)", vm.vm_id, exc)
        return False
    log.warning(
        "abandoned-launch: vm=%s REAPING via §24 job=%s — its launch gave up "
        "with %r (%s), it never bound a host, and no miner reports a live "
        "domain for it. The per-VM Vault-Transit KEK is destroyed and the row "
        "is tombstoned; nothing recoverable is being discarded (a registered "
        "vm_id is already un-relaunchable behind the KBS anti-migration fence, "
        "and a never-baked one never had a disk to lose).",
        vm.vm_id,
        job.job_id,
        vm.launch_abandoned_outcome,
        "post-register" if vm.launch_abandoned_registered else "no measured cmdline was ever baked",
    )
    return True


def sweep_abandoned_launches() -> int:
    """Detect — and where PROVABLY safe, REAP — every `Vm` row an
    abandoned launch left behind. Returns the number SEEN (the tick
    counter), not the number reaped. Never raises.

    ## The leak

    `launch_on_miner` registers the VM with the KBS and provisions its
    per-VM Vault-Transit KEK BEFORE it dispatches (step 8 before step 9),
    and that ordering is deliberate + load-bearing: the guest's KBS
    release is single-shot, so a VM registered against one node and then
    re-placed hits the anti-migration CAS fence (#668's
    `kbs-admin-conflict`). It is therefore the FAILURE path, never the
    ordering, that has to change.

    When the dispatch then fails, the `Vm` row is left `state=active`
    with an EMPTY host and a LIVE KEK. Seen in production on 2026-08-13:
    three consecutive `dispatch-failed-after-register`
    onto a miner that could not start a CVM, each leaving
    `state=active host='' kek_destroyed=False`. That is a data-death
    invariant leak arriving by a route no sweep watched — it is the
    MIRROR of the unbound launch (#939): that was a VM the control plane
    could not SEE; this is a VM it sees that does not EXIST.

    ## Detection vs action

    Detection is unconditional and covers EVERY abandoned launch. The
    automatic reap covers two classes:

      * the post-register one (`launch_abandoned_registered`) — see
        `Vm.launch_abandoned_registered`: a registered vm_id is already
        un-relaunchable anywhere, so reaping forfeits nothing;
      * the NEVER-BAKED one ([`cmdline_was_baked`] is False) — a launch
        that never reached step 4b, i.e. was refused before any measured
        cmdline existed.

    The pre-register hold-back ("that vm_id is still theoretically
    launchable, and erasing a KEK is not a thing to do to a VM that could
    still be saved") is an argument about a VM with a DISK, and it does
    not reach the never-baked class: no cmdline ⇒ no dispatch ⇒ no guest
    ⇒ nothing was ever `luksFormat`ed under that KEK, so there is no
    tenant data to save — only a live per-VM Vault-Transit key with no VM,
    which is the leak itself. It is also the class §24 REFUSED outright
    (`_decommission_vm`'s no-nonce precondition), so before this it had no
    automated path at all: live on 2026-08-13, `vm-fedora-3` sat
    `state=active` with a LIVE KEK and a `failed` DecommissionJob.

    A PRE-register abandonment that DID bake a cmdline is unchanged —
    surfaced only. §24 accepts those by hand today, so the reap policy for
    them is a policy question, not a data-death hole.

    The grace window (`VALI_ABANDONED_LAUNCH_GRACE_S`) is measured from
    the LAST failed launch, and exists so a guest that started despite the
    failed dispatch has time to announce itself before anything looks at
    it; `_abandoned_reap_veto` is what actually decides, on live evidence.
    """
    global _abandoned_warn_memo

    rows = list(
        Vm.objects.filter(
            state=VmState.ACTIVE.value,
            host="",
            launch_abandoned_at__isnull=False,
        )
    )
    if not rows:
        _abandoned_warn_memo = (frozenset(), time.monotonic())
        return 0

    cutoff = timezone.now() - timedelta(seconds=_abandoned_grace_s())
    reap_enabled = _abandoned_reap_enabled()
    outstanding: list[str] = []
    for vm in rows:
        if not vm.launch_abandoned_registered and cmdline_was_baked(vm):
            outstanding.append(f"{vm.vm_id}[{vm.launch_abandoned_outcome}:pre-register]")
            continue
        if vm.launch_abandoned_at > cutoff:
            outstanding.append(f"{vm.vm_id}[{vm.launch_abandoned_outcome}:in-grace]")
            continue
        if not reap_enabled:
            outstanding.append(f"{vm.vm_id}[{vm.launch_abandoned_outcome}:reap-disabled]")
            continue
        try:
            veto = _abandoned_reap_veto(vm)
        except Exception:  # noqa: BLE001 — one VM must not kill the sweep.
            log.exception("abandoned-launch: veto check failed for vm=%s", vm.vm_id)
            veto = "veto-error"
        if veto is not None:
            outstanding.append(f"{vm.vm_id}[{vm.launch_abandoned_outcome}:{veto}]")
            continue
        try:
            if not _reap_abandoned_launch(vm):
                outstanding.append(f"{vm.vm_id}[{vm.launch_abandoned_outcome}:reap-not-started]")
        except Exception:  # noqa: BLE001 — never let a reap kill the tick.
            log.exception("abandoned-launch: reap failed for vm=%s", vm.vm_id)
            outstanding.append(f"{vm.vm_id}[{vm.launch_abandoned_outcome}:reap-error]")

    if outstanding:
        ids = frozenset(outstanding)
        last_ids, last_at = _abandoned_warn_memo
        now = time.monotonic()
        if ids != last_ids or (now - last_at) >= _abandoned_warn_interval_s():
            _abandoned_warn_memo = (ids, now)
            shown = sorted(ids)[:20]
            log.warning(
                "abandoned-launch: %d Vm row(s) whose launch gave up WITHOUT "
                'binding a host — each `state=active host=""` with a LIVE '
                "per-VM Vault-Transit KEK and no VM, counted as running by "
                "every sweep that filters `exclude(state='destroyed')`. Each "
                "entry is vm_id[outcome:why-not-reaped]; `pre-register` ones "
                "DID bake a measured cmdline and are surfaced only (their "
                "vm_id may still be launchable) and need an operator — a "
                "pre-register launch that never baked one is reaped like any "
                "other phantom: %s%s",
                len(ids),
                ", ".join(shown),
                "" if len(shown) == len(ids) else f" (+{len(ids) - len(shown)} more)",
            )
    return len(rows)


def _reboot_recovery_relaunch(
    vm: Vm,
    node_id: str,
    flavor: str | None = None,
    *,
    supersede: bool = False,
    launch_ref: str = "",
) -> bool:
    """Rebuild the `LaunchSpec` from the VM's last SUCCEEDED launch + its
    Vault-staged userdata, and relaunch on the SAME miner via
    `launch_on_miner` (NOT `launch_vm` — which would re-run the scheduler
    and could place the VM on a DIFFERENT miner, whose disk has no overlay →
    data loss). Returns True iff the miner ACCEPTED the order.

    The KEK is NOT re-provisioned: `kek_bytes=None` makes `launch_on_miner`
    read only the KV version of the already-staged `kek-<vm_id>` datakey, so
    the SAME KEK is re-released to the attested guest and the existing overlay
    re-opens. §20: the userdata buffer is zeroized in `finally`.

    The ticket is minted at the VM's CURRENT generation: a VM §25 moved
    holds `generation >= 2`, and its KEK is releasable only there (the KBS
    fence denies every earlier one).

    `flavor` (a resize, `apps.orchestration.resize`) boots this relaunch at
    another size than the record's: vCPU/RAM and the measured
    `hippius.resource_class` follow it, the data disk does not change (the
    resize only admits a flavor with the same `disk_gb`). An accepted
    relaunch records it in the launch record WITH its measurement.

    `launch_ref` tags the relaunch's measurement-ledger row (a guest
    upgrade's attempt id).
    """
    from apps.miners.models import MinerIdentity, is_autoprovision_placeholder
    from apps.orchestration.services import launch, launch_record

    from .models import LaunchJob, LaunchJobState

    job = (
        LaunchJob.objects.filter(vm_id=vm.vm_id, state=LaunchJobState.SUCCEEDED.value)
        .order_by("-finished_at")
        .first()
    )
    if job is None:
        log.warning(
            "reboot-recovery: vm=%s has no SUCCEEDED LaunchJob to rebuild a "
            "spec from — cannot relaunch",
            vm.vm_id,
        )
        return False
    try:
        miner = MinerIdentity.objects.get(miner_id=node_id)
    except MinerIdentity.DoesNotExist:
        return False
    if not miner.platform_id or is_autoprovision_placeholder(miner.platform_id):
        # The ticket binds this chip; without a real one the KBS denies the
        # release only once the guest has booted into its retry loop.
        log.warning(
            "reboot-recovery: vm=%s miner=%s has no registered chip "
            "(platform_id=%r) — cannot relaunch",
            vm.vm_id,
            node_id,
            miner.platform_id,
        )
        return False

    mount = str(getattr(settings, "VALI_VAULT_KV_MOUNT", "secret"))
    userdata = b""
    try:
        try:
            userdata = launch.open_userdata_intake_copy(
                mount,
                job.userdata_vault_path,
                job.userdata_vault_version,
                vm.vm_id,
            )
        except EffectError as exc:
            log.warning("reboot-recovery: vm=%s userdata fetch failed: %s", vm.vm_id, exc)
            return False
        try:
            spec = launch.LaunchSpec(
                **{
                    **job.spec_json,
                    # The ticket binds the host it names. A §25-moved VM's
                    # recorded launch may have pinned its FIRST miner.
                    "platform_id": miner.platform_id,
                    # A resize: the new vCPU/RAM, the SAME data disk.
                    **(
                        {"flavor": flavor, "data_disk_size_gb": launch_record.data_disk_gb(job)}
                        if flavor
                        else {}
                    ),
                },
                kek_bytes=None,
                userdata=userdata,
            )
        except TypeError as exc:
            log.warning(
                "reboot-recovery: vm=%s spec_json is incompatible with "
                "LaunchSpec (%s) — cannot relaunch",
                vm.vm_id,
                exc,
            )
            return False
        try:
            # A relaunch reuses this host's disks; it must never create them
            # (the miner refuses with `relaunch-disks-missing` instead).
            out = launch.launch_on_miner(
                spec,
                miner,
                generation=vm.generation,
                require_existing_disks=True,
                # A resize's first relaunch (`resize._relaunch`): the KBS
                # refuses the pre-resize launch from this register on.
                supersede=supersede,
                **({"launch_ref": launch_ref} if launch_ref else {}),
            )
        except Exception as exc:  # noqa: BLE001 — never let a launch raise into the tick
            log.warning(
                "reboot-recovery: vm=%s launch_on_miner raised %s: %s",
                vm.vm_id,
                type(exc).__name__,
                exc,
            )
            return False
    finally:
        try:
            userdata = b"\x00" * len(userdata)
        except Exception:  # noqa: BLE001
            pass

    accepted = out.disposition == launch.ACCEPTED
    classifier = (getattr(out, "emit", None) or {}).get("classifier")
    if not accepted and classifier == RELAUNCH_DISKS_MISSING_CLASS:
        # Miner-controlled string — trusted ONLY to stop relaunching, the
        # fail-safe direction; it can never make vali act.
        raise RelaunchDisksMissing(f"vm {vm.vm_id!r}: miner {node_id!r} lacks its disks")
    outcome = (getattr(out, "emit", None) or {}).get("outcome")
    if not accepted and outcome == launch.ALLOWLIST_PIN_BUSY:
        raise RelaunchPinBusy(f"vm {vm.vm_id!r}: the allowlist pin lock is busy")
    log.log(
        logging.INFO if accepted else logging.WARNING,
        "reboot-recovery: vm=%s relaunch on miner=%s → %s",
        vm.vm_id,
        node_id,
        out.disposition,
    )
    if not accepted and launch.DISPATCHED_BOOT_KEY in (getattr(out, "emit", None) or {}):
        # Answered as failed after the order went out — it may have booted
        # all the same. A candidate should a retry be `already-launched`.
        try:
            launch_record.add_dispatched_boot(
                vm.vm_id,
                launch_record.dispatched_boot_candidate(
                    dict(out.emit[launch.DISPATCHED_BOOT_KEY]),
                    booted=(spec.s3_key_prefix, spec.initrd_sha256_hex),
                    flavor=flavor,
                ),
            )
        except Exception:  # noqa: BLE001 — logged loudly; the refusal stands either way.
            log.exception(
                "reboot-recovery: vm=%s dispatched boot NOT kept — if it came up, the "
                "record cannot be settled to it; run vali_backfill_launch_measurement",
                vm.vm_id,
            )
    if accepted and launch.answered_already_launched(out):
        # The miner started nothing: the domain up is the boot on record or
        # an earlier dispatch answered as failed — never this retry's. The
        # record waits for the guest's attestation to say which
        # (`sweep_unverified_boots`); no KBS recovery of it until then.
        log.warning(
            "reboot-recovery: vm=%s answered already-launched — not recording this "
            "retry's measurement; the record waits for the guest's attestation",
            vm.vm_id,
        )
        try:
            launch_record.mark_boot_unverified(vm.vm_id)
        except Exception:
            # Unflagged, the record would let a KBS recovery re-mint a boot
            # that may not be the one running: never a silent success.
            log.exception(
                "reboot-recovery: vm=%s already-launched but its record could not be "
                "flagged unverified",
                vm.vm_id,
            )
            raise
    elif accepted:
        # The relaunch is a NEW boot with a NEW measurement (fresh
        # eol_nonce in the measured cmdline). Record it where every
        # re-mint / §25 / recovery path reads "what this VM booted" —
        # otherwise the next KBS-state recovery or §25 hop re-mints the
        # FIRST boot's measurement and the KBS denies the VM. Failing to
        # record is loud but must not undo an accepted relaunch.
        try:
            launch_record.record_relaunch(
                vm.vm_id,
                dict(out.emit or {}),
                reason="reboot-recovery-relaunch",
                # What this boot was launched from — clears a pending
                # initrd-swap marker (`vali_swap_vm_initrd`) once the new
                # initrd is the one running.
                booted=(spec.s3_key_prefix, spec.initrd_sha256_hex),
                flavor=flavor,
            )
        except Exception:  # noqa: BLE001 — logged loudly below; never unwinds the relaunch.
            log.exception(
                "reboot-recovery: vm=%s relaunched but its new measurement was NOT "
                "recorded — a KBS-state recovery or §25 hop would re-mint the old "
                "one; run vali_backfill_launch_measurement",
                vm.vm_id,
            )
    if accepted:
        # The VM is running on `node_id` again, so it holds that host's
        # RAM/CPU again — whatever became of its placement while the host
        # was down (the §13 re-eval drained it on a stale heartbeat before
        # it learned to hold). `launch_on_miner` writes no placement, so
        # the relaunch must. A no-op when the placement already names it.
        rebind_placement_to_host(
            vm, node_id=miner.chain_node_id or "", reason="reboot-recovery:relaunched"
        )
        # ...at the size it booted: a stopped VM resized smaller on the
        # books kept its larger reservation until this boot (`resize.py`).
        # (the boot on record: an `already-launched` retry's own size is
        # not what runs).
        _placement_follows_boot(
            vm,
            node_id=miner.chain_node_id or "",
            flavor=launch_record.booted_flavor(launch_record.latest_record(vm.vm_id) or job),
        )
        # A new boot: restart the boot-stall clock (covers the power-API
        # start too, which relaunches through here). The new boot must then
        # produce its own in-guest signal within the deadline.
        Vm.objects.filter(pk=vm.pk).update(boot_started_at=timezone.now())
    return accepted


def _placement_follows_boot(vm: Vm, *, node_id: str, flavor: str) -> None:
    """Shrink the VM's reservation on `node_id` to the flavor it just booted
    at, when that is smaller in every dimension. Never grows one (a grow is
    reserved, fit-checked, when it is admitted) — and never fails the
    relaunch it follows: logged."""
    from apps.scheduler import service as sched
    from apps.scheduler.models import ACTIVE_PLACEMENT_STATES, Placement

    from .services import flavors

    row = (
        Placement.objects.filter(vm=vm, status__in=ACTIVE_PLACEMENT_STATES, miner_node_id=node_id)
        .values_list("resource_class", flat=True)
        .first()
    )
    if not node_id or row is None or row == flavor:
        return
    try:
        held, booted = flavors.resolve_flavor(row), flavors.resolve_flavor(flavor)
    except flavors.UnknownFlavor:
        return
    if booted.cpu_count > held.cpu_count or booted.memory_mb > held.memory_mb:
        return
    try:
        sched.swap_placement_class(
            vm,
            node_id=node_id,
            new_class=flavor,
            reason=f"booted:{flavor}",
            decided_by=_placement_reconciler(),
            check_fit=False,
        )
    except Exception:  # noqa: BLE001 — the relaunch stands; the books are wrong, loudly
        log.exception(
            "reboot-recovery: vm=%s booted at %s but its %s reservation could not follow",
            vm.vm_id,
            flavor,
            row,
        )


def tick_once() -> TickReport:
    """Advance every non-terminal job by one bounded step.

    First enrol warm migrations for any VM on a gracefully-departing
    (Quarantined/Decommissioned) miner, then advance all in-flight jobs —
    so a freshly-enrolled migration starts moving in the same tick.
    """
    enroll_departing_miner_migrations()
    _reset_kbs_fence_budget()

    migrations = list(
        MigrationJob.objects.exclude(state__in=TERMINAL_MIGRATION_STATES).select_related("vm")
    )
    for job in migrations:
        try:
            advance_migration_job(job)
        except Exception:  # noqa: BLE001 — one job must not kill the tick.
            log.exception("migration %s: unhandled error in tick", job.job_id)

    decommissions = list(
        DecommissionJob.objects.exclude(state__in=TERMINAL_DECOMMISSION_STATES).select_related("vm")
    )
    for job in decommissions:
        try:
            advance_decommission_job(job)
        except Exception:  # noqa: BLE001
            log.exception("decommission %s: unhandled error in tick", job.job_id)

    # Resizes run after the migrations so one whose §25 hop completed this
    # tick takes its next step at once.
    resize_jobs = 0
    try:
        from .resize import tick_resizes

        resize_jobs = tick_resizes()
    except Exception:  # noqa: BLE001 — the resizes must not break the tick.
        log.exception("resize: unhandled error in tick")

    # Guest upgrades (`guest_upgrade`, off unless VALI_GUEST_UPGRADE_ENABLED).
    try:
        from .guest_upgrade import tick_guest_upgrades

        tick_guest_upgrades()
    except Exception:  # noqa: BLE001 — the upgrades must not break the tick.
        log.exception("guest upgrade: unhandled error in tick")
    try:
        from .guest_rollout import tick_guest_rollouts

        tick_guest_rollouts()
    except Exception:  # noqa: BLE001 — the rollouts must not break the tick.
        log.exception("guest rollout: unhandled error in tick")

    # In-guest liveness sweep — count + log the Active VMs whose guest has
    # gone silent behind a still-`running` libvirt domain. Pure
    # observability, ALWAYS on, dispatches nothing. Runs BEFORE
    # reboot-recovery so the operator-facing warning is emitted even if
    # the recovery scan then raises.
    wedged_guests = 0
    try:
        wedged_guests = sweep_guest_liveness()
    except Exception:  # noqa: BLE001 — an observability sweep must not break the tick.
        log.exception("guest-liveness: unhandled error in sweep")
    boot_stalls = 0
    try:
        boot_stalls = sweep_boot_stalls()
    except Exception:  # noqa: BLE001 — an observability sweep must not break the tick.
        log.exception("boot-stall: unhandled error in sweep")

    # Unbound-launch sweep (P9/#18) — surface any vm_id vali launched but
    # has no `Vm` row for. Pure observability like the one above: it reads
    # vali's own ledger, warns, and writes NOTHING. It must never adopt,
    # because a `Vm` row is what makes a VM eligible for crypto-erase.
    unbound_launches = 0
    try:
        unbound_launches = sweep_unbound_launches()
    except Exception:  # noqa: BLE001 — an observability sweep must not break the tick.
        log.exception("unbound-launch: unhandled error in sweep")

    # Abandoned-launch sweep — surface every `Vm` row a failed launch left
    # `active` with no host and a live KEK, and reap the ones proven
    # phantom. Runs BEFORE the decommission jobs would be nice, but it
    # OPENS decommission jobs, so it runs here: a job opened this tick is
    # advanced by the next one (10 s later), which keeps the reap out of
    # the same pass that enumerated the jobs.
    abandoned_launches = 0
    try:
        abandoned_launches = sweep_abandoned_launches()
    except Exception:  # noqa: BLE001 — the sweep must not break the tick.
        log.exception("abandoned-launch: unhandled error in sweep")

    # Stranded-migration sweep — surface (and, where the KBS provably never
    # moved, restore) every VM fenced in `migrating` behind a TERMINAL job.
    # Runs BEFORE reboot-recovery deliberately: a VM restored here is
    # `Active` on its source with no domain, which is exactly the shape
    # reboot-recovery exists for, so the same tick brings the guest back.
    stranded = 0
    try:
        stranded = sweep_stranded_migrations()
    except Exception:  # noqa: BLE001 — the sweep must not break the tick.
        log.exception("stranded-migration: unhandled error in sweep")

    # Stranded-decommission sweep — re-open a job for every VM left in
    # `decommissioning` behind a FAILED §24 job. The job it opens is
    # advanced by the next tick.
    stranded_decommissions = 0
    try:
        stranded_decommissions = sweep_stranded_decommissions()
    except Exception:  # noqa: BLE001 — the sweep must not break the tick.
        log.exception("stranded-decommission: unhandled error in sweep")

    # §24 KBS fence re-drive — land every decommission fence / tombstone a
    # job had to give up on in-line. A no-op unless VALI_KBS_FENCE_ENABLED.
    kbs_fence_pending = 0
    try:
        kbs_fence_pending = sweep_pending_kbs_fences()
    except Exception:  # noqa: BLE001 — the sweep must not break the tick.
        log.exception("kbs-fence: unhandled error in sweep")

    # Reboot-recovery — relaunch any Active VM that is down on its still-alive
    # bound miner (default-off; a no-op unless VALI_REBOOT_RECOVERY_ENABLED).
    # Runs LAST so it never contends with an in-flight migration/decommission
    # for the same VM (those are re-checked per-VM inside the scan anyway).
    reboot_recovery_relaunches = 0
    try:
        reboot_recovery_relaunches = reboot_recovery_once()
    except Exception:  # noqa: BLE001 — the recovery scan must not break the tick.
        log.exception("reboot-recovery: unhandled error in scan")
    relaunch_disks_missing = 0
    try:
        relaunch_disks_missing = sweep_relaunch_disks_missing()
    except Exception:  # noqa: BLE001 — an observability sweep must not break the tick.
        log.exception("reboot-recovery: unhandled error in disks-missing sweep")

    # Placement invariant — every live VM holds an active placement on the
    # host it runs on. After reboot-recovery, so a VM it relaunched this
    # tick is already back on its host's books.
    # Orphaned launch jobs first: resolving one can release the Pending
    # placement the placement sweeps below would otherwise wait on.
    orphan_completed = orphan_failed = 0
    try:
        from apps.orchestration.launch_jobs import reap_orphaned_launch_jobs

        orphan_completed, orphan_failed = reap_orphaned_launch_jobs()
    except Exception:  # noqa: BLE001 — the sweep must not break the tick.
        log.exception("launch janitor: unhandled error")

    # Stale Pending rows first: a cancelled one leaves its VM with no
    # placement, which the next sweep re-binds on its real host this tick.
    pending_promoted = pending_cancelled = 0
    try:
        pending_promoted, pending_cancelled = sweep_stale_pending_placements()
    except Exception:  # noqa: BLE001 — the sweep must not break the tick.
        log.exception("placement invariant: unhandled error in stale-pending sweep")
    placements_repaired = 0
    try:
        placements_repaired = sweep_live_vm_placements()
    except Exception:  # noqa: BLE001 — the sweep must not break the tick.
        log.exception("placement invariant: unhandled error in sweep")

    # A superseded launch whose eviction failed right after its relaunch
    # (busy lock, S3 / KBS error) still releases a key until this lands.
    try:
        sweep_superseded_measurements()
    except Exception:  # noqa: BLE001 — the sweep must not break the tick.
        log.exception("allowlist: unhandled error evicting superseded launches")

    # An `already-launched` answer left a record waiting for its guest's
    # attestation: settle it, so §25 and KBS recovery can re-mint again.
    try:
        sweep_unverified_boots()
    except Exception:  # noqa: BLE001 — the sweep must not break the tick.
        log.exception("launch record: unhandled error settling unverified boots")

    # Post-§25 overlay verification (P9/#17). Independent of the job state
    # machines — a migration is already Done by the time its VM is checked
    # — so it runs unconditionally, and its failures never touch a job.
    netbird_checks = 0
    try:
        netbird_checks = verify_netbird_enrolments()
    except Exception:  # noqa: BLE001 — the sweep must not break the tick.
        log.exception("netbird: unhandled error in post-migration sweep")

    # Tenant NetBird peers are persistent, so a missed §24 revoke would
    # leak one forever — collect the peers of Destroyed / unknown VMs.
    # Throttled inside; a NetBird failure is logged, never raised.
    netbird_orphan_peers_deleted = 0
    try:
        from .netbird_janitor import sweep_orphan_tenant_peers

        netbird_orphan_peers_deleted = sweep_orphan_tenant_peers()
    except Exception:  # noqa: BLE001 — the sweep must not break the tick.
        log.exception("netbird janitor: unhandled error in sweep")

    # Post-§25 SOURCE reclaim (P9/#15). Also outside the job state machine,
    # and for the same reason: a source that cannot be proven safe to
    # reclaim must never hold a completed migration open.
    source_reclaims = 0
    try:
        source_reclaims = reclaim_migrated_sources()
    except Exception:  # noqa: BLE001 — the sweep must not break the tick.
        log.exception("source-reclaim: unhandled error in post-migration sweep")
    try:
        gc_migration_snapshots()
    except Exception:  # noqa: BLE001 — the sweep must not break the tick.
        log.exception("migration-snapshot-gc: unhandled error")
    try:
        settle_cold_migrations()
    except Exception:  # noqa: BLE001 — the sweep must not break the tick.
        log.exception("cold-migration: unhandled error in settle sweep")
    try:
        _restore().sweep_restore_cleanups()
    except Exception:  # noqa: BLE001 — the sweep must not break the tick.
        log.exception("restore: unhandled error in cleanup sweep")
    try:
        _restore().sweep_rollback_events()
    except Exception:  # noqa: BLE001 — the sweep must not break the tick.
        log.exception("restore: unhandled error in the rollback-arm sweep")
    try:
        _restore().reconcile_failover_quarantines()
    except Exception:  # noqa: BLE001 — the sweep must not break the tick.
        log.exception("failover: unhandled error in reappearance reconciliation")

    # Public IPs: follow each attached VM's NetBird address, release the
    # addresses of VMs that are gone, and keep the edges' exit routing
    # right. Lazy import — orchestration must not couple to the network
    # app at module load.
    public_ip_retargets = 0
    try:
        from apps.network.service import reconcile as reconcile_public_ips

        public_ip_retargets = reconcile_public_ips().retargeted
    except Exception:  # noqa: BLE001 — the sweep must not break the tick.
        log.exception("public-ip: unhandled error in reconcile")

    # Live VM backups: follow in-flight runs, start the due ones, prune.
    # Inert unless VALI_BACKUP_ENABLED. Lazy import, like the network app.
    backup_runs_started = 0
    try:
        from apps.backup.service import tick as backup_tick

        backup_runs_started = backup_tick().started
    except Exception:  # noqa: BLE001 — the sweep must not break the tick.
        log.exception("backup: unhandled error in tick")

    # Zombie VMs — observability only: the refusal and the quarantine are
    # enforced at ingest / placement / epoch weights, not here.
    zombie_vms = 0
    zombie_quarantined_miners = 0
    try:
        from apps.lifecycle import zombie

        zombie_vms = len({row.vm_id for row in zombie.fresh_observations()})
        zombie_quarantined_miners = len(zombie.quarantined_node_ids())
    except Exception:  # noqa: BLE001 — the sweep must not break the tick.
        log.exception("zombie: unhandled error counting observations")

    # KBS audit-log ingest — copy the KBS's hash-chained release/admin
    # logs out of its CVM and verify them. Throttled inside; inert unless
    # VALI_KBS_AUDIT_INGEST_ENABLED. Lazy import, like the sweeps above.
    kbs_audit_ingested = kbs_audit_breaks = 0
    try:
        from .kbs_audit import ingest_tick as kbs_audit_tick

        audit_result = kbs_audit_tick()
        kbs_audit_ingested, kbs_audit_breaks = audit_result.stored, audit_result.breaks
    except Exception:  # noqa: BLE001 — the ingest must not break the tick.
        log.exception("kbs-audit: unhandled error in ingest")

    return TickReport(
        migration_jobs=len(migrations),
        decommission_jobs=len(decommissions),
        resize_jobs=resize_jobs,
        reboot_recovery_relaunches=reboot_recovery_relaunches,
        relaunch_disks_missing=relaunch_disks_missing,
        netbird_checks=netbird_checks,
        wedged_guests=wedged_guests,
        boot_stalls=boot_stalls,
        source_reclaims=source_reclaims,
        unbound_launches=unbound_launches,
        stranded_migrations=stranded,
        stranded_decommissions=stranded_decommissions,
        abandoned_launches=abandoned_launches,
        public_ip_retargets=public_ip_retargets,
        backup_runs_started=backup_runs_started,
        zombie_vms=zombie_vms,
        zombie_quarantined_miners=zombie_quarantined_miners,
        kbs_fence_pending=kbs_fence_pending,
        placements_repaired=placements_repaired,
        pending_promoted=pending_promoted,
        pending_cancelled=pending_cancelled,
        orphan_launches_completed=orphan_completed,
        orphan_launches_failed=orphan_failed,
        netbird_orphan_peers_deleted=netbird_orphan_peers_deleted,
        kbs_audit_ingested=kbs_audit_ingested,
        kbs_audit_breaks=kbs_audit_breaks,
    )


# ─── idempotency-guarded side-effects ────────────────────────────────


def _guarded(key: str, effect: Callable[[], None]) -> None:
    """Run an external side-effect, deduplicated across tick retries.

    `recall` before — if the §14 store already recorded this key a
    prior tick performed the side-effect; skip it. `record` after a
    successful run. Because `record` follows the effect, a crash in
    the window between them re-runs the effect on retry — so this is
    *common-case* dedup, NOT exactly-once. Every peer effect is
    idempotent (§24) and that is the crash-window guarantee; a failed
    `record` is therefore logged, not fatal.
    """
    if idempotency.recall(key) is not None:
        log.info("idempotency: step %s already done — skipping side-effect", key)
        return
    effect()
    try:
        idempotency.record(key, idempotency.marker_hash(key))
    except IdempotencyUnavailable as exc:
        log.warning(
            "idempotency: record failed for %s (side-effect already done): %s",
            key,
            exc,
        )


def _mig_key(job: MigrationJob, step: str) -> str:
    return f"migration:{job.job_id}:{step}"


def _dec_key(job: DecommissionJob, step: str) -> str:
    return f"decommission:{job.job_id}:{step}"


# ─── VM lifecycle transitions (the §24/§25 unified state model) ──────


def _fence_vm(job: MigrationJob) -> None:
    """§25 step 5 — CAS the `Vm` `Active → Migrating`. Idempotent: a
    re-run that finds the VM already fenced for THIS job is a no-op.

    §25 M3 — the EOL nonce is NOT (re-)minted here. It was minted at
    `start_migration`, BEFORE the quiesce stopped the source guest, and
    the guest has ALREADY signed its `stopped{}` ack with it. Re-minting
    at the fence would invalidate that already-produced ack (vali would
    then verify against a nonce the guest never saw → fail closed forever
    → spurious quarantine). So the fence only flips state + records the
    dest/new_gen; it PRESERVES the nonce the source signed.
    """
    vm = Vm.objects.get(id=job.vm_id)
    if vm.state == VmState.MIGRATING:
        if vm.migration_dest == job.dest_node_id and vm.new_generation == job.new_gen:
            return  # already fenced by a prior tick of this job
        raise EffectError(f"vm already migrating elsewhere (dest={vm.migration_dest!r})")
    if vm.state != VmState.ACTIVE:
        raise EffectError(f"vm is {vm.state!r}, not Active — cannot fence")
    if vm.generation != job.source_gen:
        raise EffectError(f"vm generation moved ({vm.generation} != source_gen {job.source_gen})")
    if job.kind == MigrationKind.MIGRATE.value and not vm.eol_nonce:
        # Defensive: `start_migration` mints the nonce; a Migrating-bound
        # VM without one cannot have a verifiable source ack — fail closed
        # rather than fence a migration whose ack can never verify. (A
        # restore / failover is not activated on an ack.)
        raise EffectError("vm has no eol_nonce at fence — not prepared for the ack")
    with transaction.atomic():
        updated = Vm.objects.filter(
            id=vm.id, version=vm.version, state=VmState.ACTIVE.value
        ).update(
            state=VmState.MIGRATING.value,
            new_generation=job.new_gen,
            migration_dest=job.dest_node_id,
            # RESET the boot progress HERE, at the fence — not at dest
            # activation.
            #
            # `advance_boot_phase` is MONOTONIC, so carrying the SOURCE's
            # terminal `running` forward does not merely leave a stale
            # value: it PERMANENTLY SUPPRESSES the destination's
            # milestones, because `booting` ranks below `running` and is
            # refused, and so is `kek_released`.
            #
            # The fence is the right moment for two reasons:
            #
            # 1. The dest's `booting` fires from `run_domain` INSIDE the
            #    same `handle_launch` whose return triggers
            #    `mark_activate_done` — so it reaches vali milliseconds
            #    BEFORE the dest reports done. Resetting at activation
            #    (where this used to live) refused that milestone against
            #    the inherited `running` and then wiped it: `booting` was
            #    lost on EVERY migration.
            # 2. Here the source is being stopped and the dest has not
            #    been told to boot, so there is no destination progress to
            #    destroy. Resetting later CAN wipe real progress — a VM
            #    migrated while at `kek_released` has its dest milestones
            #    refused, then a served receipt advances the row to
            #    `running` while it is still MIGRATING, and the activation
            #    wiped that.
            #
            # It also stops `GET /state` reporting `running` for a guest
            # that is powered off mid-migration, which is the same
            # green-record/dead-workload shape §25's Done-gate had. A
            # post-fence failure then leaves `boot_phase=""` on a stopped
            # guest — more honest than `running`.
            boot_phase="",
            boot_phase_at=None,
            # eol_nonce PRESERVED — the source already signed it (M3).
            version=vm.version + 1,
        )
        if updated:
            _consume_prior_stopped_acks(vm)
    if updated == 0:
        raise EffectError("vm changed concurrently during fence")


def _consume_prior_stopped_acks(vm: Vm) -> None:
    """Delete every stopped-ack `vm` delivered before the fence being
    committed. Call INSIDE the transaction of an `Active → Migrating` /
    `Active → Decommissioning` CAS, and only once it has won.

    The guest signs at its baked `signing_generation` with its per-launch
    `eol_nonce`, both constant for the VM's life, so an ack left over from
    an earlier stop (a previous §25 hop, an aborted attempt) is a valid ack
    for this one, and `poll_source_ack` / `poll_eol_ack` would hand it to
    `_verify_ack` inside its timestamp skew. For §25 that activates the
    destination while the source still runs: the KBS moves the fence on
    from a `Migrating` row (second §25, failover), so nothing downstream
    catches it. For §24 it records a clean stop that never happened.

    The ingest only accepts acks once the VM is `Migrating` /
    `Decommissioning`, which the enclosing transaction makes visible, so
    every row deleted here predates this job's stop.
    """
    StoppedAckIngest.objects.filter(vm_id=vm.vm_id).delete()


def _mop_up_boot_phase() -> dict[str, Any]:
    """UPDATE expressions that clear a LATE source `running` at §25 dest
    activation, so it cannot suppress the destination's milestones.

    Evaluated INSIDE the UPDATE, deliberately. Deciding from the row read
    at the top of `_activate_dest_vm` would be a TOCTOU: the served-receipt
    writer saves `boot_phase` with
    `update_fields=["boot_phase","boot_phase_at","updated_at"]` and does
    NOT bump `version` (`telemetry/service.py`), so the CAS's `version` pin
    cannot detect a receipt landing between that read and this write. The
    mop-up would then be skipped on a stale decision and the destination's
    milestones would be suppressed for the rest of the VM's life — the
    original bug, on a narrow but silent and permanent window.

    Why a second reset at all, when `_fence_vm` already cleared it:
    `_fence_vm` runs BEFORE `relay_quiesce` dispatches (the §M-StoppedAck
    ordering), so the source guest is still RUNNING when the fence clears
    the phase. The tenant telemetry agent does a FINAL DRAIN of its
    buffered receipts on shutdown — which is exactly what the quiesce
    triggers. That flushed `served_receipt` lands after the fence and
    `_advance_tenant_vm_boot_progress` puts the row straight back to
    `running`; it guards on source/kind only, never on lifecycle state.
    With only the fence reset nothing cleaned that up and the
    destination's milestones were refused for the rest of the VM's life —
    the original bug.

    The two sites fail in OPPOSITE directions, which is why both exist:
    fence-only loses to the shutdown drain; activation-only refuses the
    dest's `booting`, which arrives inside the same `handle_launch` whose
    return triggers `mark_activate_done`.

    Why ONLY `running`, rather than clearing unconditionally: by
    activation the destination has normally already reported `booting` and
    `kek_released`, and wiping those makes `boot_phase` visibly REGRESS
    (`kek_released → "" → running`) in a field the model documents as
    monotonic — briefly reporting `""` for a guest that has already
    released its KEK.

    The asymmetry that makes this safe is SELF-HEALING, not provenance:
    `running` is re-asserted by every served receipt (~1/min), so mopping
    one that legitimately belonged to the destination costs a receipt
    interval, while `booting` / `kek_released` are ONE-SHOT and never come
    back once refused. (Note `running` has two producers — served receipts
    at `telemetry/service.py` and a miner-relayed milestone at
    `telemetry/views.py` — so this cannot be justified by "only the source
    can have written it".)
    """
    running = VmBootPhase.RUNNING.value
    return {
        "boot_phase": Case(
            When(boot_phase=running, then=Value("")),
            default=F("boot_phase"),
        ),
        "boot_phase_at": Case(
            When(
                boot_phase=running,
                then=Value(None, output_field=DateTimeField()),
            ),
            default=F("boot_phase_at"),
        ),
    }


def _netbird_verify_grace() -> float:
    """How long a post-§25 `pending` peer has to come back CONNECTED
    before it is declared `lost` (default 15 min).

    Sized to bracket a destination boot (the guest must POST its way
    through `booting → kek_released → running` and only then does its
    netbird unit dial out) WITHOUT waiting so long that an operator
    learns about the loss from the tenant. It is a floor on the false-
    positive side only: a peer whose RECORD has been GC'd is declared
    lost immediately, because that verdict cannot become wrong later.
    """
    return float(getattr(settings, "VALI_NETBIRD_VERIFY_GRACE_S", 900.0))


def _netbird_verify_marker() -> dict[str, Any]:
    """UPDATE expressions that ARM the post-migration overlay check.

    Evaluated INSIDE the `_activate_dest_vm` CAS, for the same reason
    `_mop_up_boot_phase` is: the served-receipt writer updates
    `netbird_ip` without bumping `version`, so a decision taken from the
    row read at the top of `_activate_dest_vm` could be stale and the
    marker silently skipped. Arming it in the same UPDATE that flips the
    row to `Active` also makes it impossible for a migration to report
    Done WITHOUT the check being armed — there is no second write to
    lose.

    Armed ONLY for a VM that already has a resolved `netbird_ip`. Two
    reasons, both load-bearing:
      - a netbird-DISABLED VM has no peer to look for, and "peer absent"
        would flag it `lost` forever;
      - a netbird-ENABLED VM that never enrolled in the first place was
        already off the overlay BEFORE the migration — that is a launch
        bug, not a §25 one, and flagging it here would blame the wrong
        subsystem.
    """
    deadline = timezone.now() + timedelta(seconds=_netbird_verify_grace())
    enrolled = ~Q(netbird_ip="")
    return {
        "netbird_status": Case(
            When(enrolled, then=Value(VmNetbirdStatus.PENDING.value)),
            default=F("netbird_status"),
        ),
        "netbird_verify_deadline": Case(
            When(enrolled, then=Value(deadline)),
            default=F("netbird_verify_deadline"),
            output_field=DateTimeField(),
        ),
    }


def _settle_netbird(vm: Vm, status: str, *, reason: str, ip: str | None = None) -> None:
    """CAS the VM out of `pending` into a terminal overlay verdict.

    Filtered on `netbird_status=pending` so a concurrent settle (or a
    re-armed check from a NEWER migration that has already run) cannot be
    clobbered. Deliberately does NOT bump `version`: these fields are
    display/alerting only and are not read by any lifecycle CAS filter,
    exactly like the served-receipt `boot_phase` / `netbird_ip` writers.
    """
    patch: dict[str, Any] = {
        "netbird_status": status,
        "netbird_verify_deadline": None,
    }
    if ip:
        patch["netbird_ip"] = ip
    updated = Vm.objects.filter(id=vm.id, netbird_status=VmNetbirdStatus.PENDING.value).update(
        **patch
    )
    if updated == 0:
        return  # someone else settled it — leave their verdict alone
    if status == VmNetbirdStatus.LOST.value:
        # The ONLY signal a tenant-off-the-overlay migration produces.
        # ERROR, not warning: nothing else in the system will notice, and
        # the guest cannot self-heal (its one-off setup key is spent).
        log.error(
            "netbird: vm %s is OFF the overlay after its migration (%s) — "
            "last known ip=%s; the guest cannot re-enrol itself (§25 does "
            "not re-mint a setup key for the destination)",
            vm.vm_id,
            reason,
            vm.netbird_ip or "<none>",
        )
    else:
        log.info(
            "netbird: vm %s is back on the overlay after its migration (%s)",
            vm.vm_id,
            reason,
        )


def _verify_one_netbird_enrolment(vm: Vm) -> None:
    """Resolve one `pending` VM's peer and settle / keep waiting."""
    if vm.state != VmState.ACTIVE.value:
        # Re-migrating, decommissioning or destroyed: there is no steady
        # state to verify. Disarm rather than hold a `pending` that would
        # eventually time out into a bogus `lost`.
        Vm.objects.filter(id=vm.id, netbird_status=VmNetbirdStatus.PENDING.value).update(
            netbird_status="", netbird_verify_deadline=None
        )
        return
    try:
        peer = effects.resolve_netbird_peer(vm.vm_id)
    except EffectError as exc:
        # EffectUnavailable (transport/token) and EffectError (4xx/5xx,
        # non-JSON) alike. NOT evidence of absence — a NetBird outage must
        # never be laundered into "every migrated tenant is off the
        # overlay". Stay `pending` (itself a visible state) and retry.
        log.warning("netbird: could not verify vm %s after migration: %s", vm.vm_id, exc)
        return
    if peer is None:
        # The peer RECORD is gone from management — NetBird's ephemeral GC
        # removed it while the VM was down for the cold move. This is
        # terminal: the launch-time setup key is `usage_limit=1` and
        # consumed, so no boot of this guest can ever re-register.
        _settle_netbird(vm, VmNetbirdStatus.LOST.value, reason="peer record deleted")
        return
    if peer.connected:
        _settle_netbird(vm, VmNetbirdStatus.OK.value, reason="peer connected", ip=peer.ip)
        return
    deadline = vm.netbird_verify_deadline
    if deadline is not None and timezone.now() < deadline:
        return  # still booting — give it the grace window
    _settle_netbird(
        vm,
        VmNetbirdStatus.LOST.value,
        reason="peer never reconnected before the deadline",
    )


def verify_netbird_enrolments() -> int:
    """Settle every VM awaiting a post-§25 overlay check. Returns the
    number of rows examined.

    §25 moves the guest-keyed overlay INTACT, so the guest's own NetBird
    identity survives the migration — but the management-side peer record
    did not for a VM launched before tenant peers became persistent: its
    setup key was minted `ephemeral: True` and
    NetBird deletes an ephemeral peer after ~10 min offline, which a cold
    move routinely exceeds (the dest-activation poll alone budgets 20).
    The destination cannot re-enrol, because the only key it has is the
    consumed one-off from launch.

    Nothing else in the system notices: `netbird_ip` is carried across the
    activation verbatim and the served-receipt self-heal only re-resolves
    while the field is EMPTY and the VM is under 30 minutes old. Tenant
    telemetry rides vsock, not the overlay, so receipts keep flowing and
    the VM keeps reporting `running`. Without this sweep the migration
    reports Done, the row reads healthy, and the tenant simply cannot
    reach their machine.

    Driven from the tick rather than from a served receipt on purpose: it
    must fire whether or not the destination guest is talking to us.
    """
    pending = list(Vm.objects.filter(netbird_status=VmNetbirdStatus.PENDING.value))
    for vm in pending:
        try:
            _verify_one_netbird_enrolment(vm)
        except Exception:  # noqa: BLE001 — one VM must not kill the sweep.
            log.exception("netbird: unhandled error verifying vm %s", vm.vm_id)
    return len(pending)


# ─── §25 source-side reclaim (P9/#15) ────────────────────────────────


def _source_reclaim_enabled() -> bool:
    """Master switch. Default ON: the gate below is the safety, and a
    default-off flag is how this repo repeatedly ends up with a fix that
    is merged, believed live, and doing nothing."""
    return bool(getattr(settings, "VALI_MIGRATION_SOURCE_RECLAIM_ENABLED", True))


def _source_reclaim_proof_window() -> float:
    """How long a completed migration waits for proof that the DESTINATION
    obtained the KEK before the source reclaim is abandoned.

    Generous (6h) on purpose: the cost of waiting is disk on a host that is
    not serving the VM, while the cost of a premature give-up is nothing
    at all — abandoning only leaves the artifacts in place and logs. The
    window exists so a job cannot sit `pending` forever silently; when it
    elapses the outcome is a LOUD, operator-visible `skipped`.
    """
    return float(getattr(settings, "VALI_MIGRATION_SOURCE_RECLAIM_WINDOW_S", 6 * 3600.0))


def _dest_unproven_reason(job: MigrationJob, vm: Vm) -> str | None:
    """`None` iff the DESTINATION is proven good; otherwise a short reason
    the destination is not (yet) proven, safe to log and to persist.

    ## What counts as proof, and why nothing weaker does

    "The migration reports Done" is NOT proof — `poll_dest_activation`
    reads the DEST MINER's own `migration/{vm}/status`, unsigned and
    self-reported by the party that benefits, and the repo has a recorded
    live failure where exactly that said `done` for a destination that
    booted and never unlocked. `Vm.boot_phase == kek_released` is not
    proof either: that milestone is signed by the destination MINER, which
    merely observed a 200 on a KEK release it PROXIED
    (`miner-agent/src/vsock/kbs_proxy.rs`). A served receipt is
    guest-signed but its `node_id` is self-declared and cross-checked only
    against the launch-time `VmBillingBinding`, which no migration ever
    updates — so a migrated guest keeps attesting the SOURCE node forever.

    The proof used here is the KBS EVIDENCE BUNDLE:

    1. it exists only because the KBS GRANTED a KEK release — i.e. it
       verified an SNP report chained VCEK→ASK→ARK whose `REPORT_DATA`
       bound a single-use KBS nonce, and whose `chip_id` equalled the
       ticket's `platform_id`;
    2. under `Migrating{new_gen, dest}` the KBS's own `check_releasable`
       refuses anything but the DESTINATION at `new_gen`
       (`kbs-core/src/lifecycle.rs`), so a grant at all is a host+
       generation assertion made by the KBS, not by the miner;
    3. vali reads it DIRECTLY from the KBS admin listener — the untrusted
       miner is not on that path and cannot forge, replay or withhold it.

    We then re-check (2) against vali's OWN record rather than trusting the
    bundle's summary fields: the bundle names the `ticket_id` it granted
    against, and `OrderTicketIntake` is the row `remint_dest_ticket` wrote
    when it minted the dest ticket at `new_gen` bound to the dest chip.

    Absence is AMBIGUOUS, never negative: the KBS evidence sink is an
    emptyDir, so a KBS restart erases bundles (a VM whose bundle
    predates the restart returns `None`). Absence therefore keeps
    the job `pending` — it never authorises a reclaim, and it never
    condemns the destination.
    """
    # (a) vali's own authoritative record of the activation.
    if vm.state != VmState.ACTIVE.value:
        return f"vm-not-active:{vm.state}"
    if vm.host != job.dest_node_id:
        return f"vm-not-on-dest:{vm.host or '(none)'}"
    if vm.generation != job.new_gen:
        return f"vm-generation:{vm.generation}!={job.new_gen}"
    return _kbs_grant_unproven_reason(job, vm)


def _kbs_grant_unproven_reason(job: MigrationJob, vm: Vm) -> str | None:
    """The KBS half of `_dest_unproven_reason`: `None` iff the KBS's latest
    grant for the VM is the DESTINATION's at `new_gen` on its chip (b-d
    there). Needs no activated `Vm` row, so a restore reads it BEFORE the
    activation, as its commit point. Raises `EffectError` when the KBS
    cannot be read."""
    # (b) the dest chip the ticket had to be bound to. Fail CLOSED when it
    #     cannot be resolved — an unverifiable host bind is not a pass.
    from apps.miners.models import MinerIdentity

    dest_platform_id = (
        MinerIdentity.objects.filter(miner_id=job.dest_node_id)
        .values_list("platform_id", flat=True)
        .first()
    )
    if not dest_platform_id:
        return "dest-platform-id-unresolvable"

    # (c) the KBS-side grant.
    from .services import kbs_evidence

    bundle = kbs_evidence.fetch_evidence(vm.vm_id)
    if bundle is None:
        return "no-kbs-evidence-bundle"
    ticket_id = str(bundle.get("ticket_id") or "")
    if not ticket_id:
        return "evidence-without-ticket-id"

    from apps.orders.models import OrderTicketIntake

    intake = OrderTicketIntake.objects.filter(ticket_id=ticket_id).first()
    if intake is None:
        return "evidence-ticket-unknown-to-vali"
    if intake.vm_id != vm.vm_id:
        return "evidence-ticket-other-vm"
    if intake.vm_generation != job.new_gen:
        # The latest grant is not the destination's. Common and benign
        # while the dest is still booting; permanent if it never unlocked.
        return f"evidence-generation:{intake.vm_generation}!={job.new_gen}"
    if intake.node_id != job.dest_node_id:
        return "evidence-ticket-other-node"
    if intake.platform_id != dest_platform_id:
        return "evidence-ticket-other-platform"

    # (d) freshness — the grant must post-date the migration. Cheap, and it
    #     stops a hand-seeded historical intake row from ever qualifying.
    try:
        granted_at = int(bundle.get("granted_at_unix") or 0)
    except (TypeError, ValueError):
        return "evidence-granted-at-malformed"
    if granted_at < int(job.started_at.timestamp()):
        return "evidence-predates-migration"
    return None


def _reclaim_liveness_grace() -> timedelta:
    return timedelta(
        seconds=float(getattr(settings, "VALI_MIGRATION_RECLAIM_LIVENESS_GRACE_S", 600.0))
    )


def _dest_not_alive_reason(job: MigrationJob, vm: Vm) -> str | None:
    """`None` iff the destination GUEST has proved it is running: an
    in-guest signal (a served receipt or a KBS-verified live attestation,
    `Vm.guest_signal_at`) at least the grace period after the migration
    finished.

    Defense in depth on top of `_dest_unproven_reason`'s KBS grant: that
    proves the destination was RELEASED its key, not that it then booted
    — live, a destination unlocked a truncated volume and hung. Neither
    signal is bound to a chip, and neither needs to be: the SOURCE guest
    was quiesced and fenced before the destination was activated, and the
    reboot-watcher does not restart a migrated-away domain, so a signal
    after the migration finished can only come from the destination."""
    since = (job.finished_at or job.started_at) + _reclaim_liveness_grace()
    if vm.guest_signal_at is None or vm.guest_signal_at < since:
        return "dest-guest-not-alive-past-grace"
    return None


def _delete_migration_snapshot(job: MigrationJob) -> bool:
    """Delete a migration's S3 snapshot objects (volume + state disk) and
    record it. Best-effort: a store failure leaves them for the janitor."""
    if job.snapshot_deleted_at is not None or not job.snapshot_key:
        return False
    try:
        client = s3.get_s3_client()
        for key in (job.snapshot_key, job.snapshot_state_key):
            if key:
                client.delete_object(bucket=job.snapshot_bucket, key=key)
    except Exception as exc:  # noqa: BLE001 — hygiene, never fatal
        log.warning("migration %s: snapshot delete failed: %s", job.job_id, exc)
        return False
    # Every job naming these objects (a re-drive reuses its failed job's).
    MigrationJob.objects.filter(
        snapshot_bucket=job.snapshot_bucket, snapshot_key=job.snapshot_key
    ).update(snapshot_deleted_at=timezone.now())
    log.info("migration %s: S3 snapshot deleted (%s)", job.job_id, job.snapshot_key)
    return True


def _snapshot_retired(job: MigrationJob, vm: Vm | None) -> bool:
    """Whether a TERMINAL migration's snapshot can no longer be needed:
    - the VM is gone (Destroyed, or no row);
    - the migration is Done and its destination guest PROVED it runs
      (`_dest_not_alive_reason`) — checked here, not inferred from the
      source having been reclaimed: jobs reclaimed before that gate existed
      were reclaimed on the KBS grant alone;
    - the migration FAILED and the VM is no longer fenced `Migrating` (it
      was restored to its source, or has moved on): a forward re-drive,
      the only use of a failed job's snapshot, is then impossible. Kept for
      the retention window regardless.
    A VM still `Migrating` keeps it."""
    if vm is None or vm.state == VmState.DESTROYED.value:
        return True
    if job.state == MigrationState.DONE.value:
        return _dest_not_alive_reason(job, vm) is None
    if job.state != MigrationState.FAILED.value:
        return False
    retention = timedelta(
        seconds=float(getattr(settings, "VALI_MIGRATION_SNAPSHOT_RETENTION_S", 3 * 86400.0))
    )
    return (
        vm.state != VmState.MIGRATING.value
        and job.finished_at is not None
        and timezone.now() - job.finished_at > retention
    )


def gc_migration_snapshots(*, limit: int = 20) -> int:
    """Janitor: delete the S3 snapshots of TERMINAL migrations that can no
    longer be needed. A snapshot is shared by every job naming its key (a
    re-drive reuses the failed job's), so it is deleted only when EVERY
    job naming it is terminal and retired (`_snapshot_retired`). Nothing is
    deleted for a job that is not terminal. At most `limit` deletions per
    pass; returns the number deleted."""
    candidates = (
        MigrationJob.objects.filter(
            state__in=[MigrationState.DONE.value, MigrationState.FAILED.value],
            snapshot_deleted_at__isnull=True,
        )
        .exclude(snapshot_key="")
        .order_by("finished_at")
    )
    deleted = 0
    seen: set[tuple[str, str]] = set()
    for job in candidates.iterator():
        if deleted >= limit:
            break
        ident = (job.snapshot_bucket, job.snapshot_key)
        if ident in seen:
            continue
        seen.add(ident)
        sharing = list(
            MigrationJob.objects.filter(
                snapshot_bucket=job.snapshot_bucket, snapshot_key=job.snapshot_key
            )
        )
        if all(
            _snapshot_retired(j, Vm.objects.filter(id=j.vm_id).first()) for j in sharing
        ) and _delete_migration_snapshot(job):
            deleted += 1
    return deleted


def _reclaim_one_source(job: MigrationJob) -> None:
    """Reclaim ONE completed migration's source artifacts, or leave them
    alone and say why. Never raises."""
    vm = Vm.objects.filter(id=job.vm_id).first()
    if vm is None:
        # The Vm row is gone entirely (hard delete). We cannot prove
        # anything about the destination — leave the source alone.
        _settle_source_reclaim(job, SourceReclaimState.SKIPPED, "vm-row-missing", loud=True)
        return

    # A VM whose §24 teardown already destroyed the KEK is unambiguously
    # safe: the source copy is inert ciphertext no key can ever open, and
    # there is no "only good copy" left to lose. Reclaim it — that is the
    # migrate-then-decommission case, where §24's destroy order only ever
    # reached the DESTINATION.
    dest_dead = vm.state == VmState.DESTROYED.value
    if job.kind == MigrationKind.FAILOVER.value and not _restore().source_back(job):
        # A failover's source is dead: its copy is reclaimed when it comes
        # back (the reappearance reconciliation), never given up on while
        # it is away.
        log.info(
            "source-reclaim: failover %s waits for its source %s to reappear",
            job.job_id,
            job.source_node_id,
        )
        return
    reason = (
        None if dest_dead else (_dest_unproven_reason(job, vm) or _dest_not_alive_reason(job, vm))
    )
    if reason is not None:
        age = (timezone.now() - (job.finished_at or job.started_at)).total_seconds()
        if age > _source_reclaim_proof_window():
            _settle_source_reclaim(
                job,
                SourceReclaimState.SKIPPED,
                f"dest-unproven:{reason}",
                loud=True,
            )
        else:
            log.info(
                "source-reclaim: migration %s waiting on dest proof (%s)",
                job.job_id,
                reason,
            )
        return

    try:
        if job.kind == MigrationKind.RESTORE.value:
            # The destination's `*.pre-restore-<id>` files (the original,
            # kept until now) and, when the restore moved hosts, the
            # source's copy. Under the job's row lock, re-checked: an
            # operator undo (`restore.start_undo`) that took the job since
            # it was listed wins, and one asked meanwhile waits for this
            # verdict (it refuses a reclaimed original).
            with transaction.atomic():
                locked = (
                    MigrationJob.objects.select_for_update()
                    .filter(
                        id=job.id,
                        state=job.state,
                        undo__isnull=True,
                        source_reclaim_state=SourceReclaimState.PENDING.value,
                    )
                    .first()
                )
                if locked is None:
                    return
                _restore().reclaim(job, vm)
                _settle_source_reclaim(
                    job,
                    SourceReclaimState.RECLAIMED,
                    "dest-proven" if not dest_dead else "vm-destroyed",
                )
        else:
            effects.dispatch_source_reclaim(
                vm, source_node_id=job.source_node_id, job_id=job.job_id
            )
    except EffectError as exc:  # `EffectUnavailable` is a subclass.
        # A dark source miner, or the miner refusing because the domain is
        # still up (the reboot-watcher race). Stay `pending` and retry.
        log.warning(
            "source-reclaim: migration %s could not reclaim source %s: %s",
            job.job_id,
            job.source_node_id,
            exc,
        )
        return
    _settle_source_reclaim(
        job,
        SourceReclaimState.RECLAIMED,
        "dest-proven" if not dest_dead else "vm-destroyed",
    )
    # The same proof retires the S3 snapshot: the destination runs it.
    _delete_migration_snapshot(job)
    log.info(
        "source-reclaim: migration %s reclaimed source %s for vm %s",
        job.job_id,
        job.source_node_id,
        vm.vm_id,
    )


def _settle_source_reclaim(
    job: MigrationJob, state: str, reason: str, *, loud: bool = False
) -> None:
    """Record the reclaim verdict. Filtered on `pending` so a concurrent
    tick cannot overwrite a settled one, and deliberately NOT a `version`
    bump: this field is bookkeeping, never read by a job CAS."""
    updated = MigrationJob.objects.filter(
        id=job.id, source_reclaim_state=SourceReclaimState.PENDING.value
    ).update(
        source_reclaim_state=state,
        source_reclaim_reason=reason[:256],
        source_reclaim_at=timezone.now(),
    )
    if updated and loud:
        log.error(
            "source-reclaim: migration %s NOT reclaiming source %s (%s) — the "
            "tenant's encrypted overlay, boot-counter disk and staged boot "
            "artifacts REMAIN on that host",
            job.job_id,
            job.source_node_id,
            reason,
        )


def _cold_retry_backoff() -> timedelta:
    return timedelta(
        seconds=float(getattr(settings, "VALI_MIGRATION_COLD_RETRY_BACKOFF_S", 6 * 3600.0))
    )


def _settle_cold(job: MigrationJob, reason: str, *, loud: bool = False) -> None:
    updated = MigrationJob.objects.filter(id=job.id, cold_settled_at__isnull=True).update(
        cold_settled_at=timezone.now(), cold_settle_reason=reason[:128]
    )
    if updated:
        (log.error if loud else log.info)(
            "cold-migration %s: vm %s settled (%s)", job.job_id, job.vm.vm_id, reason
        )


def settle_cold_migrations(*, limit: int = 10) -> int:
    """Return the VM of every TERMINAL cold migration to STOPPED — the state
    the tenant left it in. Returns the number of VMs stopped.

    - Done: only once the source was reclaimed, i.e. once the destination
      guest PROVED it runs (`_reclaim_one_source`) — stopping it earlier
      would also stop the proof. A destination never proven (`skipped`) is
      left running for an operator, loudly.
    - Failed: once the VM is back `Active` with no job driving it (restored
      to its source, or never fenced) — a VM still stranded `Migrating`
      waits for the stranded-migration sweep.
    A stop the power API refuses is retried on the next tick."""
    from .services import power

    stopped = 0
    jobs = MigrationJob.objects.filter(
        cold=True,
        cold_settled_at__isnull=True,
        state__in=[MigrationState.DONE.value, MigrationState.FAILED.value],
    ).select_related("vm")
    for job in jobs.iterator():
        if stopped >= limit:
            break
        vm = Vm.objects.filter(id=job.vm_id).first()
        if vm is None:
            _settle_cold(job, "vm-row-missing")
            continue
        if vm.state == VmState.DESTROYED.value:
            _settle_cold(job, "vm-destroyed")
            continue
        # The cold intent follows the VM's LATEST migration: a later (warm)
        # job that moved it again must itself finish — and prove its
        # destination — before the VM is stopped.
        ref = (
            MigrationJob.objects.filter(vm=vm, started_at__gte=job.started_at)
            .order_by("-started_at")
            .first()
        ) or job
        if ref.state not in (MigrationState.DONE.value, MigrationState.FAILED.value):
            continue
        if vm.state != VmState.ACTIVE.value or _has_active_job(vm):
            continue
        if (
            vm.power_state_at is not None
            and ref.finished_at is not None
            and (vm.power_state_at > ref.finished_at)
        ):
            # The power state moved after the migration ended — the tenant's
            # own call, not ours to undo. (Also true, harmlessly, when an
            # abandoned start marker is settled late: the VM is left running.)
            _settle_cold(job, "tenant-took-over")
            continue
        if ref.state == MigrationState.DONE.value:
            if ref.source_reclaim_state == SourceReclaimState.PENDING.value:
                continue  # destination not yet proven — keep it running
            if ref.source_reclaim_state == SourceReclaimState.SKIPPED.value:
                _settle_cold(job, "dest-never-proven:left-running", loud=True)
                continue
        if vm.power_state == VmPowerState.STOPPED:
            _settle_cold(job, "already-stopped")
            continue
        if vm.power_state != VmPowerState.RUNNING:
            continue  # a power op in flight — next tick
        try:
            power.stop_vm(vm)
        except power.PowerOpRefused as exc:
            log.info("cold-migration %s: stop refused (%s), retrying", job.job_id, exc.reason)
            continue
        except Exception as exc:  # noqa: BLE001 — one VM must not kill the sweep
            log.warning("cold-migration %s: stop failed: %s", job.job_id, exc)
            continue
        _settle_cold(
            job,
            "stopped-at-dest" if ref.state == MigrationState.DONE.value else "stopped-at-source",
        )
        stopped += 1
    return stopped


def reclaim_migrated_sources() -> int:
    """Reclaim the SOURCE artifacts of every completed §25 migration whose
    destination is proven good. Returns the number of jobs examined.

    Runs OUTSIDE the migration state machine, after `Done`, for one
    reason: the reclaim must never be able to hold a migration open. A
    source that cannot be proven safe to reclaim is a hygiene problem; a
    migration stuck short of `Done` is an availability problem. Modelling
    the reclaim as a required state would trade the second for the first.

    Fail-SAFE end to end — every path that is not a positive proof leaves
    the source artifacts exactly where they are.
    """
    if not _source_reclaim_enabled():
        return 0
    pending = list(
        MigrationJob.objects.filter(
            Q(state=MigrationState.DONE.value)
            # A restore that failed AFTER its commit point kept the original
            # on the destination; once the keep window is over it is
            # reclaimed on the same proof as a done one — the restored VM
            # proven on the destination and alive (an operator recovered
            # it), never before.
            | Q(
                state=MigrationState.FAILED.value,
                kind=MigrationKind.RESTORE.value,
                restore_keep_original_until__lt=timezone.now(),
            ),
            source_reclaim_state=SourceReclaimState.PENDING.value,
        ).select_related("vm")
    )
    for job in pending:
        try:
            _reclaim_one_source(job)
        except Exception:  # noqa: BLE001 — one job must not kill the sweep.
            log.exception("source-reclaim: unhandled error on migration %s", job.job_id)
    return len(pending)


# ─── §25 stranded-migration detection + recovery ─────────────────────
#
# A §25 migration that fails from `Quiescing` onward leaves the `Vm` row
# in `Migrating` with NO domain anywhere: the source guest was gracefully
# stopped (and signed its `stopped{}` ack), the destination never came
# up. Before this, that VM was outside EVERY automatic path —
# `reboot_recovery_once` iterates `Active` VMs, `reclaim_migrated_sources`
# iterates `Done` jobs, `sweep_guest_liveness` iterates `Active` VMs — and
# nothing logged it. A tenant's VM could sit down indefinitely, silently.
#
# THE CRUX: what a source restore has to do about the generation and the
# KBS. `kbs_activate_dest` moves the KBS `VmState` to
# `Migrating{old_gen, new_gen, source, dest}`, and from that instant
# `kbs_core::lifecycle::check_releasable` releases the KEK to `(new_gen,
# dest-chip)` and to NOTHING else — the source at `source_gen` is denied
# forever. That is not a soft fence vali can lift: the KBS admin surface
# has exactly three lifecycle writes (`register-vm`, `activate`,
# `seed-boot-counter`), `activate` is forward-only (it only ever moves the
# fence to a strictly higher generation, never back to `source_gen`), and
# `register-vm` on a divergent state is a 409-with-no-write. There is NO
# route from `Migrating` back to `Active{source}`.
#
# So the answer to "what does a source restore do about the generation"
# is: it is only ever legal BEFORE the KBS moved. Two disjoint classes:
#
#  (a) the job never entered `DestActivating` — the KBS is still
#      `Active{source_gen, source}`, the source is the ONLY host that can
#      unlock, and the destination was never even told to restore
#      (`dispatch_migrate_activate` also only runs in that state). Flipping
#      vali's row back to `Active{source_gen, source}` makes vali's intent
#      agree with the KBS's authoritative state. It cannot create a
#      split-brain, because the fence that prevents one is the KBS state
#      itself and that state has not moved: a destination guest, even a
#      malicious miner's, has no ticket at `source_gen` bound to its own
#      chip and `check_releasable` compares the ATTESTED chip against the
#      bound host. The restored VM then falls to reboot-recovery, which
#      relaunches it on the source at the same generation.
#
#  (b) the job reached `DestActivating` — the KBS is committed to
#      `(new_gen, dest)`. A "source restore" here would un-fence a guest
#      that can never obtain its KEK: it would boot, hang in its
#      initramfs, burn the relaunch budget, and — worse — leave vali
#      claiming `Active{source}` while the KBS says the destination owns
#      the VM, so a destination that later recovered would activate at
#      `new_gen` behind vali's back. The ONLY recovery is forward: re-drive
#      the SAME destination at the SAME `new_gen`. That is an operator
#      action (`vali_migration_recover --action redrive-dest`), never
#      automatic — the destination has already failed once.
#
# Everything below is the machinery for telling (a) from (b) with
# POSITIVE evidence, and failing closed into (b) whenever it cannot.

#: The migration states that run BEFORE `effects.kbs_activate_dest` can
#: possibly have been called. A job that failed in one of these PROVABLY
#: never moved the KBS: `_h_mig_dest_activating` is the sole caller, the
#: state is entered only through a durable `_cas_migration`, and this
#: field is written by `_fail_migration` from `job.state` at that moment.
_PRE_KBS_ACTIVATION_STATES: frozenset[str] = frozenset(
    {
        MigrationState.SOURCE_STARTING.value,
        MigrationState.DRAINING.value,
        MigrationState.QUIESCING.value,
        MigrationState.SNAPSHOTTING.value,
        MigrationState.UPLOADING.value,
        MigrationState.FENCING.value,
        MigrationState.AWAITING_SOURCE_ACK.value,
    }
)

#: Verdict actions. `restore-source` is the only one the sweep ever acts
#: on automatically.
STRAND_RESTORE_SOURCE = "restore-source"
STRAND_REDRIVE_DEST = "redrive-dest"
STRAND_BLOCKED = "blocked"


@dataclass(frozen=True)
class StrandVerdict:
    """What may be done about one stranded VM, and on what evidence.

    `action` is one of [`STRAND_RESTORE_SOURCE`], [`STRAND_REDRIVE_DEST`],
    [`STRAND_BLOCKED`]; `reason` is a short, log-safe, operator-facing
    explanation. Shared by the tick sweep and the operator command so
    there is ONE evidence rule — the operator cannot reach a restore the
    sweep would refuse.
    """

    action: str
    reason: str

    @property
    def restorable(self) -> bool:
        return self.action == STRAND_RESTORE_SOURCE


def _strand_restore_max_failures() -> int:
    """How many FAILED migrations a VM may accumulate before the sweep
    stops restoring it automatically.

    The loop this bounds is real. An `AwaitingSourceAck` timeout
    §13-QUARANTINES the source, and `enroll_departing_miner_migrations`
    auto-enrols a fresh migration for every `Active` VM on a quarantined
    miner. So a restore hands the VM straight back to a migration that
    may fail the same way — each cycle costing an ack timeout and a
    full snapshot upload, forever, if the underlying fault persists.

    That direction is CORRECT (a VM on a departing miner should keep
    trying to leave) which is why the cap is generous rather than one,
    and why it gates only the AUTOMATIC action: the verdict is about
    SAFETY, this is about not spinning. Past the cap the VM is reported
    with a distinct reason and an operator decides — including by
    running the same restore explicitly, which the command still allows
    because a human has looked at it.
    """
    return int(getattr(settings, "VALI_MIGRATION_STRAND_MAX_FAILURES", 3))


def _strand_restore_enabled() -> bool:
    """Master switch for the AUTOMATIC source restore. Default ON: the
    evidence gate is the safety, and a default-off flag is how this repo
    repeatedly ends up with a fix that is merged, believed live, and
    doing nothing. Detection is unconditional either way."""
    return bool(getattr(settings, "VALI_MIGRATION_STRAND_RESTORE_ENABLED", True))


def stranded_migrations() -> list[tuple[Vm, MigrationJob | None]]:
    """Every VM stuck in `Migrating` with NO migration still driving it.

    "No live job" is the whole definition: a `Migrating` VM is legitimate
    for exactly as long as a non-terminal `MigrationJob` owns it. The
    partial unique index allows at most one, so the moment that job goes
    `Failed` (or `Done` without activating, or the row is gone) the VM is
    fenced with nobody responsible for it.

    Returns `(vm, latest_terminal_job_or_None)` pairs.
    """
    pairs: list[tuple[Vm, MigrationJob | None]] = []
    for vm in Vm.objects.filter(state=VmState.MIGRATING).iterator():
        jobs = list(MigrationJob.objects.filter(vm=vm).order_by("-started_at"))
        if any(j.state not in TERMINAL_MIGRATION_STATES for j in jobs):
            continue  # a live migration owns this VM — not stranded
        pairs.append((vm, jobs[0] if jobs else None))
    return pairs


def _dest_activation_veto(job: MigrationJob, vm: Vm) -> str | None:
    """`None` iff NOTHING in vali's own durable records suggests the
    migration ever reached `DestActivating`; otherwise the reason it may
    have.

    Every check here is a VETO — it can only BLOCK a source restore,
    never authorise one — which is why each may lean on evidence too weak
    to permit with. Ordered cheapest-first, and all local (no KBS call):

    1. `failed_from_state` — the authoritative record, written by
       `_fail_migration` from `job.state`.
    2. the `reason` PREFIX. `_fail_migration` builds it as
       `f"{job.state}:{…}"`, so a job that predates `failed_from_state`
       still names its state here. Free text, hence veto-only.
    3. an `OrderTicketIntake` at `new_gen`. `remint_dest_ticket` mints
       one only from `effects.dispatch_migrate_activate`, which runs AFTER
       `kbs_activate_dest` in the same state; a relaunch records one at
       the VM's generation, which reaches `new_gen` only once an activate
       did. Either way the row means the KBS activate had succeeded.
    4. the §14 idempotency markers for the two `DestActivating` effects.
       `_guarded` records AFTER the effect, so ABSENCE proves nothing
       (which is exactly why absence is not a permit); PRESENCE proves
       the effect ran. A store that cannot be read is itself a veto —
       an unverifiable input is never a pass.
    """
    if job.failed_from_state == MigrationState.DEST_ACTIVATING.value:
        return "failed-from-dest-activating"
    prefix = (job.reason or "").split(":", 1)[0].strip()
    if prefix == MigrationState.DEST_ACTIVATING.value:
        return "reason-names-dest-activating"

    from apps.orders.models import OrderTicketIntake

    if OrderTicketIntake.objects.filter(vm_id=vm.vm_id, vm_generation=job.new_gen).exists():
        return "dest-ticket-minted-at-new-gen"

    for step in ("dest-activating", "dispatch-migrate-activate"):
        try:
            if idempotency.recall(_mig_key(job, step)) is not None:
                return f"idempotency-marker:{step}"
        except IdempotencyUnavailable:
            return "idempotency-store-unreadable"
    return None


def _kbs_grant_veto(job: MigrationJob, vm: Vm) -> str | None:
    """`None` iff the KBS's latest recorded grant for this VM is one only
    the SOURCE could have obtained; otherwise the reason it is not.

    This is the direct, KBS-side check for "did the destination actually
    unlock?" — the split-brain case. It is the same proof discipline
    `_dest_unproven_reason` (#936) uses for the reclaim decision, pointed
    the other way: there, a grant AT the destination authorises deleting
    the source copy; here, a grant anywhere but the source FORBIDS
    restoring it.

    The bundle exists only because the KBS GRANTED a release against a
    VCEK-chained SNP report, vali reads it DIRECTLY off the KBS admin
    listener (the untrusted miner is not on that path), and the
    `ticket_id` it names is re-checked against vali's OWN
    `OrderTicketIntake` rather than the bundle's summary fields.

    Absence is AMBIGUOUS, as always — the KBS evidence sink is an
    emptyDir, so a KBS restart erases bundles. Absence is therefore NOT a
    veto: it neither proves nor disproves anything, and the permit this
    guards rests on `failed_from_state`, not on this. Anything that is
    present but not the source's own grant, and any failure to READ the
    KBS, IS a veto.
    """
    from .services import kbs_evidence

    try:
        bundle = kbs_evidence.fetch_evidence(vm.vm_id)
    except EffectError:  # `EffectUnavailable` is a subclass.
        return "kbs-evidence-unreadable"
    if bundle is None:
        return None  # ambiguous — see the docstring
    ticket_id = str(bundle.get("ticket_id") or "")
    if not ticket_id:
        return "evidence-without-ticket-id"

    from apps.orders.models import OrderTicketIntake

    intake = OrderTicketIntake.objects.filter(ticket_id=ticket_id).first()
    if intake is not None:
        grant = (intake.vm_id, intake.vm_generation, intake.node_id)
    else:
        grant = _launch_ticket_grant(ticket_id)
        if grant is None:
            return "evidence-ticket-unknown-to-vali"
    vm_id, generation, node_id = grant
    if vm_id != vm.vm_id:
        return "evidence-ticket-other-vm"
    if generation != job.source_gen:
        return f"evidence-generation:{generation}!={job.source_gen}"
    if node_id != job.source_node_id:
        return f"evidence-grant-off-source:{node_id or '(none)'}"
    return None


def _launch_ticket_grant(ticket_id: str) -> tuple[str, int, str] | None:
    """`(vm_id, generation, node_id)` of a ticket a SUCCEEDED launch minted
    — vali's own record of it for VMs launched before `launch_on_miner`
    wrote an `OrderTicketIntake` (those carry the ticket only in the
    job's result). A launch mints at the launch generation."""
    from .models import LaunchJob, LaunchJobState
    from .services.launch import _LAUNCH_GENERATION

    job = (
        LaunchJob.objects.filter(
            state=LaunchJobState.SUCCEEDED.value, result_json__ticket_id=ticket_id
        )
        .only("vm_id", "result_json")
        .first()
    )
    if job is None:
        return None
    return job.vm_id, _LAUNCH_GENERATION, str((job.result_json or {}).get("miner_id") or "")


def stranded_recovery_verdict(vm: Vm, job: MigrationJob | None) -> StrandVerdict:
    """Classify one stranded VM. Fail-CLOSED: every path that is not a
    positive proof returns [`STRAND_BLOCKED`] or [`STRAND_REDRIVE_DEST`],
    and only an unbroken chain of positives returns
    [`STRAND_RESTORE_SOURCE`].
    """
    if vm.state != VmState.MIGRATING.value:
        return StrandVerdict(STRAND_BLOCKED, f"vm-not-migrating:{vm.state}")
    if job is None:
        # No job to reason from: we cannot tell whether the KBS moved, and
        # we do not know which host is the source. Operator-only.
        return StrandVerdict(STRAND_BLOCKED, "no-migration-job")
    if job.kind != MigrationKind.MIGRATE.value:
        # A restore / failover fences the VM for its own reasons: a failure
        # before its commit point reverts on its own, so a VM left fenced
        # behind one is a failed revert or a failure after the commit point.
        # Neither the source restore nor the §25 re-drive applies (there is
        # no snapshot, and the original may be an older state) — operator.
        return StrandVerdict(STRAND_BLOCKED, f"{job.kind}-job:{job.reason or job.state}"[:180])
    if job.state != MigrationState.FAILED.value:
        return StrandVerdict(STRAND_BLOCKED, f"job-not-failed:{job.state}")
    # The VM must be fenced for THIS job, on the source, at the source
    # generation. Anything else and the row we are about to un-fence is not
    # the one this job fenced.
    if vm.migration_dest != job.dest_node_id or vm.new_generation != job.new_gen:
        return StrandVerdict(
            STRAND_BLOCKED,
            f"fenced-for-another-migration:{vm.migration_dest or '(none)'}",
        )
    if vm.generation != job.source_gen:
        return StrandVerdict(STRAND_BLOCKED, f"vm-generation:{vm.generation}!={job.source_gen}")
    if vm.host != job.source_node_id:
        return StrandVerdict(STRAND_BLOCKED, f"vm-not-on-source:{vm.host or '(none)'}")

    veto = _dest_activation_veto(job, vm)
    if veto is not None:
        return StrandVerdict(STRAND_REDRIVE_DEST, veto)
    if job.failed_from_state not in _PRE_KBS_ACTIVATION_STATES:
        # Unrecorded (every job that predates the column) or a state we do
        # not recognise. We cannot PROVE the KBS never moved, so no restore.
        return StrandVerdict(
            STRAND_BLOCKED,
            f"unknown-failure-state:{job.failed_from_state or '(unrecorded)'}",
        )
    # About to permit — spend the one remote call on the strongest,
    # most independent check there is.
    kbs_veto = _kbs_grant_veto(job, vm)
    if kbs_veto is not None:
        return StrandVerdict(STRAND_REDRIVE_DEST, kbs_veto)
    return StrandVerdict(
        STRAND_RESTORE_SOURCE, f"never-reached-dest-activating:{job.failed_from_state}"
    )


def restore_source_vm(vm: Vm, job: MigrationJob) -> bool:
    """Un-fence `vm` back to `Active{source_gen, source}`. Returns `True`
    iff the CAS won.

    NOT a §24/§25 state-machine transition, and deliberately not routed
    through `lifecycle.state_machine`: that table rejects
    `Migrating → Active(old_gen)` because, for a migration that COMMITTED
    to a new generation, the old one is burned. This runs only where the
    caller has PROVEN the migration never committed — the KBS never left
    `Active{source_gen, source}` — so there is no burned generation and
    nothing to roll back. The transition table stays exactly as strict for
    the API surface it guards.
    """
    now = timezone.now()
    with transaction.atomic():
        updated = Vm.objects.filter(
            id=vm.id,
            version=vm.version,
            state=VmState.MIGRATING.value,
            # Pinned in the WHERE, not merely checked in Python: the row
            # must still be the exact one the verdict was computed against.
            host=job.source_node_id,
            generation=job.source_gen,
            migration_dest=job.dest_node_id,
            new_generation=job.new_gen,
        ).update(
            state=VmState.ACTIVE.value,
            migration_dest="",
            new_generation=None,
            # `boot_phase` stays as `_fence_vm` left it (empty): the guest
            # IS down, and reboot-recovery is what brings it back.
            # `eol_nonce` stays too — it is the launch-baked, measured
            # value the guest still signs with.
            # `boot_started_at` is NOT restarted: nothing here proves the
            # source guest is down (the job may have failed before or after
            # the quiesce reached it), so this is not a new boot. The
            # reboot-recovery relaunch that brings a down guest back stamps
            # it. Until then the old boot's signals keep it out of
            # `boot_stalled`; a silent source reads `wedged` instead.
            version=vm.version + 1,
        )
        if updated == 0:
            return False
        # #936 INTERACTION — the source is now the VM's ONLY copy, so its
        # artifacts must never be reclaimed. `reclaim_migrated_sources`
        # already cannot touch this job (it filters `state=Done`), but
        # record the verdict explicitly so the intent survives any future
        # widening of that sweep. `skipped` is the strictly SAFER value:
        # it is the terminal that never dispatches a destroy.
        _settle_source_reclaim(job, SourceReclaimState.SKIPPED, "source-restored", loud=False)
        MigrationJob.objects.filter(
            id=job.id, strand_recovery_state=StrandRecoveryState.NONE.value
        ).update(
            strand_recovery_state=StrandRecoveryState.SOURCE_RESTORED.value,
            strand_recovery_at=now,
            strand_recovery_reason=f"restored to {job.source_node_id} at gen {job.source_gen}"[
                :256
            ],
        )
    return True


# In-process memo for the stranded-VM alarm: `(ids, warned_at)`. The
# condition is PERMANENT until an operator acts and the tick runs every
# ~10 s, so an unthrottled line would emit thousands of identical errors
# a day. Re-warn when the SET changes or the interval lapses.
_strand_warn_memo: tuple[frozenset[str], float] = (frozenset(), 0.0)


def _strand_warn_interval_s() -> float:
    return float(getattr(settings, "VALI_MIGRATION_STRAND_WARN_INTERVAL_S", 900))


def sweep_stranded_migrations() -> int:
    """Detect — and where PROVABLY safe, recover — every VM stranded in
    `Migrating`. Returns the number of stranded VMs SEEN (the tick
    counter), not the number recovered.

    Detection is unconditional and always runs. Recovery is the automatic
    source restore, and ONLY for the class where the KBS provably never
    moved; everything else is surfaced at ERROR with the action an
    operator must take. Never raises.
    """
    global _strand_warn_memo

    pairs = stranded_migrations()
    if not pairs:
        _strand_warn_memo = (frozenset(), time.monotonic())
        return 0

    restore_enabled = _strand_restore_enabled()
    outstanding: list[str] = []
    for vm, job in pairs:
        try:
            verdict = stranded_recovery_verdict(vm, job)
        except Exception:  # noqa: BLE001 — one VM must not kill the sweep.
            log.exception("stranded-migration: verdict failed for vm=%s", vm.vm_id)
            verdict = StrandVerdict(STRAND_BLOCKED, "verdict-error")
        if verdict.restorable and restore_enabled and job is not None:
            failures = MigrationJob.objects.filter(
                vm_id=vm.id,
                state=MigrationState.FAILED.value,
                kind=MigrationKind.MIGRATE.value,
            ).count()
            if failures > _strand_restore_max_failures():
                # Safe, but not automatically — see `_strand_restore_max_
                # failures`. Reported with its own reason so it reads as
                # "a human must look", not as "unsafe".
                outstanding.append(
                    f"{vm.vm_id}[{verdict.action}:capped-after-{failures}-failed-migrations]"
                )
                continue
            try:
                if restore_source_vm(vm, job):
                    log.warning(
                        "stranded-migration: vm=%s RESTORED to source %s at "
                        "generation %d (%s) — migration %s failed before the "
                        "KBS was ever moved, so the source is still the only "
                        "host that can unlock it; reboot-recovery now owns "
                        "bringing the guest back up",
                        vm.vm_id,
                        job.source_node_id,
                        job.source_gen,
                        verdict.reason,
                        job.job_id,
                    )
                    continue
                verdict = StrandVerdict(STRAND_BLOCKED, "restore-cas-lost")
            except Exception:  # noqa: BLE001 — never let a restore kill the tick.
                log.exception("stranded-migration: restore failed for vm=%s", vm.vm_id)
                verdict = StrandVerdict(STRAND_BLOCKED, "restore-error")
        elif verdict.restorable and not restore_enabled:
            verdict = StrandVerdict(STRAND_BLOCKED, "restore-disabled")
        outstanding.append(f"{vm.vm_id}[{verdict.action}:{verdict.reason}]")

    if outstanding:
        ids = frozenset(outstanding)
        last_ids, last_at = _strand_warn_memo
        now = time.monotonic()
        if ids != last_ids or (now - last_at) >= _strand_warn_interval_s():
            _strand_warn_memo = (ids, now)
            shown = sorted(ids)[:20]
            log.error(
                "stranded-migration: %d VM(s) are FENCED in `migrating` with a "
                "terminal migration job and NO domain on either host — they are "
                "DOWN and outside every automatic sweep (reboot-recovery scans "
                "`active` only). Recovery is `manage.py vali_migration_recover "
                "--vm-id <id>` (dry-run by default): %s%s",
                len(ids),
                ", ".join(shown),
                "" if len(shown) == len(ids) else f" (+{len(ids) - len(shown)} more)",
            )
    return len(pairs)


def _billing_cutover_unix(job: MigrationJob) -> int:
    """The instant the DESTINATION becomes the miner paid for this VM.

    `job.phase_started_at` — when the job entered `DestActivating` — and
    not "now", because it is the one timestamp that provably lies in the
    migration's DEAD ZONE, the interval in which NEITHER host is serving:

      * it is AFTER the source guest stopped. `DestActivating` is entered
        only from `AwaitingSourceAck`, on a VERIFIED guest-signed
        `stopped{}` ack — the source's own attestation that it powered
        off. Everything the source served, including the receipts its
        agent drains during that shutdown, has a `period_end` before it.
      * it is BEFORE the destination started. `dispatch_migrate_activate`
        — the first thing that tells the dest to restore and boot — runs
        in the FIRST tick of `DestActivating`, i.e. after this stamp;
        `_cas_migration` sets `phase_started_at` only on a state CHANGE,
        so the polling ticks that follow never move it forward past the
        dest's boot. And the dest guest's first receipt window opens at
        its own agent start (`genesis_period_start`), which is after that
        boot.

    That is what makes a single `effective_from` honest rather than a
    rounding choice: no receipt window can STRADDLE this instant, so
    every receipt falls entirely on one side and is credited whole to the
    host that actually served it. Using "now" (the activation CAS) would
    put the cutover AFTER the destination had already booted and begun
    emitting receipts, handing the destination's first window to the
    source; using the fence would put it BEFORE the source stopped,
    handing the source's last windows to the destination.
    """
    if job.kind != MigrationKind.MIGRATE.value:
        # A restore / failover activates the VM from `RestoreVerifying`, not
        # from the state it booted the destination in. Its dead zone begins
        # when the source domain was confirmed down (the instant recorded on
        # its authorization), before the destination was asked to boot.
        down = _restore().activation_started_at(job)
        if down is not None:
            return int(down.timestamp())
    return int(job.phase_started_at.timestamp())


def _dest_chain_node_id(job: MigrationJob) -> str:
    """The destination's 64-hex chain `node_id` — the identity the
    `UsageAccrual` ledger (and the on-chain epoch weight) is keyed by.

    `job.dest_node_id` is the human `miner_id` (`Vm.host`); the ledger
    speaks chain ids, so this is the same join the launch path does.
    Returns `""` when the dest has no registered `chain_node_id`, which
    [`_activate_dest_vm`] records as UNATTRIBUTABLE custody — vali cannot
    name the miner now running the VM, so it credits nobody rather than
    keep paying the source for a workload it no longer runs.
    """
    from apps.miners.models import MinerIdentity

    return (
        MinerIdentity.objects.filter(miner_id=job.dest_node_id)
        .values_list("chain_node_id", flat=True)
        .first()
        or ""
    )


def _activate_dest_vm(job: MigrationJob) -> None:
    """§25 step 7 — CAS the `Vm` `Migrating → Active{new_gen, dest}`.
    Reached only after a verified source-stopped ack. Idempotent.

    Also moves the BILLING CUSTODY and the §23 PLACEMENT CUSTODY to the
    destination, and RE-SCOPES the VM's reboot-recovery bookkeeping to it,
    in the SAME transaction as the CAS — `Vm.host`, the miner that gets
    paid, the miner the scheduler believes holds the VM, and the host the
    relaunch cap is counted against either all move or none of them do.

    Uptime billing is armed
    (`VALI_EPOCH_WEIGHT_SOURCE=usage` feeds real on-chain epoch weight),
    and the miner credited for a VM's uptime must be the miner running
    it: without this the source keeps being paid for a workload the
    destination is doing, for the rest of the VM's life.

    The VM's `VmBillingBinding` is deliberately NOT re-pointed here. That
    row is the identity the GUEST declares, which it reads from its
    SNP-measured cmdline — carried to the destination verbatim, because
    rewriting it would change the measurement and the dest would never
    unlock. A migrated guest keeps declaring its launch node in both its
    served receipts and its KBS-signed live attestations, so re-pointing
    the binding would make both fail their match and bill NOTHING.
    """
    vm = Vm.objects.get(id=job.vm_id)
    if vm.state == VmState.ACTIVE and vm.generation == job.new_gen and vm.host == job.dest_node_id:
        return  # already activated
    if vm.state != VmState.MIGRATING:
        raise EffectError(f"vm is {vm.state!r}, not Migrating — cannot activate dest")
    # Defense-in-depth: the VM must be fenced for THIS job — same
    # destination + new generation. Refuse to activate over a
    # Migrating row that belongs to a different migration, and pin
    # the same fields in the CAS filter so the UPDATE itself rejects
    # a mismatch.
    if vm.migration_dest != job.dest_node_id or vm.new_generation != job.new_gen:
        raise EffectError(
            "vm is fenced for a different migration "
            f"(dest={vm.migration_dest!r}, new_gen={vm.new_generation}) "
            "— refusing to activate"
        )
    with transaction.atomic():
        updated = Vm.objects.filter(
            id=vm.id,
            version=vm.version,
            state=VmState.MIGRATING.value,
            migration_dest=job.dest_node_id,
            new_generation=job.new_gen,
        ).update(
            state=VmState.ACTIVE.value,
            generation=job.new_gen,
            host=job.dest_node_id,
            migration_dest="",
            new_generation=None,
            # The destination's boot is the VM's current boot.
            boot_started_at=timezone.now(),
            # MOP UP the source's late `running` — see
            # `_mop_up_boot_phase` for why only that value, and why the
            # decision is made INSIDE this UPDATE rather than from the row
            # read above.
            **_mop_up_boot_phase(),
            #
            # `netbird_ip` is deliberately NOT cleared. Not because the IP
            # is guaranteed to survive — it is not for a VM launched before
            # tenant peers became persistent: its setup key was minted
            # `ephemeral: True`, and NetBird's management GCs an
            # ephemeral peer after ~10 min offline, which a cold migration
            # can exceed. The dest cannot re-enrol either (cloud-init
            # re-runs the `runcmd` with the launch-time key, which is
            # `usage_limit=1` and already consumed).
            #
            # It is preserved because CLEARING IS STRICTLY WORSE:
            # `_advance_tenant_vm_boot_progress` only re-resolves the IP
            # while the VM is under 30 minutes old
            # (`_NETBIRD_RESOLVE_WINDOW`), and every migration candidate is
            # older than that — so a cleared field would be permanently
            # blank with no self-heal, where a stale one is at least right
            # whenever the peer did survive. §25 still does not RE-ENROL
            # the destination; what it now does is make the loss VISIBLE —
            # `**_netbird_verify_marker()` arms the post-migration sweep
            # below so the row can no longer read `Active` + a stale
            # `netbird_ip` while the tenant is off the overlay.
            **_netbird_verify_marker(),
            # eol_nonce PRESERVED — the migrated guest is LIVE again at
            # new_gen booting the SAME measured cmdline, so its baked
            # `hippius.eol_nonce` is UNCHANGED. Clearing the Vm field here
            # would break every FUTURE EOL ack of this VM: a re-migration
            # (`start_migration` requires eol_nonce → `no-eol-nonce`) AND a
            # clean §24 decommission (`_verify_ack` reads the Vm nonce → an
            # empty one fails → the slow forced-reclaim instead of the
            # graceful path). The COLD-migration nonce is per-VM-for-life
            # (never re-delivered to a running guest); the per-generation
            # replay guard is the GENERATION + the KBS fence, not the nonce.
            # Only `_destroy_vm` (the permanent tombstone) clears it.
            version=vm.version + 1,
        )
        if updated == 0:
            raise EffectError("vm changed concurrently during dest activation")
        # §25 BILLING CUSTODY — INSIDE the CAS transaction, and only on the
        # branch where the CAS actually won.
        #
        # Inside, because `Vm.host` and "the miner we pay" must never
        # disagree: a second, later write would open a window in which the
        # destination runs the VM while the ledger still credits the
        # source, and every receipt metered in that window would be
        # mis-paid. There is no compensating action for an on-chain epoch
        # weight that has already been submitted.
        #
        # Only on the winning branch, because a LOST CAS means this tick
        # did not activate anything — a concurrent tick did, or the row
        # moved under us. Recording custody there would hand the
        # destination a VM that may never have been activated. A failed or
        # aborted migration reaches neither statement: every earlier
        # failure path returns/raises before the CAS, and the §25
        # split-brain gate refuses `DestActivating` outright without a
        # verified source ack.
        #
        # Append-only and append-if-changed, so the re-drive that finds
        # the VM already activated (the early return above) and the
        # reboot-recovery relaunch (same host) both record nothing.
        from apps.scheduler import billing
        from apps.scheduler.models import VmBillingAssignment

        dest_chain_node_id = _dest_chain_node_id(job)
        if not dest_chain_node_id:
            # Cannot NAME the miner now running the VM. Recorded as
            # UNATTRIBUTABLE rather than left pointing at the source: the
            # activation must not be blocked (the tenant's VM is up), but
            # nobody may be paid for work the source is not doing.
            log.error(
                "migration %s: dest %s has no chain_node_id — recording "
                "UNATTRIBUTABLE billing custody for vm %s (nobody is "
                "credited for its uptime until the dest registers one)",
                job.job_id,
                job.dest_node_id,
                vm.vm_id,
            )
        billing.record_assignment(
            vm_id=vm.vm_id,
            node_id_hex=dest_chain_node_id,
            at_unix=_billing_cutover_unix(job),
            reason=VmBillingAssignment.MIGRATION,
        )
        # §23 PLACEMENT CUSTODY — same transaction, same winning branch,
        # for the same reason: `Vm.host` and the miner the §23 ledger says
        # holds the VM must never disagree. `Placement` was ALSO written
        # only by the launch path, so the source kept the VM on its books
        # forever — its slot AND its RAM/CPU counted against the source in
        # `decision_inputs` (so the DESTINATION looked emptier than it was
        # to the #668 fit gate and could be oversubscribed), the `snapshot`
        # reward source paid the source, and — the operational one — a
        # miner asking to leave cleanly was drained by BOUND placement, so
        # the destination's migrated-in VMs were never enrolled.
        #
        # The one deliberate ASYMMETRY with the billing block above: an
        # unnameable destination is recorded UNATTRIBUTABLE for BILLING
        # (pay nobody) but moves NOTHING here. "Count nobody" is not the
        # safe direction for capacity — a VM with no active placement is
        # invisible to the fit gate, and the destination could then be
        # oversubscribed by exactly this VM (the #939 hazard by another
        # route). Wrong-miner accounting is bounded; missing accounting is
        # not.
        from apps.scheduler.service import (
            PlacementMoveConflict,
            move_placement_to_node,
        )

        try:
            move_placement_to_node(
                vm,
                node_id=dest_chain_node_id,
                decided_by=job.decided_by,
                reason=f"migrated:{job.job_id}",
                # The §25 destination's KEK release at `new_gen`
                # (`effects.kbs_activate_dest`) happened earlier in THIS
                # state, and the dest reported its restore/boot `done` —
                # the same evidence `/bind` records for a launch-time
                # placement, which is why the new row opens `Bound` rather
                # than `Pending`.
                release_ref=f"migration:{job.job_id}",
                # A resize that migrates holds its new size on the
                # destination from this instant (`ResizeJob`).
                resource_class=job.resize_to_flavor,
            )
        except PlacementMoveConflict as exc:
            # A concurrent writer held the VM's active placement. Surfaced
            # as a RETRYABLE step failure so the whole transaction — the
            # `Vm.host` CAS included — rolls back and the next tick
            # re-drives the activation. Half-moving custody is the one
            # outcome this must never produce.
            raise EffectError(str(exc)) from exc
        # REBOOT-RECOVERY SCOPE — same transaction, same winning branch,
        # for the same reason as the two blocks above: `RebootRecovery`
        # holds HOST-scoped state (the relaunch cap, the backoff window,
        # the down/wedged debounces) and no migration path touched it, so
        # a VM that burned its relaunch budget on a flaky SOURCE arrived
        # at a healthy DESTINATION already at the cap and could never be
        # reboot-recovered there. Inside the CAS so `Vm.host` and the
        # counters can never disagree — and because the version bump this
        # writes is what FENCES a reboot-recovery tick that read the row
        # before the move and would otherwise aim its relaunch at the
        # source. `seen_running` is preserved (it is a fact about the
        # VM's past, not host-scoped policy — see the model docstring).
        rescope_reboot_recovery_to_host(vm, new_host=job.dest_node_id)


def _decommission_vm(job: DecommissionJob) -> None:
    """§24 — CAS the `Vm` `Active → Decommissioning` (the
    `ticket_frozen` commit point). Idempotent.

    §24/§25 GAP-3 — the EOL nonce is NOT (re-)minted here. Exactly like a
    §25 migration, the decommissioning guest signs its `stopped{}` ack
    from its ALREADY-BAKED, MEASURED cmdline (`hippius.eol_nonce`), which
    `launch.launch_on_miner` set at launch AND persisted onto
    `Vm.eol_nonce`. Re-minting at decommission would hand `_verify_ack` a
    nonce the running guest never saw → fail closed → the §24 destroy
    could never commit on a verified ack. The nonce is PRESERVED; the
    generation + the KBS crypto-erase are the §24 finality guards.

    ## The no-nonce precondition, and its ONE exception

    A missing `eol_nonce` normally means the guest's stopped-ack could
    never verify, so freezing the ticket would start a teardown that can
    only end in a forced reclaim — refuse it. But it has a second reading,
    and for one shape of VM it is the ONLY one: the nonce is baked +
    persisted at launch step 4b, BEFORE the preflight, the KBS register
    and the dispatch, so its ABSENCE proves no measured cmdline was ever
    built for this vm_id ([`cmdline_was_baked`]) — there is provably no
    guest, because there was never even a dispatch. Demanding an ack from
    it is demanding a signature from something that does not exist.

    Refusing that VM is not "fail closed", it is a DEADLOCK: a launch
    refused at placement leaves the row `state=active` with a live per-VM
    Vault-Transit KEK, and this refusal is what makes §24 — the only
    automated path that erases a KEK — decline to run on it. Live on
    2026-08-13, `vm-fedora-3`: `no-eligible-miner`, no host, no nonce,
    a `failed` DecommissionJob and a LIVE `transit/keys/kek-vm-fedora-3`.

    ⛔ NOT relaxed for a VM that ran. The exception is ANDed with
    [`never_ran_veto`] — the same predicate #968's ack shortcut uses — so
    it clears only when `vm.host` is empty, no boot milestone landed, no
    guest ever signalled, `seen_running` was never set, the generation is
    still 1, no launch is in flight or ever succeeded, no placement is
    active, the launch is positively marked abandoned, and either the
    miner affirmatively reports no live domain or no miner was ever
    chosen. A VM that DID run keeps its nonce anyway, so it never reaches
    this branch at all; if one somehow arrived here without a nonce (a
    malformed operator-supplied nonce token skips the persist while the
    launch proceeds), every one of those checks still refuses it.

    Ordering is unchanged and stays load-bearing: this CAS moves the row
    Active→**Decommissioning** — a fence, not a tombstone. The KEK is
    destroyed later, in `CryptoErasing`, and only THEN does `_destroy_vm`
    tombstone the row. Nothing here tombstones a VM whose KEK is live.
    """
    vm = Vm.objects.get(id=job.vm_id)
    if vm.state in (VmState.DECOMMISSIONING, VmState.DESTROYED):
        return  # ticket already frozen
    if vm.state != VmState.ACTIVE:
        raise EffectError(f"vm is {vm.state!r}, not Active — cannot decommission")
    if not vm.eol_nonce:
        veto = never_ran_veto(vm)
        if veto is not None:
            # Fail closed: a decommission whose stopped-ack can never verify
            # (the launch baked a nonce the row lost, or a guest may be alive)
            # must not freeze the ticket.
            raise EffectError(
                "vm has no eol_nonce (launch did not bake hippius.eol_nonce) "
                f"and vali cannot prove no guest was ever created ({veto}) "
                "— cannot decommission a vm whose stopped-ack can never verify"
            )
        log.warning(
            "decommission %s: vm %s has no eol_nonce because NO measured "
            "cmdline was ever baked for it (launch %r gave up before step 4b, "
            "so it never registered and never dispatched) — freezing the "
            "ticket anyway. There is no guest to ack: the ack requirement is "
            "vacuous here, not waived. Its live per-VM Vault-Transit KEK is "
            "erased by `CryptoErasing` BEFORE the row is tombstoned.",
            job.job_id,
            vm.vm_id,
            vm.launch_abandoned_outcome or "unknown",
        )
    with transaction.atomic():
        updated = Vm.objects.filter(
            id=vm.id, version=vm.version, state=VmState.ACTIVE.value
        ).update(
            state=VmState.DECOMMISSIONING.value,
            # eol_nonce PRESERVED — the launch-baked value is what the
            # guest signs; we neither re-mint nor clear it here.
            version=vm.version + 1,
        )
        if updated:
            _consume_prior_stopped_acks(vm)
    if updated == 0:
        raise EffectError("vm changed concurrently during ticket-freeze")


def _destroy_vm(job: DecommissionJob) -> None:
    """§24 — CAS the `Vm` `Decommissioning → Destroyed` (the permanent
    tombstone), after the erasable-KEK destroy. Idempotent.
    """
    vm = Vm.objects.get(id=job.vm_id)
    if vm.state == VmState.DESTROYED:
        # A re-run after a crash between the CAS below and the tombstone:
        # the row is already dead, but the KBS may not have heard.
        _try_kbs_tombstone(job, vm)
        return
    if vm.state != VmState.DECOMMISSIONING:
        raise EffectError(f"vm is {vm.state!r}, not Decommissioning — cannot destroy")
    with transaction.atomic():
        updated = Vm.objects.filter(
            id=vm.id, version=vm.version, state=VmState.DECOMMISSIONING.value
        ).update(
            state=VmState.DESTROYED.value,
            host="",
            migration_dest="",
            new_generation=None,
            eol_nonce=None,
            **destroyed_power_fields(),
            version=vm.version + 1,
        )
    if updated == 0:
        raise EffectError("vm changed concurrently during destroy")

    # Release the VM's placements so its capacity slot is freed the instant
    # it is destroyed — otherwise a `Bound` placement pins the miner's
    # admission bound forever (§13 capacity leak). Lazy import: orchestration
    # must not couple to the scheduler at module-load time (import cycle).
    from apps.scheduler.service import release_placements_for_vm

    release_placements_for_vm(vm, reason="released:vm-destroyed")

    # …and its public IP, for the same reason: a destroyed VM must not hold
    # an address, nor keep one DNAT'ed at an overlay IP NetBird may reuse.
    from apps.network.service import release_for_destroyed_vm

    release_for_destroyed_vm(vm)

    # Last: tell the KBS. Never raises — a KBS that cannot be reached must
    # not hold a destroyed VM open; the sweep re-drives a failure.
    _try_kbs_tombstone(job, vm)


# ─── guest-signed ack verification ───────────────────────────────────


def _verify_ack(vm: Vm, raw: bytes, *, vm_generation: int) -> None:
    """Verify a guest `SignedStoppedAck` against the VM's pinned
    lifecycle key + EOL nonce. Raises `_AckInvalid` on a bad ack
    (fail-closed — caller keeps waiting) or `EffectError` if the
    verifier binary itself is unavailable (caller retries).
    """
    if not vm.eol_nonce:
        raise _AckInvalid("vm has no eol_nonce — not prepared for stop")
    skew = int(getattr(settings, "VALI_STOPPED_ACK_SKEW_SECS", 600))
    now = int(time.time())
    try:
        lifecycle_validator.verify_stopped_ack(
            signed_bytes=raw,
            lifecycle_vk_hex=vm.lifecycle_vk_hex(),
            vm_id=vm.vm_id,
            lease_id=vm.lease_id,
            vm_generation=vm_generation,
            nonce_hex=bytes(vm.eol_nonce).hex(),
            now_unix_min=now - skew,
            now_unix_max=now + skew,
        )
    except lifecycle_validator.ValidatorFailed as exc:
        raise _AckInvalid(str(exc)) from exc
    except lifecycle_validator.ValidatorUnavailable as exc:
        raise EffectError(f"ack verifier unavailable: {exc}") from exc


# ─── migration state handlers ────────────────────────────────────────


def _source_start_timeout() -> float:
    # Relaunch + boot of a stopped guest; a rotational-disk host took ~340 s.
    return float(getattr(settings, "VALI_MIGRATION_SOURCE_START_TIMEOUT_S", 900.0))


def _h_mig_source_starting(job: MigrationJob) -> StepResult:
    """COLD §25 step 0 — start the tenant-stopped VM on its SOURCE and wait
    until its guest proves it booted (an in-guest signal after the job
    began): the warm §25 that follows needs a running guest to quiesce and
    sign its stopped-ack. Pre-fence — the VM stays `Active` throughout."""
    from .services import power

    vm = Vm.objects.get(id=job.vm_id)
    if vm.power_state == VmPowerState.STOPPED:
        # One relaunch attempt per pacing window, claimed BEFORE it runs: a
        # relaunch is a synchronous multi-minute launch inside the tick, and
        # a host that keeps rejecting it must not be re-asked every tick.
        elapsed = (timezone.now() - job.started_at).total_seconds()
        key = _mig_key(job, f"source-start:{int(elapsed // _source_start_pacing_s())}")
        try:
            if idempotency.recall(key) is not None:
                return None
            idempotency.record(key, idempotency.marker_hash(key))
        except IdempotencyUnavailable:
            return None
        try:
            power.start_vm(vm, by_migration=True)
        except power.PowerOpRefused as exc:
            if exc.reason == power.DISKS_MISSING_REASON:
                # The source does not hold the VM's disks: every re-ask is
                # the same refusal. Fail the job now, not at the deadline.
                raise _StepFailed(f"source-start refused: {exc.reason}") from exc
            raise EffectError(f"source-start refused: {exc.reason}") from exc
        return None
    if vm.power_state != VmPowerState.RUNNING:
        return None  # starting — WAIT
    # The boot proof is an in-guest signal ingested AFTER the start landed
    # (`power_state_at`), never one from before it.
    started = max(job.started_at, vm.power_state_at or job.started_at)
    if vm.guest_signal_at is None or vm.guest_signal_at <= started:
        return None  # relaunched, guest not yet proven booted — WAIT
    return MigrationState.DRAINING.value, {}


def _source_start_pacing_s() -> float:
    return float(getattr(settings, "VALI_MIGRATION_SOURCE_START_PACING_S", 120.0))


def _h_mig_draining(job: MigrationJob) -> StepResult:
    # §25 step 1 — vali stops dispatching new compute to the source
    # for this VM. v1: a near-instant record step (vali holds no
    # per-VM compute queue to drain) — advance.
    return MigrationState.QUIESCING.value, {}


def _h_mig_quiescing(job: MigrationJob) -> StepResult:
    # §25 step 2 — trigger the source guest's COLD-migration EOL
    # shutdown-sign. This is the SAME §24 guest EOL path: the source guest
    # cleanly shuts down and signs its `stopped{}` ack from its ALREADY-BAKED
    # cmdline (vm_id / lease_id / vm_generation / eol_nonce) — NO fresh nonce
    # is delivered to a running guest (the locked COLD-migration design).
    # Per-migration replay protection is NOT the generation: the guest signs
    # at its baked `signing_generation`, identical on every hop. It is the
    # fence consuming every earlier ack (`_fence_vm`), so the only ack
    # `poll_source_ack` can find is one ingested after this job's fence.
    #
    # NON-DESTRUCTIVE: the guest's EOL teardown is `luksClose` + `poweroff`
    # only (it removes the dm-crypt MAPPING, never the on-disk LUKS
    # ciphertext) and §25 SKIPS vali's crypto-erase entirely — so the
    # encrypted disk survives intact for the snapshot. The quiesce relay
    # carries the `source_gen` (the generation the guest signs at, NOT
    # `new_gen`) so the miner can address the right guest; vali verifies the
    # resulting ack at `source_gen` in `_h_mig_awaiting_source_ack`.
    #
    # ORDERING (the fence MUST precede the graceful stop): the source guest
    # signs + POSTs its `stopped{}` ack DURING this quiesce shutdown, and
    # `StoppedAckIngestView` only accepts an ack for a VM already in
    # `Migrating`/`Decommissioning` at the matching generation (the §M-StoppedAck
    # identity-bind). So the `Vm` is fenced `Active → Migrating` HERE, before the
    # quiesce dispatches — exactly as §24's `_h_dec_draining` sets
    # `Decommissioning` before its graceful stop. Fencing at the old (later)
    # `Fencing` state raced the guest's push: the ack arrived while the VM was
    # still `Active` → a 404 that discarded it → the migration hung at
    # `AwaitingSourceAck` forever. The fence preserves the `source_gen` the guest
    # signs at (only `new_generation`/`migration_dest` are stamped), so the
    # ingest's generation match holds. `_fence_vm` is idempotent, so a re-driven
    # quiesce tick is a no-op.
    _fence_vm(job)
    vm = Vm.objects.get(id=job.vm_id)
    _guarded(
        _mig_key(job, "quiescing"),
        lambda: effects.relay_quiesce(vm, source_gen=job.source_gen),
    )
    return MigrationState.SNAPSHOTTING.value, {}


def _h_mig_snapshotting(job: MigrationJob) -> StepResult:
    # §25 steps 3-4 — presign the single-object S3 PUT, then tell the
    # source miner to snapshot the LUKS2+dm-integrity volume + upload.
    bucket = _snapshot_bucket()
    key = f"migrations/{job.vm.vm_id}/{job.job_id}.luks"
    # Second object: the per-VM anti-rollback state disk. The guest keeps
    # its boot counter there and submits `counter + 1` on every release;
    # the KBS requires exactly `stored + 1` and refuses an omitted counter
    # once it holds one. A dest that starts from a blank disk therefore
    # submits `1` against `stored = N` and is refused BEFORE any Vault read
    # — the migrated guest boots and never unlocks. So the counter travels
    # with the volume. The bytes are not secret (a forged counter can only
    # make the dest's release fail closed), so the same short-TTL presigned
    # channel as the ciphertext is sufficient.
    state_key = f"migrations/{job.vm.vm_id}/{job.job_id}.state"
    client = s3.get_s3_client()
    state_put = client.presign_put(bucket=bucket, key=state_key, ttl_seconds=_presign_ttl())
    plan = _plan_snapshot_parts(job.vm)
    if plan is None:
        # A legacy VM (no golden overlay size on record): the single PUT.
        put = client.presign_put(bucket=bucket, key=key, ttl_seconds=_presign_ttl())
        _guarded(
            _mig_key(job, "snapshotting"),
            lambda: effects.trigger_snapshot(job.vm, put_url=put.url, state_put_url=state_put.url),
        )
    else:
        # MULTIPART: the operator S3 account refuses any single request over
        # ~10 GiB, and a golden overlay is 40 GiB. The upload is opened (and
        # recorded) once per job, so a re-driven tick presigns the same one.
        upload_id = _open_snapshot_upload(job, client, bucket, key, plan)
        part_size, part_count = plan
        part_urls = [
            client.presign_upload_part(
                bucket=bucket,
                key=key,
                upload_id=upload_id,
                part_number=n,
                ttl_seconds=_presign_ttl(),
            ).url
            for n in range(1, part_count + 1)
        ]
        _guarded(
            _mig_key(job, "snapshotting"),
            lambda: effects.trigger_multipart_snapshot(
                job.vm,
                job_id=job.job_id,
                part_size=part_size,
                part_urls=part_urls,
                state_put_url=state_put.url,
            ),
        )
    return MigrationState.UPLOADING.value, {
        "snapshot_bucket": bucket,
        "snapshot_key": key,
        "snapshot_state_key": state_key,
    }


#: Most parts one snapshot order carries.
SNAPSHOT_MAX_PARTS = s3.MAX_ORDER_PARTS
#: The store's ceiling on one part (hippius-s3 `EntityTooLarge` above it).
_S3_MAX_PART_BYTES = s3.MAX_PART_BYTES
#: Planned over the overlay's nominal size, for whatever the file carries
#: beyond it; part URLs the file does not need are simply never used.
_SNAPSHOT_SIZE_HEADROOM = 64 * 1024**2


def _plan_snapshot_parts(vm: Vm) -> tuple[int, int] | None:
    """`(part_size, part_count)` for a golden VM's overlay, or `None` for a
    VM with no golden overlay size on record (legacy: the single PUT)."""
    disk_bytes = _golden_overlay_bytes(vm)
    if disk_bytes is None:
        return None
    bound = disk_bytes + _SNAPSHOT_SIZE_HEADROOM
    mib = 1024**2
    floor = int(getattr(settings, "VALI_ORCHESTRATION_SNAPSHOT_PART_BYTES", _S3_MAX_PART_BYTES))
    part_size = max(floor, math.ceil(bound / SNAPSHOT_MAX_PARTS))
    part_size = math.ceil(part_size / mib) * mib
    if part_size > _S3_MAX_PART_BYTES:
        raise _StepFailed(f"snapshot: a {disk_bytes}-byte overlay exceeds the multipart bound")
    return part_size, math.ceil(bound / part_size)


def _golden_overlay_bytes(vm: Vm) -> int | None:
    """The size of `vm`'s golden overlay (the snapshot's exact length), or
    `None` for a VM with no golden launch on record (legacy, or launched
    outside the pipeline): those keep the single PUT. A golden VM whose size
    cannot be read fails the step — the single PUT is refused for any
    golden overlay."""
    from apps.backup import service as backup_service

    try:
        return backup_service.source_disk_bytes(vm)
    except backup_service.BackupError as exc:
        if exc.code in ("not-golden", "no-launch-record") and not _is_golden(vm):
            return None
        raise _StepFailed(f"snapshot: cannot size the overlay ({exc.code})") from exc


def _open_snapshot_upload(
    job: MigrationJob, client: Any, bucket: str, key: str, plan: tuple[int, int]
) -> str:
    """The job's multipart upload id — opened and recorded on first call."""
    if job.snapshot_upload_id:
        return job.snapshot_upload_id
    upload_id = client.create_multipart_upload(bucket=bucket, key=key)
    part_size, part_count = plan
    recorded = MigrationJob.objects.filter(id=job.id, snapshot_upload_id="").update(
        snapshot_upload_id=upload_id,
        snapshot_part_size=part_size,
        snapshot_part_count=part_count,
        # With the id, so a failure before `Uploading` can still abort it.
        snapshot_bucket=bucket,
        snapshot_key=key,
    )
    if not recorded:
        # A concurrent tick opened one first: use it, drop ours.
        _abort_snapshot_upload(bucket, key, upload_id)
        job.refresh_from_db()
        return job.snapshot_upload_id
    job.snapshot_upload_id = upload_id
    job.snapshot_part_size = part_size
    job.snapshot_part_count = part_count
    job.snapshot_bucket = bucket
    job.snapshot_key = key
    return upload_id


def _abort_snapshot_upload(bucket: str, key: str, upload_id: str) -> None:
    """Best-effort abort: a failure only leaves parts for the store's own
    expiry of incomplete uploads."""
    try:
        s3.get_s3_client().abort_multipart_upload(bucket=bucket, key=key, upload_id=upload_id)
    except Exception as exc:  # noqa: BLE001 — cleanup, never fatal
        log.warning("migration: abort of snapshot upload %s failed: %s", key, exc)


def _h_mig_uploading(job: MigrationJob) -> StepResult:
    # §25 step 4 cont. — poll until the snapshot+upload finishes.
    if not job.snapshot_upload_id:
        status = effects.poll_snapshot(job.vm)
        if status == "failed":
            raise _StepFailed("source miner reported snapshot/upload failure")
        if status != "done":
            return None  # still running — WAIT
        return MigrationState.FENCING.value, {}
    status, disk = effects.poll_snapshot_status(job.vm)
    if status == "failed":
        # The miner's upload task has ended: re-polling cannot change it.
        raise _StepFailed("source miner reported snapshot/upload failure")
    if status != "done":
        return None
    size, sha256 = _complete_snapshot_upload(job, disk)
    return MigrationState.FENCING.value, {
        "snapshot_upload_id": "",
        "snapshot_size": size,
        "snapshot_sha256": sha256,
    }


def _complete_snapshot_upload(job: MigrationJob, disk: dict[str, Any] | None) -> tuple[int, str]:
    """Complete the multipart upload from the miner's part receipts, after
    checking they tile exactly one object of the planned part size, then
    confirm the store holds that many bytes. Returns the object's length
    and the source's sha256 of it, for the destination to verify."""
    try:
        size = int((disk or {})["size"])
        sha256 = str(disk["sha256_hex"])
        parts = [(int(p["part_number"]), str(p["etag"]), int(p["size"])) for p in disk["parts"]]
    except (KeyError, TypeError, ValueError) as exc:
        raise _StepFailed(f"snapshot: malformed part receipts ({exc})") from exc
    if len(sha256) != 64 or any(c not in "0123456789abcdef" for c in sha256):
        raise _StepFailed("snapshot: the receipt's sha256 is not 64 lower-case hex")
    n = len(parts)
    if not 0 < n <= job.snapshot_part_count or [p[0] for p in parts] != list(range(1, n + 1)):
        raise _StepFailed(f"snapshot: part numbers are not 1..{n} within the plan")
    for number, _etag, part_bytes in parts:
        full = number < n
        if (full and part_bytes != job.snapshot_part_size) or not (
            0 < part_bytes <= job.snapshot_part_size
        ):
            raise _StepFailed(f"snapshot: part {number} has {part_bytes} bytes")
    if sum(p[2] for p in parts) != size:
        raise _StepFailed("snapshot: the parts do not add up to the reported size")
    expected = _golden_overlay_bytes(job.vm)
    if size != expected:
        raise _StepFailed(f"snapshot: {size} bytes uploaded, the overlay is {expected}")
    client = s3.get_s3_client()
    try:
        client.complete_multipart_upload(
            bucket=job.snapshot_bucket,
            key=job.snapshot_key,
            upload_id=job.snapshot_upload_id,
            parts=[s3.CompletedPart(part_number=p[0], etag=p[1]) for p in parts],
        )
    except s3.S3RequestRejected as exc:
        # Completed by an earlier tick that died before recording it?
        if client.head_object(bucket=job.snapshot_bucket, key=job.snapshot_key) != size:
            raise _StepFailed(f"snapshot: the store refused the upload ({exc})") from exc
    stored = client.head_object(bucket=job.snapshot_bucket, key=job.snapshot_key)
    if stored != size:
        raise _StepFailed(f"snapshot: the store holds {stored} bytes, not {size}")
    return size, sha256


def _h_mig_fencing(job: MigrationJob) -> StepResult:
    # §25 step 5 — the generation fence. The `Vm` was already CAS'd
    # `Active → Migrating` back at `Quiescing` (so the guest's stopped-ack,
    # pushed during that shutdown, lands in an ack-accepting state). This is
    # an idempotent re-assert: `_fence_vm` no-ops when the VM is already
    # fenced for THIS job, and fails closed if it was fenced elsewhere.
    _fence_vm(job)
    return MigrationState.AWAITING_SOURCE_ACK.value, {}


def _h_mig_awaiting_source_ack(job: MigrationJob) -> StepResult:
    # §25 step 6 — poll for + verify the source guest's signed
    # `stopped{}` ack. The destination is NOT activated without it.
    raw = effects.poll_source_ack(job.vm)
    if raw is None:
        return None  # not produced yet — WAIT (timeout → quarantine)
    try:
        vm = Vm.objects.get(id=job.vm_id)
        # The source guest signs at its BAKED generation (signing_generation),
        # which is `source_gen` ONLY for a never-migrated VM; a re-migration
        # runs at a higher source_gen but the guest still signs its launch
        # generation, so verify at signing_generation.
        _verify_ack(vm, raw, vm_generation=vm.signing_generation)
    except _AckInvalid as exc:
        # Fail-closed: a bad ack never advances the migration.
        log.warning("migration %s: source ack rejected (%s)", job.job_id, exc)
        return None
    return MigrationState.DEST_ACTIVATING.value, {"source_ack_verified": True}


#: §25 restore/failover dest-activation failure classes (the `migration/…`
#: string the dest's status route reports — `MinerAgentError::Migration`'s
#: `Display`) that are refusals over the staged restore's own on-disk
#: state: the staged overlay vanished, staging was never `Staged`, a swap
#: is already mid-flight, or the staged/live artifacts don't match what
#: was recorded at stage time. All of that is decided BEFORE the dest
#: touches the network or the domain, from state a retry cannot change —
#: unlike `migration/restore-swap-io` (a write/rename/fsync failed) or
#: `migration/restore-stat` (a stat failed), which are ordinary I/O and
#: stay in the retry loop below. `_h_mig_dest_activating` treats a class
#: in this set as terminal: straight to the pre-commit revert instead of
#: spending the rest of the attempt budget re-asking the same question.
_TERMINAL_RESTORE_ACTIVATION_CLASSES = frozenset(
    {
        "migration/restore-staged-missing",
        "migration/restore-not-staged",
        "migration/staged-restore-conflict",
        "migration/restore-size-mismatch",
        "migration/restore-swap-conflict",
    }
)


def _h_mig_dest_activating(job: MigrationJob) -> StepResult:
    # §25 step 7 — reached ONLY post-fence: `_migration_guard` refuses
    # `DestActivating` without `source_ack_verified`, so the verified
    # source-stopped ack is already proven here (the split-brain gate).
    #
    # Ordering (all AFTER the fence):
    #   (a) KBS releases the key to the destination at new_gen — moves the
    #       KBS VmState to `Migrating{new_gen, dest}` so ONLY the dest at
    #       new_gen may unlock, and the source is denied forever after.
    #   (b) M4 — dispatch the `migrate-activate` order to the DEST miner so
    #       it downloads the snapshot, stages the measured boot artifacts,
    #       and boots the domain at new_gen. Without this the KBS release
    #       was inert (nothing told the dest to restore). Carries the SAME
    #       presigned snapshot GET as the KBS release.
    #   (c) POLL the dest's restore/boot to completion, THEN the local Vm CAS
    #       Migrating→Active{new_gen, dest}.
    #
    # (b) is ACK-then-async on the dest (the restore is a multi-GB download +
    # boot that far exceeds the order-relay timeout), so the dispatch only
    # confirms the dest ACCEPTED the order — it does NOT mean the dest booted.
    # We then poll the DEST miner's migration status (the SAME status surface
    # the source snapshot uses, targeted at the destination) until it reports
    # `done`/`failed`, and only activate the local Vm on `done`. This state is
    # therefore a POLLING state with a longer (download-sized) timeout.
    restoring = job.kind == MigrationKind.RESTORE.value
    failing_over = job.kind == MigrationKind.FAILOVER.value
    get_url = ""
    state_get_url = ""
    backup_chain: dict[str, Any] | None = None
    if restoring:
        # A restore reaches here with the VM still `Active` and its domain
        # proven down (`restore.h_stopping`): the fence happens now, in this
        # state, so a job cancelled or failed before it never leaves the VM
        # fenced. Idempotent.
        _fence_vm(job)
    elif failing_over:
        # The source must still be dead at the fence; the fence, then the
        # source quarantined (`restore.prepare_failover_activation`).
        _restore().prepare_failover_activation(job)
    else:
        client = s3.get_s3_client()
        get_url = client.presign_get(
            bucket=job.snapshot_bucket, key=job.snapshot_key, ttl_seconds=_presign_ttl()
        ).url
        # Blank on a job that started before the state disk was carried — the
        # dest then keeps the pre-fix blank-counter behaviour instead of being
        # handed a presigned URL for an object that was never uploaded.
        if job.snapshot_state_key:
            state_get_url = client.presign_get(
                bucket=job.snapshot_bucket,
                key=job.snapshot_state_key,
                ttl_seconds=_presign_ttl(),
            ).url
    _guarded(
        _mig_key(job, "dest-activating"),
        lambda: effects.kbs_activate_dest(
            job.vm,
            dest_node_id=job.dest_node_id,
            new_gen=job.new_gen,
            get_url=get_url,
        ),
    )
    if restoring and _restore().is_rollback(job):
        # A2 — arm the KBS for ONE release of the restored (earlier-boot)
        # disk, now that it holds `Migrating{new_gen, dest}` and BEFORE the
        # destination boots anything. A refusal reverts (`restore.fail`).
        _guarded(_mig_key(job, "rollback-arm"), lambda: _restore().arm_rollback(job))

    # M4 — tell the dest miner to actually restore + boot. Idempotency-
    # guarded so a tick re-drive does not re-dispatch (the miner-agent's
    # order_id dedup + desired-state idempotency also tolerate a repeat).
    # The boot-artifact staging bundle is resolved from the VM's launch
    # record; `None` when no record exists (the dest then relies on its
    # pre-staged-artifact existence check — never a half boot).
    # RETRY, not one-shot. `sev_common_kvm_init … EBUSY` on the dest is
    # intermittent and self-recovering (see `scheduler.cvm_capability`),
    # and by the time we are here the SOURCE has already been quiesced,
    # stopped and KBS-fenced — so giving up on the first `failed` costs
    # the tenant its VM for a fault that clears by itself. Before this,
    # a `failed` status was terminal in practice: the handler re-ran each
    # tick, but the dispatch idempotency key was CONSTANT, so the miner
    # was never asked again and the job merely burned down the phase
    # deadline re-polling a dead answer.
    #
    # The attempt number counts the attempts the dest has REPORTED failed
    # (`_dest_activate_attempt`), not the phase clock. A clock-derived
    # number sent a new order every backoff bucket while the first restore
    # was still running: the dest answered `activate-in-progress` to each,
    # and a multi-GB restore that failed at minute 5 found its retry
    # budget already spent on no-ops. So attempt N+1 is dispatched only
    # once attempt N was dispatched AND reported `failed` — and never
    # after a `done`, which would drag an activated dest back through a
    # restore. The clock stays a pacing floor (attempt N no earlier than
    # N × backoff into the phase), so a fault that fails fast is still
    # retried after `_dest_retry_backoff_s()`, not immediately. Bounded
    # by `_dest_activate_max_attempts()` and by the `_activate_timeout()`
    # phase deadline; no `MigrationJob` column needed.
    #
    # Each attempt is a NEW order at the dest (`attempt` is folded into
    # the order_id): `begin_activate` accepts a `Failed` dest entry back to
    # `Activating`, `activate_dest` is existence-gated on the download and
    # content-checked on the artifacts, and a launch whose ticket push
    # failed is torn down so the retry boots a fresh domain. An in-flight
    # job carried over this deploy is on attempt 0 — the same order_id as
    # before, so it is not re-sent.
    max_attempts = _dest_activate_max_attempts()
    attempt = _dest_activate_attempt(job, max_attempts)
    # Past the cap we stop ASKING. The handler keeps polling until the
    # phase deadline fails the job, but no further orders go out.
    exhausted = attempt >= max_attempts
    paced = attempt * _dest_retry_backoff_s() > _phase_elapsed_s(job)
    # Nor once the dest could no longer restore and settle before its
    # settle-by: it would refuse the order (`dest-settle-by-passed`) and
    # report `failed`, which the ledger below would book as a CVM start
    # failure of a host that was never asked to start anything.
    too_late = timezone.now().timestamp() >= _activate_settle_by_unix(job) - _DEST_SETTLE_WINDOW_S
    _warn_if_activate_timeout_too_small()
    if not exhausted and not paced and not too_late:
        if restoring:
            # Write-ahead: absent, it proves no ticket at `new_gen` ever
            # left vali (`restore.commit_state`).
            _restore().note_dest_dispatch(job)
        if failing_over and not _attempt_dispatched(job, attempt):
            # No staging is possible on a dead host: the destination
            # downloads the chain as it activates. The order's `get_url` is
            # required on the wire and ignored by the destination when a
            # chain is set.
            backup_chain = _restore().failover_chain(job)
            get_url = backup_chain["full"]["url"]
        _guarded(
            _mig_key(job, _dispatch_step(attempt)),
            lambda: effects.dispatch_migrate_activate(
                job.vm,
                dest_node_id=job.dest_node_id,
                new_gen=job.new_gen,
                get_url=get_url,
                state_get_url=state_get_url,
                boot_artifacts=effects.resolve_boot_artifacts(job.vm),
                # #952 scopes the dest miner's idempotency key to THIS
                # JOB so a re-drive of a failed activation is a real
                # dispatch; `attempt` scopes it WITHIN the job so a retry
                # is too. Both are needed: one fixes re-driving a dead
                # job, the other fixes retrying inside a live one.
                job_id=job.job_id,
                attempt=attempt,
                snapshot_size=job.snapshot_size,
                snapshot_sha256_hex=job.snapshot_sha256,
                # vali's phase deadline, so a retry's restore on the dest
                # cannot settle after this job has already failed.
                settle_by_unix=_activate_settle_by_unix(job),
                **({"staged_restore_id": job.restore_id} if restoring else {}),
                **({"backup_chain": backup_chain} if failing_over else {}),
            ),
        )
    # Poll the dest's async restore. `running` ⇒ WAIT (timeout → fail closed,
    # the dest is never activated — split-brain gate holds); `failed` ⇒ fail
    # closed; `done` ⇒ the dest booted + unlocked at new_gen, activate the Vm.
    status, failure_class = effects.poll_dest_activation_status(
        job.vm, dest_node_id=job.dest_node_id
    )
    if status == "failed":
        if exhausted and job.kind != MigrationKind.MIGRATE.value:
            # A restore decides at once: revert before the commit point,
            # keep the original after it (`restore.fail`).
            raise _StepFailed(f"activate-failed:{failure_class or 'dest-failed'}")
        if exhausted:
            raise EffectError(
                "dest miner reported migrate-activate restore/boot failure on all "
                f"{max_attempts} attempts"
            )
        if not _attempt_dispatched(job, attempt):
            # The `failed` is the PREVIOUS attempt's, still standing while
            # this one waits out its pacing floor. Not a new observation.
            return None
        # §23 gate (e) — the destination was asked to boot a confidential
        # guest and reported that it could not. THAT is the observation
        # nothing in the control plane was recording: the host stays
        # heart-beating, stays on-chain Active, and keeps reporting all its
        # CPU/RAM free (it has plenty — it is booting nothing), so without
        # this write it remained a first-class candidate for the very next
        # launch AND the very next migration, and `quarantine_node_id`
        # named nobody.
        #
        # `_guarded` on an ATTEMPT-scoped key so this counts ONCE per
        # dispatch attempt, not once per tick: the streak that eventually
        # hard-excludes a host must count real start attempts. The same
        # key is what advances `_dest_activate_attempt` — so it is recorded
        # for EVERY failed attempt, and only the evidence write inside it
        # depends on the class: a restore that failed before any boot
        # (`dest-settle-by-passed`, a snapshot download, artifact staging, …)
        # is a real failed attempt but says nothing about starting a CVM.
        _guarded(
            _mig_key(job, _failure_step(attempt)),
            lambda: _record_dest_activation_failure(job, failure_class),
        )
        if (
            job.kind != MigrationKind.MIGRATE.value
            and failure_class in _TERMINAL_RESTORE_ACTIVATION_CLASSES
        ):
            # The dest refused on the staged restore's own on-disk state —
            # the overlay it staged is gone, was never staged, conflicts
            # with an in-progress swap, or does not match the size/markers
            # recorded at stage time. None of that changes on a re-ask: the
            # remaining attempt budget would just re-run the same check and
            # get the same answer while the VM sits stopped. Skip straight
            # to the pre-commit revert instead of retrying.
            raise _StepFailed(f"activate-failed:{failure_class}")
        if attempt + 1 < max_attempts:
            # Bounded RETRY. Raising `EffectError` keeps the job in
            # `DestActivating` (the driver's retryable path); the recorded
            # failure moves the next tick to the next attempt, a new order.
            raise EffectError(
                "dest reported migrate-activate failure "
                f"(attempt {attempt + 1}/{max_attempts}) — retrying"
            )
        if job.kind != MigrationKind.MIGRATE.value:
            raise _StepFailed(f"activate-failed:{failure_class or 'dest-failed'}")
        raise EffectError(
            "dest miner reported migrate-activate restore/boot failure on all "
            f"{max_attempts} attempts"
        )
    if status != "done":
        return None  # still restoring — WAIT
    if not any(_attempt_dispatched(job, n) for n in range(min(attempt, max_attempts - 1) + 1)):
        # The dest never ACCEPTED an activate order of this job, so its
        # `done` is not about this restore. Live (a migrated VM, A→B→A): the dest
        # was the VM's previous SOURCE, refused every activate as
        # `activate-on-source`, and its status route reported that old
        # source leg's `done` — vali activated a VM nothing had restored.
        log.warning(
            "migration %s: dest %s reports done but accepted no activate "
            "order of this job — ignoring",
            job.job_id,
            job.dest_node_id,
        )
        return None
    # The dest booted AND unlocked at `new_gen` — an unforgeable-enough
    # positive: `done` is only reachable through the KBS release, which is
    # measurement-gated on vali's side.
    _record_dest_cvm_evidence(job, started=True)
    if job.kind != MigrationKind.MIGRATE.value:
        # A restore / failover is done only on the KBS's own proof that the
        # restored guest released at `new_gen` — never on the destination's
        # word (`restore.h_verifying`).
        return MigrationState.RESTORE_VERIFYING.value, {}
    _activate_dest_vm(job)
    return MigrationState.DONE.value, {}


def _dest_retry_backoff_s() -> float:
    """Minimum spacing between §25 dest-activation attempts. Default 120s
    — long enough for a transient PSP/SEV `EBUSY` to clear and for the
    dest's own background restore task to unwind, short enough that a
    real retry fits inside `_activate_timeout()` several times over."""
    return float(getattr(settings, "VALI_MIGRATION_DEST_ACTIVATE_BACKOFF_S", 120.0))


def _dest_activate_max_attempts() -> int:
    """How many times vali will ask a §25 destination to boot the guest
    before failing the migration. Default 3.

    Deliberately equal to `cvm_capability.fail_threshold()`: three
    attempts is exactly the evidence it takes to call a host incapable,
    so a migration that exhausts its retries leaves behind precisely the
    streak that keeps the next placement off that host — the retry and
    the exclusion are two readings of the same measurement.
    """
    return int(getattr(settings, "VALI_MIGRATION_DEST_ACTIVATE_MAX_ATTEMPTS", 3))


def _dest_activate_attempt(job: MigrationJob, max_attempts: int) -> int:
    """The 0-based dest-activation attempt this job is on: the number of
    attempts the destination has already reported failed, read from the
    per-attempt `_failure_step(n)` keys `_h_mig_dest_activating`
    records (once each). `max_attempts` once they are all spent.
    """
    for n in range(max_attempts):
        if idempotency.recall(_mig_key(job, _failure_step(n))) is None:
            return n
    return max_attempts


def _dispatch_step(attempt: int) -> str:
    # `r` namespace: the clock-numbered keys an older vali recorded for a job
    # in flight across the deploy (`dispatch-migrate-activate:{bucket}`,
    # one per backoff window) meant something else, and read with this
    # meaning they would swallow real retries.
    return f"dispatch-migrate-activate:r{attempt}"


def _failure_step(attempt: int) -> str:
    return f"cvm-start-failure:r{attempt}"


def _attempt_dispatched(job: MigrationJob, attempt: int) -> bool:
    """Whether `attempt`'s migrate-activate order went out (its `_guarded`
    dispatch key is recorded)."""
    key = _mig_key(job, _dispatch_step(attempt))
    return idempotency.recall(key) is not None


def _phase_elapsed_s(job: MigrationJob) -> float:
    return (timezone.now() - job.phase_started_at).total_seconds()


def _record_dest_activation_failure(job: MigrationJob, failure_class: str) -> None:
    """Book a failed §25 dest activation in the §23 capability ledger —
    unless the dest's class says the attempt ended before any CVM start
    (`cvm_capability.is_dest_activation_start_failure`)."""
    from apps.scheduler import cvm_capability

    if cvm_capability.is_dest_activation_start_failure(failure_class):
        _record_dest_cvm_evidence(job, started=False)
        return
    log.warning(
        "migration %s: dest %s failed before any CVM start (%s) — "
        "not recorded as capability evidence",
        job.job_id,
        job.dest_node_id,
        failure_class[:64],
    )


def _record_dest_cvm_evidence(job: MigrationJob, *, started: bool) -> None:
    """Write the §25 destination's observed CVM-start outcome into the §23
    capability ledger (`apps.scheduler.cvm_capability`).

    Keyed on the DESTINATION vali itself chose/was told to use, bridged
    `miner_id → chain_node_id` through the DB-unique `MinerIdentity` join
    — never on anything in the dest's status response. A miner therefore
    cannot use the migration path to mark a rival incapable, only itself.

    Fail-open: this must never convert a successful activation into a
    failed migration, nor mask the `EffectError` on the failure path.
    """
    from apps.scheduler import cvm_capability

    try:
        node_id = _dest_chain_node_id(job)
        if started:
            cvm_capability.record_start_ok(node_id)
        else:
            cvm_capability.record_start_failure(
                node_id, reason=cvm_capability.REASON_DEST_ACTIVATION_FAILED
            )
    except Exception as exc:  # noqa: BLE001 — never load-bearing
        log.warning(
            "migration %s: cvm-capability record skipped for dest %s: %s",
            job.job_id,
            job.dest_node_id,
            exc,
        )


_MIGRATION_HANDLERS: dict[str, Callable[[MigrationJob], StepResult]] = {
    MigrationState.SOURCE_STARTING.value: _h_mig_source_starting,
    MigrationState.DRAINING.value: _h_mig_draining,
    MigrationState.QUIESCING.value: _h_mig_quiescing,
    MigrationState.SNAPSHOTTING.value: _h_mig_snapshotting,
    MigrationState.UPLOADING.value: _h_mig_uploading,
    MigrationState.FENCING.value: _h_mig_fencing,
    MigrationState.AWAITING_SOURCE_ACK.value: _h_mig_awaiting_source_ack,
    MigrationState.DEST_ACTIVATING.value: _h_mig_dest_activating,
    MigrationState.RESTORE_STAGING.value: lambda job: _restore().h_staging(job),
    MigrationState.RESTORE_STOPPING.value: lambda job: _restore().h_stopping(job),
    MigrationState.RESTORE_VERIFYING.value: lambda job: _restore().h_verifying(job),
    MigrationState.RESTORE_REVERTING.value: lambda job: _restore().h_reverting(job),
    MigrationState.RESTORE_UNDOING.value: lambda job: _restore().h_undoing(job),
}


def _restore() -> Any:
    """`apps.orchestration.restore`, imported late (it imports this module)."""
    from . import restore

    return restore


def _migration_timeout(state: str) -> float:
    if state == MigrationState.SOURCE_STARTING.value:
        return _source_start_timeout()
    if state == MigrationState.AWAITING_SOURCE_ACK.value:
        return _ack_timeout()
    if state == MigrationState.UPLOADING.value:
        return _upload_timeout()
    if state == MigrationState.DEST_ACTIVATING.value:
        # The dest restore is a multi-GB snapshot download + boot; it must be
        # allowed to outlast the plain per-step timeout (else a large-overlay
        # migration times out mid-restore and fails an otherwise-good move).
        return _activate_timeout()
    return _step_timeout()


# The only migration state that runs BEFORE the §25 generation fence:
# `Draining` executes with the VM still `Active` on the source. `Quiescing`
# performs the fence itself (`Active → Migrating`, before dispatching the
# graceful stop so the guest's ack ingests), so from `Quiescing` on the VM is
# expected to be `Migrating`, not `Active`.
_MIG_PRE_FENCE_STATES: frozenset[str] = frozenset(
    {
        MigrationState.SOURCE_STARTING.value,
        MigrationState.DRAINING.value,
        # A restore stages and stops the original with the VM `Active`; its
        # fence is the first step of `DestActivating`.
        MigrationState.RESTORE_STAGING.value,
        MigrationState.RESTORE_STOPPING.value,
    }
)

#: The states each kind may be in (besides the terminal ones). A job in
#: another kind's state is corrupt and fails closed.
_KIND_STATES: dict[str, frozenset[str]] = {
    MigrationKind.MIGRATE.value: frozenset(
        {
            MigrationState.SOURCE_STARTING.value,
            MigrationState.DRAINING.value,
            MigrationState.QUIESCING.value,
            MigrationState.SNAPSHOTTING.value,
            MigrationState.UPLOADING.value,
            MigrationState.FENCING.value,
            MigrationState.AWAITING_SOURCE_ACK.value,
            MigrationState.DEST_ACTIVATING.value,
        }
    ),
    MigrationKind.RESTORE.value: frozenset(
        {
            MigrationState.RESTORE_STAGING.value,
            MigrationState.RESTORE_STOPPING.value,
            MigrationState.DEST_ACTIVATING.value,
            MigrationState.RESTORE_VERIFYING.value,
            MigrationState.RESTORE_REVERTING.value,
            MigrationState.RESTORE_UNDOING.value,
        }
    ),
    MigrationKind.FAILOVER.value: frozenset(
        {
            MigrationState.DEST_ACTIVATING.value,
            MigrationState.RESTORE_VERIFYING.value,
            MigrationState.RESTORE_REVERTING.value,
        }
    ),
}

#: The states that activate a destination (or act on one activated), each
#: needing the job kind's OWN justification (`_dest_justification_missing`).
_DEST_STATES = frozenset(
    {MigrationState.DEST_ACTIVATING.value, MigrationState.RESTORE_VERIFYING.value}
)


def _dest_justification_missing(job: MigrationJob) -> str | None:
    """`None` iff the job holds the justification ITS kind needs to activate
    a destination; else why not. Each kind has exactly one, and none is
    accepted for another kind:

    - `migrate`  — the verified guest-signed source stopped-ack
                   (`source_ack_verified`). An authorization row is ignored.
    - `restore`  — a `DestAuthorization` of kind `restore` (its requesting
                   principal is a non-null FK), for this job's `request_id`, recording the
                   source domain confirmed DOWN by its host. The ack flag is
                   ignored.
    - `failover` — a `DestAuthorization` of kind `failover`, for this job's
                   `request_id`, carrying the dead-miner evidence. The ack
                   flag is ignored.

    An authorization that accepts a rollback (A2) is valid only for a
    `restore` and only with its `on_behalf_of` principal.
    """
    kind = job.kind
    if kind == MigrationKind.MIGRATE.value:
        if not job.source_ack_verified:
            return "dest-activating-without-verified-source-ack"
        return None
    if kind not in (MigrationKind.RESTORE.value, MigrationKind.FAILOVER.value):
        return f"unknown-job-kind:{kind}"
    auth = job.authorization
    if auth is None:
        return f"dest-activating-without-{kind}-authorization"
    if auth.kind != kind:
        return f"authorization-kind-mismatch:{auth.kind}!={kind}"
    if not job.request_id or auth.request_id != job.request_id:
        return "authorization-request-mismatch"
    evidence = auth.evidence if isinstance(auth.evidence, dict) else {}
    if auth.accept_rollback:
        # A2: only a restore asked on behalf of a named tenant / superuser
        # may roll back; a failover never does.
        if kind != MigrationKind.RESTORE.value:
            return f"{kind}-cannot-roll-back"
        if auth.on_behalf_of_kind not in ("tenant", "superuser") or not auth.on_behalf_of_id:
            return "rollback-without-on-behalf-of"
    if kind == MigrationKind.RESTORE.value and evidence.get("source_domain_down") is not True:
        return "restore-without-source-down"
    if kind == MigrationKind.FAILOVER.value and evidence.get("dead") is not True:
        return "failover-without-dead-evidence"
    return None


def _migration_guard(job: MigrationJob) -> str | None:
    """Defense-in-depth invariants checked before every migration
    step. Returns a failure reason, or `None` if the job may proceed.
    """
    if job.state not in _KIND_STATES.get(job.kind, frozenset()):
        return f"state-not-for-kind:{job.state}:{job.kind}"
    if job.state == MigrationState.DRAINING.value:
        power_now = Vm.objects.filter(id=job.vm_id).values_list("power_state", flat=True).first()
        if power_now not in (None, VmPowerState.RUNNING):
            # The fence is next: quiescing a guest that is not running yields
            # no stopped-ack, and the job would strand the VM `Migrating`.
            return f"vm-not-running:{power_now}"
    # A `Draining` migration whose VM has left `Active` (e.g. a racing
    # decommission froze the ticket first) is doomed — fail it fast
    # rather than waste a tick trying to fence a VM that is being torn
    # down. (`Quiescing` performs the fence: `_fence_vm` re-reads the VM
    # and rejects a non-Active one, so it needs no separate guard.)
    if job.state in _MIG_PRE_FENCE_STATES and job.vm.state != VmState.ACTIVE:
        return f"vm-no-longer-active:{job.vm.state}"
    # §25 split-brain gate enforced AT the activation point: the
    # destination is NEVER activated without its kind's justification — a
    # verified source ack for a migration — not even if a corrupt /
    # hand-edited job reaches `DestActivating` with it unset.
    if job.state in _DEST_STATES:
        return _dest_justification_missing(job)
    return None


def advance_migration_job(job: MigrationJob) -> None:
    """Advance one `MigrationJob` by a single bounded step."""
    handler = _MIGRATION_HANDLERS.get(job.state)
    if handler is None:
        return  # terminal
    restoring = job.kind != MigrationKind.MIGRATE.value
    guard_failure = _migration_guard(job)
    if guard_failure is not None:
        log.error(
            "migration %s: invariant guard tripped (%s) — failing closed",
            job.job_id,
            guard_failure,
        )
        if restoring:
            _restore().fail(job, guard_failure)
        else:
            _fail_migration(job, reason=guard_failure)
        return
    timeout = _job_timeout(job)
    clock = _timer_start(job)
    try:
        result = handler(job)
    except _StepFailed as exc:
        log.error("migration %s: step %s failed: %s", job.job_id, job.state, exc)
        if restoring:
            _restore().fail(job, _short(exc))
        else:
            _fail_migration(job, reason=f"{job.state}:{_short(exc)}")
        return
    except _restore().StepFailed as exc:  # evaluated only when something raised
        log.error("restore %s: step %s failed: %s", job.job_id, job.state, exc)
        _restore().fail(job, _short(exc))
        return
    except _RETRYABLE as exc:
        if _phase_timed_out(clock, timeout):
            log.error(
                "migration %s: step %s exhausted retry window: %s",
                job.job_id,
                job.state,
                exc,
            )
            if restoring:
                _restore().on_timeout(job)
            else:
                _fail_migration(job, reason=f"{job.state}:{_short(exc)}")
        else:
            log.warning(
                "migration %s: step %s failed, will retry: %s",
                job.job_id,
                job.state,
                exc,
            )
        return
    if result is None:
        # Polling state — condition not yet met.
        if _phase_timed_out(clock, timeout):
            if not MigrationJob.objects.filter(
                id=job.id, version=job.version, state=job.state
            ).exists():
                return  # the handler (or a concurrent tick) already moved it
            if restoring:
                _restore().on_timeout(job)
            else:
                _on_migration_poll_timeout(job)
        return
    next_state, patch = result
    _cas_migration(job, next_state, patch)


#: The restore / failover states whose timer waits on the restored GUEST'S
#: boot: `restore_verifying` waits for the first KBS release at `new_gen`
#: (the commit point), and its timeout is the pre-commit auto-revert.
_GUARDIAN_PAUSABLE_STATES = frozenset({MigrationState.RESTORE_VERIFYING.value})


def _timer_start(job: MigrationJob) -> Any:
    """Where the current phase's timer starts. `phase_started_at`, except
    for a restore / failover waiting on the restored guest's boot of an
    M1/M2 VM whose guest reports it is waiting on the customer's key
    guardian (design §6): with guardian-first ordering the KBS release —
    the commit point — only happens once the guardian answers, so the
    wait is not a failure, and reverting a restore the customer is about
    to unblock would throw the restore away. Each guardian report restarts
    the clock, capped at `VALI_GUARDIAN_WAIT_MAX_PAUSE_S` past the phase
    start (`apps.lifecycle.guardian_wait.timer_start`). §25 migrations have
    no boot-time timer (their dest phase ends at the launch), so they are
    unaffected."""
    if job.kind == MigrationKind.MIGRATE.value or job.state not in _GUARDIAN_PAUSABLE_STATES:
        return job.phase_started_at
    from apps.lifecycle import guardian_wait

    vm = Vm.objects.filter(id=job.vm_id).first()
    if vm is None:
        return job.phase_started_at
    start = guardian_wait.timer_start(vm, job.phase_started_at)
    if start != job.phase_started_at and guardian_wait.is_awaiting(vm):
        log.info(
            "restore %s: vm %s is waiting on its key guardian (%s) — the %s timer is paused",
            job.job_id,
            vm.vm_id,
            vm.guardian_wait_reason,
            job.state,
        )
    return start


def _job_timeout(job: MigrationJob) -> float:
    """The current phase's deadline — a restore-only state's own, else the
    §25 table's."""
    own = _restore().job_timeout_s(job) if job.kind != MigrationKind.MIGRATE.value else None
    return own if own is not None else _migration_timeout(job.state)


def _on_migration_poll_timeout(job: MigrationJob) -> None:
    if job.state == MigrationState.AWAITING_SOURCE_ACK.value:
        # §25 split-brain gate: the source never produced a verified
        # stopped ack. The destination is NOT activated — fail closed.
        # The VM stays Migrating (fenced — the source can no longer
        # re-unlock); forward-only recovery from the snapshot is a
        # separate operator action.
        #
        # Defence-in-depth for GOLDEN: golden migration is newly-enabled and
        # its ack path, while proven live, is not yet battle-tested — so a
        # golden ack-timeout fails closed WITHOUT §13-quarantining the source
        # (a conservative safety net: a spurious timeout on a not-yet-hardened
        # path must not take a healthy real-tenant miner offline). The VM still
        # stays fenced-Migrating + the dest is not activated (no split-brain,
        # no data loss); only the source-quarantine compensation is skipped.
        if _is_golden(job.vm):
            log.error(
                "migration %s: source ack timeout for a GOLDEN vm — failing "
                "WITHOUT quarantining the source (conservative safety net for "
                "the newly-enabled golden path); destination NOT activated",
                job.job_id,
            )
            _fail_migration(job, reason="source-ack-timeout:golden-no-quarantine")
        else:
            log.error(
                "migration %s: source ack timeout — §13-quarantining source "
                "%s, destination NOT activated",
                job.job_id,
                job.source_node_id,
            )
            _fail_migration(
                job,
                reason="source-ack-timeout:quarantine-source",
                quarantine_node=job.source_node_id,
            )
    else:
        # Uploading: the snapshot never completed.
        log.error("migration %s: step %s timed out", job.job_id, job.state)
        _fail_migration(job, reason=f"{job.state}:timeout")


def _cas_migration(job: MigrationJob, next_state: str, patch: dict[str, Any]) -> bool:
    now = timezone.now()
    fields: dict[str, Any] = {
        "state": next_state,
        "version": job.version + 1,
        "phase_started_at": now,
        **patch,
    }
    if next_state in TERMINAL_MIGRATION_STATES:
        fields["finished_at"] = now
    updated = MigrationJob.objects.filter(id=job.id, version=job.version, state=job.state).update(
        **fields
    )
    if updated:
        log.info("migration %s: %s → %s", job.job_id, job.state, next_state)
    else:
        log.info("migration %s: CAS lost on %s (concurrent tick)", job.job_id, job.state)
    return updated == 1


def _fail_migration(job: MigrationJob, *, reason: str, quarantine_node: str = "") -> None:
    """Terminate a migration as `Failed`.

    Compensating cleanup is inherent to WHERE the failure occurred:

    - **`Draining`** — the `Vm` was never transitioned; it stays
      `Active` on the source (safe, no two-node risk) with the guest
      still running. The source "drain" is released simply by not
      advancing the job.
    - **`Quiescing` and beyond** — the fence has flipped the `Vm` to
      `Migrating` and the guest has been gracefully stopped. It is
      deliberately NOT rolled back HERE — this function has no way to
      know whether the KBS was moved, and un-fencing after
      `kbs_activate_dest` would leave vali claiming a VM the KBS says
      the destination owns. The VM is left `Migrating` and handed to
      `sweep_stranded_migrations`, which classifies it on the evidence
      and either restores the source (only when the job PROVABLY never
      reached `DestActivating`) or reports the operator re-drive.

    `failed_from_state` is what makes that classification possible, and
    is the ONE reason this function records anything beyond the failure:
    `DestActivating` is the sole caller of `effects.kbs_activate_dest`,
    so "which state did this job die in" is exactly "did the KBS move".

    The one active compensation is the §13 quarantine of the source
    on an ack timeout (`quarantine_node`); and an open snapshot multipart
    upload is aborted.
    """
    now = timezone.now()
    updated = MigrationJob.objects.filter(id=job.id, version=job.version, state=job.state).update(
        state=MigrationState.FAILED.value,
        snapshot_upload_id="",
        failed_from_state=job.state,
        version=job.version + 1,
        phase_started_at=now,
        finished_at=now,
        reason=reason[:256],
        quarantine_node_id=quarantine_node,
    )
    if updated:
        log.error("migration %s FAILED: %s", job.job_id, reason)
        if job.snapshot_upload_id:
            # An open snapshot upload is never completed now: drop its parts.
            _abort_snapshot_upload(job.snapshot_bucket, job.snapshot_key, job.snapshot_upload_id)


# ─── §24 KBS decommission fence ──────────────────────────────────────
#
# vali's `Decommissioning`/`Destroyed` used to be vali-only facts: the KBS
# row stayed `Active` forever after §24, and releases failed only because
# the Transit key was gone. With `VALI_KBS_FENCE_ENABLED` the KBS is told
# too — `decommission` right after the ticket freeze, `tombstone` once the
# row is destroyed — so everything the KBS issues (releases, the guest
# custody lease) can refuse a dead VM on its own authority.
#
# ⛔ The fence never replaces the erase. The erase is the data-death
# guarantee; the fence only brings the moment a live guest loses its keys
# forward. So a fence that cannot land holds the erase back for at most
# `VALI_KBS_FENCE_WINDOW_S`, and nothing here can fail or stall a job.


def _kbs_fence_enabled() -> bool:
    return bool(getattr(settings, "VALI_KBS_FENCE_ENABLED", False))


def _kbs_fence_window() -> float:
    """How long a failing fence may hold the erase back, from the start of
    the job. Clamped to HALF the step timeout: `_hold_erase_for_kbs_fence`
    raises a retryable error while it waits, and the driver fails a job
    whose step keeps raising past `_step_timeout()`. Half leaves no boundary
    where the hold's last raise is read as a timeout, and the hold re-arms
    the phase when it gives up so the erase always gets a full window of
    its own."""
    window = float(getattr(settings, "VALI_KBS_FENCE_WINDOW_S", 600.0))
    return max(0.0, min(window, _step_timeout() / 2))


#: Minimum spacing between two fence/tombstone attempts for the same job —
#: in the handlers and in the sweep alike — so a KBS that is down (or
#: predates the routes) is not hit, and does not stall the tick, every 10 s.
_KBS_FENCE_RETRY_EVERY_S = 30.0

#: At most this many pending jobs are re-driven per tick, oldest first.
_KBS_FENCE_SWEEP_BATCH = 10

#: Fleet-wide cap on KBS fence/tombstone calls per tick, handlers and sweep
#: together — per-job spacing alone still lets N due jobs cost N timeouts
#: in one tick. `tick_once` resets it; a transport failure (the KBS is
#: unreachable) spends it all, so nothing else waits on the same timeout.
_KBS_FENCE_CALLS_PER_TICK = 10
_kbs_fence_calls_left = _KBS_FENCE_CALLS_PER_TICK


def _reset_kbs_fence_budget() -> None:
    global _kbs_fence_calls_left
    _kbs_fence_calls_left = _KBS_FENCE_CALLS_PER_TICK


def _take_kbs_fence_call() -> bool:
    """Spend one call of this tick's budget; False when it is gone."""
    global _kbs_fence_calls_left
    if _kbs_fence_calls_left <= 0:
        return False
    _kbs_fence_calls_left -= 1
    return True


def _kbs_unreachable() -> None:
    global _kbs_fence_calls_left
    _kbs_fence_calls_left = 0


class _Fence:
    """Outcome of one `_try_kbs_fence`."""

    LANDED = "landed"  # the KBS holds Decommissioning (or a tombstone)
    FAILED = "failed"  # try again later
    ROUTE_MISSING = "route-missing"  # this KBS does not serve the route


def _fence_row(job: DecommissionJob) -> tuple[str, Any]:
    """`(kbs_fence, kbs_fence_at)`, re-read: the in-memory `job` is a snapshot
    from the start of the tick, and the sweep writes the same columns."""
    row = DecommissionJob.objects.filter(id=job.id).values_list("kbs_fence", "kbs_fence_at").first()
    if row is None:
        return KbsFence.NONE.value, None
    return row[0] or KbsFence.NONE.value, row[1]


def _cas_kbs_fence(job: DecommissionJob, *, expected: str, new: str) -> bool:
    """Move `kbs_fence` from `expected` to `new` (stamping `kbs_fence_at`),
    only if nobody moved it since it was read. A handler and the sweep can
    both be mid-call for the same job; a blind write lets the slower one
    erase the other's stronger fact (a pending tombstone overwritten by a
    late fence, say — and a `fenced` row on a destroyed VM is never
    tombstoned)."""
    return (
        DecommissionJob.objects.filter(id=job.id, kbs_fence=expected).update(
            kbs_fence=new, kbs_fence_at=timezone.now()
        )
        == 1
    )


def _recently_tried(stamp: Any) -> bool:
    if stamp is None:
        return False
    return (timezone.now() - stamp).total_seconds() < _KBS_FENCE_RETRY_EVERY_S


def _try_kbs_fence(job: DecommissionJob, *, respect_spacing: bool = True) -> str:
    """One attempt at the KBS `decommission` fence (a `_Fence` outcome).
    Never raises. With the flag off it does nothing and reports FAILED.

    A failed attempt stamps `kbs_fence_at` (value unchanged), and the next
    one waits `_KBS_FENCE_RETRY_EVERY_S`, so a dead KBS costs one timeout
    per job per half-minute, not one per tick."""
    if not _kbs_fence_enabled():
        return _Fence.FAILED
    fence, stamp = _fence_row(job)
    if fence in (KbsFence.FENCED, KbsFence.TOMBSTONED, KbsFence.CONFLICT):
        return _Fence.LANDED
    if respect_spacing and _recently_tried(stamp):
        return _Fence.FAILED
    if not _take_kbs_fence_call():
        return _Fence.FAILED
    vm_id = job.vm.vm_id
    try:
        effects.kbs_fence_decommission(vm_id)
    except effects.KbsRouteMissing as exc:
        # Not a blip: this KBS image does not have the route. Hand the job to
        # the sweep at once — holding the erase for it would only wait out
        # the window for an answer that cannot come.
        _cas_kbs_fence(job, expected=fence, new=KbsFence.PENDING.value)
        log.warning(
            "decommission %s: the KBS does not serve the fence route (%s) — "
            "vm %s is not fenced; left to the sweep",
            job.job_id,
            exc,
            vm_id,
        )
        return _Fence.ROUTE_MISSING
    except _RETRYABLE as exc:
        if isinstance(exc, effects.EffectUnavailable):
            _kbs_unreachable()
        _cas_kbs_fence(job, expected=fence, new=fence)
        log.warning(
            "decommission %s: KBS fence for vm %s not applied yet: %s",
            job.job_id,
            vm_id,
            exc,
        )
        return _Fence.FAILED
    if _cas_kbs_fence(job, expected=fence, new=KbsFence.FENCED.value):
        log.info("decommission %s: KBS fenced vm %s", job.job_id, vm_id)
    return _Fence.LANDED


def _hold_erase_for_kbs_fence(job: DecommissionJob) -> None:
    """`CryptoErasing` entry gate. With the flag on, the erase waits for the
    KBS fence — retrying on the spacing above — for at most
    `_kbs_fence_window()` from the start of the job. Past that (or at once,
    when the KBS does not serve the route) it proceeds anyway and marks the
    job `pending` for `sweep_pending_kbs_fences`: a KBS outage must never
    keep a tenant's KEK alive.

    Never holds back a re-run after the erase already happened (a destroy
    retry), nor a job that already gave up (a redriven job inherits the
    previous job's `pending`)."""
    if not _kbs_fence_enabled() or _erase_done(job):
        return
    fence, _ = _fence_row(job)
    if fence == KbsFence.PENDING:
        return
    outcome = _try_kbs_fence(job)
    if outcome == _Fence.LANDED:
        return
    started = min(job.started_at, job.phase_started_at)
    elapsed = (timezone.now() - started).total_seconds()
    window = _kbs_fence_window()
    if outcome == _Fence.FAILED and elapsed < window:
        raise EffectError(
            f"kbs-fence: the KBS has not acknowledged the decommission yet — "
            f"holding the crypto-erase back ({elapsed:.0f}s of {window:.0f}s)"
        )
    fence, _ = _fence_row(job)
    if fence in (KbsFence.FENCED, KbsFence.TOMBSTONED, KbsFence.CONFLICT):
        return  # it landed meanwhile — never downgrade it to pending
    _cas_kbs_fence(job, expected=fence, new=KbsFence.PENDING.value)
    # The hold used part of this phase's window; give the erase a whole one.
    # A version bump like every other phase move, so a concurrent worker
    # still holding the old deadline cannot fail the job on it.
    now = timezone.now()
    if DecommissionJob.objects.filter(id=job.id, version=job.version).update(
        phase_started_at=now, version=job.version + 1
    ):
        job.phase_started_at = now
        job.version += 1
    log.error(
        "KbsFencePending: decommission %s: the KBS did not acknowledge the "
        "decommission of vm %s (%s) — crypto-erasing anyway (the erase is the "
        "data-death guarantee); the tick sweep keeps re-driving the fence",
        job.job_id,
        job.vm.vm_id,
        "route not served" if outcome == _Fence.ROUTE_MISSING else f"{window:.0f}s elapsed",
    )


def _try_kbs_tombstone(job: DecommissionJob, vm: Vm, *, respect_spacing: bool = False) -> None:
    """Tell the KBS the VM is destroyed (`Destroyed{generation}`). Never
    raises; a no-op with the flag off. A transient failure marks the job
    `pending` (re-driven by the sweep); a generation conflict marks it
    `conflict` and stops — retrying cannot change the KBS's answer."""
    if not _kbs_fence_enabled():
        return
    fence, stamp = _fence_row(job)
    if fence in (KbsFence.TOMBSTONED, KbsFence.CONFLICT):
        return
    if respect_spacing and _recently_tried(stamp):
        return
    if not _take_kbs_fence_call():
        # Out of this tick's budget: leave it to the sweep.
        if fence != KbsFence.PENDING:
            _cas_kbs_fence(job, expected=fence, new=KbsFence.PENDING.value)
        return
    try:
        effects.kbs_tombstone(vm.vm_id, generation=int(vm.generation))
    except effects.KbsTombstoneConflict as exc:
        _cas_kbs_fence(job, expected=fence, new=KbsFence.CONFLICT.value)
        log.error(
            "KbsTombstoneConflict: decommission %s: vm %s (generation %s): %s — "
            "not retried; an operator must reconcile the KBS row",
            job.job_id,
            vm.vm_id,
            vm.generation,
            exc,
        )
        return
    except _RETRYABLE as exc:
        if isinstance(exc, effects.EffectUnavailable):
            _kbs_unreachable()
        _cas_kbs_fence(job, expected=fence, new=KbsFence.PENDING.value)
        log.warning(
            "decommission %s: KBS tombstone for vm %s failed (the sweep re-drives it): %s",
            job.job_id,
            vm.vm_id,
            exc,
        )
        return
    # A tombstone is the strongest fact; only a recorded conflict outranks it
    # (and then this call could not have succeeded).
    DecommissionJob.objects.filter(id=job.id).exclude(kbs_fence=KbsFence.CONFLICT).update(
        kbs_fence=KbsFence.TOMBSTONED.value, kbs_fence_at=timezone.now()
    )
    log.info("decommission %s: KBS tombstoned vm %s", job.job_id, vm.vm_id)


def sweep_pending_kbs_fences() -> int:
    """Re-drive the §24 jobs the KBS has not fully heard about: every
    `pending` one, and every `fenced` one whose VM is already destroyed (a
    tombstone lost to a crash or a race). Returns how many still need the
    KBS afterwards. A no-op (0) with the flag off. Never raises for one job.

    Bounded: at most `_KBS_FENCE_SWEEP_BATCH` jobs per tick, oldest attempt
    first, each at most once per `_KBS_FENCE_RETRY_EVERY_S`, and the pass
    stops at the first unreachable-KBS / route-missing answer — the rest
    would fail the same way, one timeout each, stalling the tick.

    What to send follows the VM's CURRENT state (re-read), not the job: a
    destroyed VM gets the tombstone (which subsumes the fence), a
    decommissioning one the fence.
    """
    if not _kbs_fence_enabled():
        return 0
    needs_kbs = Q(kbs_fence=KbsFence.PENDING) | Q(
        kbs_fence=KbsFence.FENCED, vm__state=VmState.DESTROYED
    )
    cutoff = timezone.now() - timedelta(seconds=_KBS_FENCE_RETRY_EVERY_S)
    due = (
        DecommissionJob.objects.filter(needs_kbs)
        .filter(Q(kbs_fence_at__isnull=True) | Q(kbs_fence_at__lte=cutoff))
        .order_by(F("kbs_fence_at").asc(nulls_first=True))
    )
    for job in due.select_related("vm")[:_KBS_FENCE_SWEEP_BATCH]:
        try:
            vm = Vm.objects.get(id=job.vm_id)
            if vm.state == VmState.DESTROYED:
                _try_kbs_tombstone(job, vm, respect_spacing=True)
                fence, _ = _fence_row(job)
                if fence not in (KbsFence.TOMBSTONED, KbsFence.CONFLICT):
                    break
            elif vm.state == VmState.DECOMMISSIONING:
                if _try_kbs_fence(job) != _Fence.LANDED:
                    break
            else:
                log.error(
                    "kbs-fence: job %s needs the KBS but vm %s is %r — neither "
                    "decommissioning nor destroyed; not re-driving",
                    job.job_id,
                    vm.vm_id,
                    vm.state,
                )
        except Exception:  # noqa: BLE001 — one job must not kill the sweep.
            log.exception("kbs-fence: re-drive failed for job %s", job.job_id)
    left = DecommissionJob.objects.filter(needs_kbs).count()
    if left:
        log.warning("KbsFencePending: %d decommission job(s) still need the KBS", left)
    return left


# ─── decommission state handlers ─────────────────────────────────────


def _h_dec_draining(job: DecommissionJob) -> StepResult:
    # §24 step 1 — freeze the ticket: CAS the Vm Active→Decommissioning
    # (the `ticket_frozen` commit point), then best-effort GRACEFULLY stop
    # the guest so its baked EOL hook fires + signs + pushes the StoppedAck
    # (which `_h_dec_awaiting_eol_ack` verifies before crypto-erase). A failed
    # graceful stop does NOT block decommission — §24 data death does not
    # depend on the ack (the ack-timeout forced reclaim + crypto-erase still
    # run); it just means this decommission takes the slower forced path
    # instead of the clean, non-quarantining verified-ack path.
    _decommission_vm(job)
    # Fence the KBS as soon as the ticket is frozen, so the KBS stops
    # treating the VM as live without waiting for the ack or the erase.
    # Best-effort here: `CryptoErasing` is where a missing fence can hold
    # the erase back (see `_hold_erase_for_kbs_fence`).
    _try_kbs_fence(job)
    try:
        _guarded(_dec_key(job, "eol-stop"), lambda: _stop_the_guest(job))
    except _RETRYABLE as exc:
        log.warning(
            "decommission %s: graceful EOL stop failed (best-effort, will "
            "fall back to ack-timeout forced reclaim): %s",
            job.job_id,
            exc,
        )
    return DecommissionState.AWAITING_EOL_ACK.value, {}


def _h_dec_awaiting_eol_ack(job: DecommissionJob) -> StepResult:
    # §24 — poll for + verify the guest's signed EOL `stopped{}` ack.
    # Keep trying the KBS fence while we wait: each tick is one more chance
    # to land it before `CryptoErasing`, and it costs one DB read once it
    # has landed.
    _try_kbs_fence(job)
    if _power_stop_proven(job):
        # A VM the tenant stopped has no guest left to stop or to sign: the
        # ack it signed on the way down for that stop was verified at ingest
        # (it could not verify now — its signed time is long out of skew).
        return DecommissionState.CRYPTO_ERASING.value, {"eol_ack_verified": True}
    raw = effects.poll_eol_ack(job.vm)
    if raw is None:
        # No ack YET — or no ack EVER, because there is no guest and there
        # never was one. Those are not the same wait, and vali already
        # holds the evidence to tell them apart.
        return _skip_ack_for_a_guest_that_never_existed(job)
    # The ack must answer THIS decommission's stop. The ticket freeze
    # already consumed every ack ingested before it, but a guest can still
    # sign one after it on its own — an in-guest `poweroff`/`reboot` runs the
    # same EOL hook — while §24's graceful stop never reached the miner. That
    # ack would record a clean, non-quarantining decommission for a guest
    # nobody stopped (the reboot-watcher restarts a guest reboot). The guest
    # cannot carry the order id (its signed fields are baked at launch), so
    # vali binds on its side: no ack counts until §24's own stop is recorded
    # delivered. Unrecorded ⇒ keep waiting; the timeout forces the reclaim.
    if not _eol_stop_delivered(job) and _claim_eol_stop_reask(job):
        # Re-ask with the SAME order id before refusing — ONCE per job (it
        # runs inside the tick): the miner replays a stop it already
        # performed with its original class (repairing a marker whose
        # `record` failed after a delivered stop), and a stop that failed
        # transiently in draining gets its second chance at the clean path.
        try:
            _guarded(
                _dec_key(job, "eol-stop"),
                lambda: _stop_the_guest(job, deadline_s=EOL_STOP_REASK_DEADLINE_S),
            )
        except _RETRYABLE as exc:
            log.info("decommission %s: re-asked EOL stop failed: %s", job.job_id, exc)
    if not _eol_stop_delivered(job):
        log.info(
            "decommission %s: an ack is waiting but §24's own graceful stop is "
            "not recorded delivered — not accepting it",
            job.job_id,
        )
        return None
    try:
        vm = Vm.objects.get(id=job.vm_id)
        # Verify at the guest's BAKED generation (signing_generation), not the
        # live `generation` — a migrated VM's guest signs at its launch
        # generation, so checking the bumped gen would reject a valid ack and
        # drop to the slow forced-reclaim path.
        _verify_ack(vm, raw, vm_generation=vm.signing_generation)
    except _AckInvalid as exc:
        log.warning("decommission %s: EOL ack rejected (%s)", job.job_id, exc)
        return None
    return DecommissionState.CRYPTO_ERASING.value, {"eol_ack_verified": True}


#: Budget for re-asking §24's stop from `AwaitingEolAck` — it runs inside
#: the orchestration tick, so it stays short.
EOL_STOP_REASK_DEADLINE_S = 50.0


def _stop_the_guest(job: DecommissionJob, *, deadline_s: float | None = None) -> None:
    """§24's graceful stop, counted as done (and so `_guarded`-recorded)
    only when the miner reports it STOPPED a guest. Anything else stopped
    nothing this decommission can vouch for: `not-running` means the guest
    was already down (e.g. it powered itself off after the freeze, signing
    an ack for a stop §24 did not perform), and a bare `idempotent-replay`
    — an older miner-agent that does not echo a replay's original class —
    could be hiding either answer. Fail-safe: not counted."""
    kwargs: dict[str, Any] = {"order_id": _eol_stop_order_id(job)}
    if deadline_s is not None:
        kwargs["deadline_s"] = deadline_s
    outcome = effects.dispatch_graceful_stop(job.vm, **kwargs)
    if outcome != "stopped":
        raise EffectError(
            f"decommission-eol-stop: the miner answered {outcome!r}, not "
            "'stopped' — this decommission cannot vouch it stopped the guest"
        )


def _eol_stop_order_id(job: DecommissionJob) -> str:
    """§24's stop order id — scoped to the JOB, not just the generation: a
    §24 reopened at the same generation must stop the guest itself, not be
    answered with the previous job's replayed `stopped`."""
    vm = job.vm
    return f"dec-eol-stop-{vm.vm_id}-{vm.generation}-{job.job_id[:12]}"


def _claim_eol_stop_reask(job: DecommissionJob) -> bool:
    """True exactly once per job: the single re-ask of §24's stop from
    `AwaitingEolAck`. Claimed BEFORE the attempt, so a hanging Edge costs
    one bounded dispatch, not one per tick until the ack timeout. An
    unreadable store claims nothing."""
    key = _dec_key(job, "eol-stop-reask")
    try:
        if idempotency.recall(key) is not None:
            return False
        idempotency.record(key, idempotency.marker_hash(key))
    except IdempotencyUnavailable:
        return False
    return True


def _power_stop_proven(job: DecommissionJob) -> bool:
    """The VM is STOPPED through the power API, and the boot that stop shut
    down proved it: its verified ack's nonce (`Vm.power_stop_proof`, set at
    ingest, cleared by every power transition out of `stopped`) is still the
    VM's current `eol_nonce`."""
    vm = (
        Vm.objects.filter(id=job.vm_id).only("power_state", "power_stop_proof", "eol_nonce").first()
    )
    return (
        vm is not None
        and vm.power_state == VmPowerState.STOPPED
        and vm.power_stop_proof is not None
        and vm.eol_nonce is not None
        and bytes(vm.power_stop_proof) == bytes(vm.eol_nonce)
    )


def _eol_stop_delivered(job: DecommissionJob) -> bool:
    """Whether §24 draining's graceful stop for `job` was delivered — the
    `_guarded` marker is recorded only after the dispatch succeeded. An
    unreadable store proves nothing: treat it as not delivered."""
    try:
        return idempotency.recall(_dec_key(job, "eol-stop")) is not None
    except IdempotencyUnavailable:
        return False


def _skip_ack_for_a_guest_that_never_existed(job: DecommissionJob) -> StepResult:
    """`AwaitingEolAck` with no ack in hand: advance straight to
    `CryptoErasing` iff vali can PROVE no guest was ever created for this
    VM — otherwise `None` (keep waiting; the timeout still forces the
    reclaim).

    ## Why this exists

    A launch that fails AFTER the KBS register leaves a `Vm` row
    `active host=""` with a live per-VM Vault-Transit KEK and no guest
    anywhere (`launch_abandoned_*`). Tearing that row down used to sit the
    full `VALI_ORCHESTRATION_ACK_TIMEOUT_S` (600 s in production) waiting
    for a guest-signed `StoppedAck` from a domain that failed at
    `libvirt-driver/create` — measured live on 2026-08-13 for
    a test VM: 9m34s in `awaiting_eol_ack` with `boot_phase=''`, its
    launch `dispatch-failed-after-register`, and its host answering
    `running: false`. Ten minutes of a live KEK on a VM that never
    existed, ended by a "forced reclaim" that also §13-quarantines the
    host for failing to ack for a guest it was never able to start.

    ## What is NOT relaxed

    ⛔ The ack requirement itself. For a VM that DID run, the guest-signed
    ack is the proof of a clean stop and nothing here touches it —
    [`never_ran_veto`] refuses on `vm.host`, on any boot milestone, on any
    guest signal, on `seen_running`, on a generation past 1, on a
    succeeded/in-flight launch, and finally on the miner's own live domain
    probe (only an affirmative "no domain" clears it). Every one of those
    is a positive record that a guest existed; the absence of an ack is
    never read as the absence of a guest.

    The evidence is re-read from the database AFTER the ack poll, never
    taken from `job.vm` — that is the instance the handler dereferenced to
    MAKE the poll, i.e. a snapshot from before a network round-trip, and a
    `booting` milestone landing while the poll is in flight is exactly the
    signal that must cancel this shortcut.

    `forced` stays FALSE and no host is quarantined. `forced=True` means
    "the miner never acked", which is a statement about a host that had a
    guest to stop; recording it here would blame a miner for a guest that
    was never created and pollute the one signal §13 acts on. The honest
    record is the `reason` stamped on the job.
    """
    vm = Vm.objects.get(id=job.vm_id)
    veto = never_ran_veto(vm)
    if veto is not None:
        return None  # a guest may exist — WAIT (timeout → forced reclaim)
    target = _abandoned_probe_target(vm)
    log.warning(
        "decommission %s: vm %s has NO guest and never had one (launch "
        "%r gave up without binding a host, no boot milestone, no guest "
        "signal, never seen running, and %s) — skipping the %.0fs EOL-ack "
        "wait for an ack that cannot come and crypto-erasing now. Not a "
        "forced reclaim: nothing failed to ack, there was nothing to ack.",
        job.job_id,
        vm.vm_id,
        vm.launch_abandoned_outcome or "unknown",
        f"miner {target!r} reports no live domain"
        if target
        else "NO miner was ever chosen for it, so there is no host that could be running it",
        _ack_timeout(),
    )
    return DecommissionState.CRYPTO_ERASING.value, {"reason": "never-ran:no-guest-was-ever-created"}


def _is_golden(vm: Vm) -> bool:
    """Whether `vm` is a GOLDEN dm-verity-overlay VM — resolved from its most
    recent SUCCEEDED launch record's `disk_mode`.

    A golden VM's tenant KEK is a Vault-Transit key (`kek-<vm_id>`) with NO
    KBS record; a legacy VM's is a KBS-erasable record. This picks the right
    §24 crypto-erase path.

    Fail SAFE toward LEGACY: an absent / unreadable / non-golden record ⇒
    `False`. Mis-classifying a golden VM as legacy merely reproduces the
    original loud failure (the KBS `crypto-erase` 404s → the job stays
    retryable/failed, never a false "erased"). The opposite default would be
    a SECURITY hole — a legacy VM treated as golden would SKIP the KBS erase
    and delete a non-existent Transit key (idempotent success) → the VM would
    be marked Destroyed with its data NOT erased. So legacy is the only safe
    default.
    """
    from .models import LaunchJob, LaunchJobState

    record = (
        LaunchJob.objects.filter(vm_id=vm.vm_id, state=LaunchJobState.SUCCEEDED)
        .order_by("-finished_at")
        .first()
    )
    if record is None:
        return False
    return (record.spec_json or {}).get("disk_mode") == _DISK_MODE_GOLDEN_VERITY


def _cut_reachability_after_erase(job: DecommissionJob, vm: Vm) -> None:
    """§24 — revoke the VM's NetBird peer once its KEK is erased,
    independently of the domain destroy.

    Best-effort and idempotent, like `RevokingNetbird`: data death is the
    KEK destroy, so a failure here is logged and never blocks the step. The
    revoke shares `RevokingNetbird`'s idempotency key, so that step skips it
    once it has succeeded here (and retries it if it failed here). Only ever
    called after the erase succeeded — a VM whose erase failed is not dead
    and keeps its peer.

    The public IP needs nothing here: `network.reconcile` withdraws every
    address held by a VM that is no longer Active/Migrating, so it is gone
    from the first tick after the VM enters `Decommissioning`.
    """
    try:
        _guarded(
            _dec_key(job, "revoke-netbird"),
            lambda: effects.revoke_netbird(vm),
        )
    except _RETRYABLE as exc:
        log.warning(
            "decommission %s: NetBird revoke after erase failed (best-effort, "
            "RevokingNetbird retries it): %s",
            job.job_id,
            exc,
        )


def _h_dec_crypto_erasing(job: DecommissionJob) -> StepResult:
    # §24 — destroy the erasable KEK (the cryptographic data-death
    # guarantee), then CAS the Vm Decommissioning→Destroyed.
    #
    # ONE PATH FOR EVERY VM (golden and legacy alike). This used to branch on
    # `_is_golden`, sending legacy VMs to the KBS admin `crypto-erase` — but
    # that route DOES NOT EXIST: `kbs-transport`'s `build_admin_router`
    # registers only register-vm / activate / evidence / allowlist-reload, so
    # the call 404'd forever and §24 data-death was NON-FUNCTIONAL for every
    # non-golden VM (fail-closed: the job failed and the VM was never
    # tombstoned, so nothing was ever falsely reported as erased).
    #
    # The Transit destroy is the correct erase for BOTH, because post-KEK-HSM
    # every VM's KEK is wrapped under its OWN per-VM Transit key: the golden
    # async path stages it in `_provision_golden_overlay_kek`, and the
    # legacy/sync path wraps with `transit_key_name(vm_id)` in
    # `launch_on_miner`. The KBS `require_wrapped_kek` gate REFUSES a
    # non-`vault:`-prefixed KEK on release (403), so a VM that ever booted
    # necessarily HAS that per-VM key. Destroying it makes the wrapped KEK
    # permanently unwrappable ⇒ the in-guest LUKS master key is
    # unrecoverable ⇒ true crypto-erase.
    #
    # The explicit `destroy` order is likewise unconditional: a guest that
    # did not self-poweroff on the EOL push would otherwise be left as a
    # zombie domain. Dispatched BEFORE `_destroy_vm` clears `vm.host`.
    vm = Vm.objects.get(id=job.vm_id)
    _hold_erase_for_kbs_fence(job)
    # `crypto-erase-v2`, not `crypto-erase`. The step now destroys TWO
    # per-VM Transit keys (`kek-<vm_id>` + `ud-<vm_id>`) and deletes THREE
    # KV paths (the KEK blob and both userdata copies); the old step
    # destroyed one key and deleted one blob. A job already in flight
    # across the upgrade has an idempotency record under the old key, and
    # reusing it would let that job SKIP the expanded erase and walk to
    # `Destroyed` with the tenant's cloud-init still readable — the exact
    # hole this change closes, re-opened for the VMs being decommissioned
    # while it ships. A new key makes those jobs re-run the step, which is
    # safe: every operation inside it is idempotent.
    _guarded(
        _dec_key(job, "crypto-erase-v2"),
        lambda: effects.crypto_erase_kek_transit(vm),
    )
    # Durable "the erase step ran" fact for the zombie detector
    # (`apps.lifecycle.zombie`): from here on, any frame this guest sends
    # proves a miner is still running a VM it was told to kill. Set once;
    # a retried tick leaves the first stamp alone.
    #
    # With it, WHAT the erase achieved for the data (`data_death`): a
    # crypto-erase for M0/M1, `customer-erase-required` for M2 — whose disk
    # key Hippius never held, so this step must never be reported as a disk
    # crypto-erase for it (design §3.4). §24 still deletes its disks,
    # backups and state disk like any other VM's.
    death = customer_keys.data_death_for(vm)
    DecommissionJob.objects.filter(id=job.id, kek_erased_at__isnull=True).update(
        kek_erased_at=timezone.now(), erase_host=vm.host or "", data_death=death
    )
    if death != DataDeath.CRYPTO_ERASED.value:
        log.warning(
            "decommission %s: vm %s is key_mode=customer — Hippius held no disk key, "
            "so this is NOT a crypto-erase (data_death=%s); only the customer's "
            "`guardian erase %s` makes the data unrecoverable",
            job.job_id,
            vm.vm_id,
            death,
            vm.vm_id,
        )
    # The data is dead — now cut the guest's NetBird peer, BEFORE the
    # destroy (its public IP is already gone, see the helper). A guest
    # keeps its LUKS master key in memory until its domain dies, and the
    # destroy needs the miner: while it is unreachable the job waits in
    # `destroy-pending`, which never reached `RevokingNetbird`. Live, three
    # erased guests stayed reachable for 13 days that way.
    _cut_reachability_after_erase(job, vm)
    # Force-stop the domain — retryable within the phase window so a
    # transient miner blip recovers; a persistently-unreachable miner
    # fails the job loudly (data is already erased) rather than leaving a
    # silently-tombstoned zombie.
    #
    # The destroy TARGET is resolved more widely than "where is this VM
    # bound" (`effects.destroy_target_miner_id`): a launch that FAILED
    # after its order reached the miner can still have left a running
    # domain, and the LaunchJob records which miner it was sent to. Live
    # example: a test VM whose launch failed with a miner 500 (SEV ASID
    # exhaustion) but whose LaunchJob names its miner.
    # Dispatching to a merely-POSSIBLE host is free — the order carries the
    # `vm_id` and the miner's `handle_destroy` no-ops for one it does not
    # know — whereas skipping would tombstone a live CVM as Destroyed.
    #
    # Only when NO vali record has ever named a miner (a placement that
    # never dispatched at all) is there genuinely nowhere to send it. Then
    # the destroy is skipped so the teardown can complete: otherwise
    # `dispatch_destroy` raises on every tick until the step window
    # elapses, `_fail_decommission` fires, and the Vm row is pinned in
    # `Decommissioning` with no API-reachable recovery —
    # `start_decommission` refuses a non-Active VM, so only an operator DB
    # fixup clears it.
    #
    # Logged at ERROR and stamped on the job: completing a teardown without
    # having proved the domain is gone is an operator-visible event, not a
    # routine warning. Data death is unaffected either way — the KEK
    # destroy above is unconditional and is what §24 actually guarantees.
    patch: dict[str, Any] = {}
    if effects.destroy_target_miner_id(vm):
        _guarded(
            _dec_key(job, "destroy-order"),
            lambda: effects.dispatch_destroy(vm),
        )
    else:
        log.error(
            "decommission %s: vm %s has no vali record naming any miner — "
            "completing the teardown WITHOUT proving the domain is gone "
            "(KEK erased, so the data is dead regardless)",
            job.job_id,
            vm.vm_id,
        )
        patch["reason"] = "destroy-skipped:no-miner-ever-recorded"
    _destroy_vm(job)
    return DecommissionState.REVOKING_NETBIRD.value, patch


def _h_dec_revoking_netbird(job: DecommissionJob) -> StepResult:
    # §24 — best-effort graceful teardown: revoke the NetBird peer.
    # Data death is already guaranteed by the KEK destroy, so a
    # NetBird failure NEVER blocks completion — log + advance.
    try:
        _guarded(
            _dec_key(job, "revoke-netbird"),
            lambda: effects.revoke_netbird(job.vm),
        )
    except _RETRYABLE as exc:
        log.warning(
            "decommission %s: NetBird revoke failed (best-effort, ignored): %s",
            job.job_id,
            exc,
        )
    return DecommissionState.DONE.value, {}


_DECOMMISSION_HANDLERS: dict[str, Callable[[DecommissionJob], StepResult]] = {
    DecommissionState.DRAINING.value: _h_dec_draining,
    DecommissionState.AWAITING_EOL_ACK.value: _h_dec_awaiting_eol_ack,
    DecommissionState.CRYPTO_ERASING.value: _h_dec_crypto_erasing,
    DecommissionState.REVOKING_NETBIRD.value: _h_dec_revoking_netbird,
}


def advance_decommission_job(job: DecommissionJob) -> None:
    """Advance one `DecommissionJob` by a single bounded step."""
    handler = _DECOMMISSION_HANDLERS.get(job.state)
    if handler is None:
        return  # terminal
    try:
        result = handler(job)
    except _RETRYABLE as exc:
        # `RevokingNetbird` swallows its own errors, so this fires
        # only for `Draining` (ticket-freeze) or `CryptoErasing`.
        if _phase_timed_out(job.phase_started_at, _step_timeout()):
            if _erase_done(job):
                # The KEK is gone, so the data is dead; only the domain
                # destroy (and its disk reclaim) keeps failing. Failing
                # the job here used to strand the VM in `Decommissioning`
                # for good: nothing retried the destroy, and
                # `start_decommission` refuses a non-Active VM. Live, three
                # guests whose KEK had been erased kept RUNNING for 13 days
                # that way. Keep retrying instead, and re-arm the window
                # so the ERROR repeats once per window, not every tick.
                log.error(
                    "decommission %s: KEK erased (data dead) but the domain "
                    "destroy on %s still fails after a full window — "
                    "retrying: %s",
                    job.job_id,
                    job.vm.host or "<no host>",
                    exc,
                )
                _cas_decommission(
                    job, job.state, {"reason": f"destroy-pending:{_short(exc)}"[:256]}
                )
                return
            log.error(
                "decommission %s: step %s exhausted retry window: %s",
                job.job_id,
                job.state,
                exc,
            )
            _fail_decommission(job, reason=f"{job.state}:{_short(exc)}")
        else:
            log.warning(
                "decommission %s: step %s failed, will retry: %s",
                job.job_id,
                job.state,
                exc,
            )
        return
    if result is None:
        # `AwaitingEolAck` is the only polling state.
        if _phase_timed_out(job.phase_started_at, _ack_timeout()):
            _on_eol_ack_timeout(job)
        return
    next_state, patch = result
    _cas_decommission(job, next_state, patch)


def _erase_done(job: DecommissionJob) -> bool:
    """True iff THIS job's §24 crypto-erase step has completed (its §14
    idempotency record exists). Only in `CryptoErasing` — any earlier
    state has not erased anything yet."""
    if job.state != DecommissionState.CRYPTO_ERASING.value:
        return False
    # The durable DB stamp is authoritative — VM-wide, because a redriven
    # job's own stamp is empty while an earlier job already erased. The
    # TTL'd idempotency store is only the fallback for a job that erased
    # before the stamp existed.
    if DecommissionJob.objects.filter(vm_id=job.vm_id, kek_erased_at__isnull=False).exists():
        return True
    try:
        return idempotency.recall(_dec_key(job, "crypto-erase-v2")) is not None
    except IdempotencyUnavailable:
        # Unknown is not "erased": fall back to today's loud failure.
        return False


def _on_eol_ack_timeout(job: DecommissionJob) -> None:
    """§24 forced reclaim — the miner never acked the stop.

    Crypto-erase does NOT depend on the ack: force the job forward to
    `CryptoErasing` (the KEK destroy still runs, data death is still
    guaranteed) and §13-quarantine the host (suspected ghost load).
    The job still completes — the ack only decides graceful vs forced.
    """
    log.error(
        "decommission %s: EOL ack timeout — forced reclaim, §13-quarantining %s",
        job.job_id,
        job.vm.host,
    )
    _cas_decommission(
        job,
        DecommissionState.CRYPTO_ERASING.value,
        {
            "forced": True,
            "quarantine_node_id": job.vm.host,
            "reason": "eol-ack-timeout:forced-reclaim",
        },
    )


def _cas_decommission(job: DecommissionJob, next_state: str, patch: dict[str, Any]) -> bool:
    now = timezone.now()
    fields: dict[str, Any] = {
        "state": next_state,
        "version": job.version + 1,
        "phase_started_at": now,
        **patch,
    }
    if next_state in TERMINAL_DECOMMISSION_STATES:
        fields["finished_at"] = now
    updated = DecommissionJob.objects.filter(
        id=job.id, version=job.version, state=job.state
    ).update(**fields)
    if updated:
        log.info("decommission %s: %s → %s", job.job_id, job.state, next_state)
    else:
        log.info(
            "decommission %s: CAS lost on %s (concurrent tick)",
            job.job_id,
            job.state,
        )
    return updated == 1


def _fail_decommission(job: DecommissionJob, *, reason: str) -> None:
    """Terminate a decommission as `Failed`.

    This is the ONE decommission failure path — `CryptoErasing` (or
    the `Draining` ticket-freeze) could not complete. Data death is
    NOT yet guaranteed; the loud `reason` is an operator escalation.
    """
    now = timezone.now()
    updated = DecommissionJob.objects.filter(
        id=job.id, version=job.version, state=job.state
    ).update(
        state=DecommissionState.FAILED.value,
        version=job.version + 1,
        phase_started_at=now,
        finished_at=now,
        reason=reason[:256],
    )
    if updated:
        log.error("decommission %s FAILED: %s", job.job_id, reason)


def _decommission_redrive_max() -> int:
    """How many FAILED §24 jobs a VM may accumulate before the stranded
    sweep stops re-opening it (`VALI_DECOMMISSION_REDRIVE_MAX`)."""
    return int(getattr(settings, "VALI_DECOMMISSION_REDRIVE_MAX", 5))


def sweep_stranded_decommissions() -> int:
    """Re-drive every VM stranded in `Decommissioning` behind a FAILED
    §24 job. Returns the number of jobs re-opened.

    A failed decommission leaves its VM `Decommissioning` with nothing to
    move it on: the tick only advances in-flight jobs, and
    `start_decommission` refuses a non-Active VM, so the API cannot retry
    either. Live, that stranded guests whose KEK was already erased, still
    RUNNING, with their ciphertext never reclaimed.

    The new job starts at `CryptoErasing`: the VM is already fenced (it
    left `Active` when the first job ran), the erase is idempotent, and
    the destroy order is a no-op on a host that no longer holds the VM.
    Only a VM that someone already asked to decommission is touched: it
    needs a prior `DecommissionJob`, and its LATEST one must be FAILED.
    Never raises.
    """
    reopened = 0
    for vm in Vm.objects.filter(state=VmState.DECOMMISSIONING):
        try:
            last = DecommissionJob.objects.filter(vm=vm).order_by("-started_at").first()
            if last is None or last.state != DecommissionState.FAILED.value:
                continue
            if _has_active_job(vm):
                continue
            failures = DecommissionJob.objects.filter(
                vm=vm, state=DecommissionState.FAILED.value
            ).count()
            if failures > _decommission_redrive_max():
                # Each failure already logged its own ERROR; a VM that keeps
                # failing needs a human, not a job row every window.
                continue
            now = timezone.now()
            try:
                with transaction.atomic():
                    job = DecommissionJob.objects.create(
                        job_id=secrets.token_hex(16),
                        vm=vm,
                        state=DecommissionState.CRYPTO_ERASING.value,
                        phase_started_at=now,
                        decided_by=last.decided_by,
                        forced=last.forced,
                        eol_ack_verified=last.eol_ack_verified,
                        quarantine_node_id=last.quarantine_node_id,
                        reason=f"redrive:{last.job_id}"[:256],
                        # Where the KBS fence stood: a redrive must not wait
                        # a fresh fence window the previous job already
                        # waited out (`_hold_erase_for_kbs_fence`).
                        kbs_fence=last.kbs_fence,
                        kbs_fence_at=last.kbs_fence_at,
                    )
            except IntegrityError:
                continue  # a concurrent tick opened one first
            log.warning(
                "stranded-decommission: vm=%s re-driven by job %s (previous job %s FAILED: %s)",
                vm.vm_id,
                job.job_id,
                last.job_id,
                last.reason,
            )
            reopened += 1
        except Exception:  # noqa: BLE001 — one VM must not kill the sweep.
            log.exception("stranded-decommission: redrive failed for vm=%s", vm.vm_id)
    return reopened
