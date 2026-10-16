"""Automatic failover off a dead miner (docs/design/backup-failover.md §9.4).

Run by the orchestration tick behind `VALI_FAILOVER_AUTO_ENABLED` (off).
For each miner hosting a VM whose backup policy says `failover_mode=auto`:

1. **Dead, and for long enough.** The three-way proof of the manual path
   (`restore.dead_evidence`: heartbeat and NetBird peer both silent, the
   Edge unable to reach the miner), with the heartbeat and the peer silent
   for `VALI_FAILOVER_AUTO_AFTER_S`, and the proof unbroken at every check
   for that long (`FailoverDeadWatch.dead_since`). One live signal — here
   or at the fence re-check — deletes the watch; so does a gap in the
   checks (the worker off, the tick down): a proof nobody watched is not
   a proof. The proof is taken afresh right before a job opens. A miner
   that only heart-beats is never probed; a partitioned host the Edge
   still reaches is alive.
2. **Not a fleet-wide failure.** More miners dead (or silent) at once than
   `VALI_FAILOVER_AUTO_MAX_DEAD_MINERS` looks like vali's own view failing:
   nothing starts (`held`).
3. **One at a time per dead miner.** While an automatic failover job off
   the miner is open, nothing else starts off it.
4. **The VM qualifies.** `failover_mode=auto`, an enabled policy, an
   eligible region and a complete current-boot point
   (`backup.service.failover_auto_status`), `Active` on that miner, not
   starting, with no job or launch in flight, and fewer than
   `MAX_FAILED_ATTEMPTS` failed automatic failovers off that miner (the last
   one at least `RETRY_BACKOFF_S` ago). A VM that did not opt in is never
   looked at, and the opt-in is re-read under the policy's row lock when
   the job opens.
5. **A destination with room.** Same region, same SNP generation, not a
   host of its placement group (`restore._pick_failover_dest`). With none,
   the VM waits in `pending_capacity` (an `AutoFailover` row), retried
   every tick; its failover id becomes the job id once one is found. The
   job's destination is counted against that host's capacity from the
   moment it opens (`scheduler.service.in_flight_move_reservations`).

The job itself is the manual one (`restore.start_failover`,
`trigger="auto"`): the re-check right before the KBS moves (a miner back
by then cancels the job), the quarantine of the dead miner, the
reappearance and reclaim. A miner back while VMs wait for room cancels
those waits.

Gauges for the `HippiusAutoFailover*` alerts are pushed from here, at
most once a minute and only while the worker is on; the alerts ignore a
report older than five minutes, so turning the worker off silences them.
"""

from __future__ import annotations

import logging
import secrets
import time
from datetime import timedelta
from typing import Any

from django.conf import settings
from django.db import IntegrityError, transaction
from django.db.models import F
from django.utils import timezone

from apps.lifecycle.models import Vm, VmPowerState, VmState

from .models import (
    TERMINAL_LAUNCH_STATES,
    TERMINAL_MIGRATION_STATES,
    AutoFailover,
    AutoFailoverState,
    FailoverDeadWatch,
    FailoverQuarantine,
    LaunchJob,
    MigrationJob,
    MigrationKind,
)

log = logging.getLogger(__name__)

ACTOR = "failover-auto"
#: How often a miner that looks dead is probed again (NetBird + the Edge).
PROBE_INTERVAL_S = 60.0
#: A watch not checked for this long is a gap: the run starts again.
WATCH_GAP_S = 3 * PROBE_INTERVAL_S
#: A silent registered miner counts towards the hold only while it hosts an
#: Active VM or was heard from this recently.
SILENT_MINER_HORIZON_S = 24 * 3600.0
#: After a failed / reverted automatic failover, the VM waits this long...
RETRY_BACKOFF_S = 3600.0
#: ...and after this many off the same miner, it waits for an operator.
MAX_FAILED_ATTEMPTS = 3
#: How often the gauges are pushed.
PUSH_INTERVAL_S = 60.0

M_ENABLED = "hippius_failover_auto_enabled"
M_JOBS = "hippius_failover_auto_jobs"
M_PENDING = "hippius_failover_auto_pending_capacity_since_seconds"
M_FAILED = "hippius_failover_auto_failed_24h"
M_CANCELLED = "hippius_failover_auto_cancelled_24h"
M_TIMESTAMP = "hippius_failover_auto_report_timestamp_seconds"
M_DEAD = "hippius_failover_auto_dead_miners"
M_HELD = "hippius_failover_auto_held"
M_UNDECIDED = "hippius_failover_fence_undecided_since_seconds"
M_SKIPPED = "hippius_failover_auto_skipped"
M_BLOCKED = "hippius_failover_auto_blocked"
M_QUARANTINE_OPEN = "hippius_failover_quarantine_open"

_last_push = 0.0
#: `{vm_id: (miner_id, reason)}`: the auto VMs on a dead miner the worker
#: passed over on its last look at each, and why — the gauges read it, and
#: each (vm, reason) is logged once. An entry lasts until the VM is looked
#: at again, stops being an auto VM on that miner, or the miner is back.
_skips: dict[str, tuple[str, str]] = {}
#: The (vm, miner, reason) already logged — kept across passes (the gauge
#: state is rebuilt each pass), dropped when the miner comes back.
_skips_logged: set[tuple[str, str, str]] = set()
#: The last push with the worker off carried an undecided fence.
_pushed_undecided = False
#: How long the last pass took (the gap tolerance follows slow passes).
_last_pass_s = 0.0


def enabled() -> bool:
    return bool(settings.VALI_FAILOVER_AUTO_ENABLED)


def after_s() -> float:
    return float(settings.VALI_FAILOVER_AUTO_AFTER_S)


def max_dead_miners() -> int:
    return int(settings.VALI_FAILOVER_AUTO_MAX_DEAD_MINERS)


def dead_count(*, now: Any = None) -> int:
    """How many miners look dead right now: those the worker watches, plus
    those registered `active` whose heartbeat has been silent for
    `VALI_FAILOVER_AUTO_AFTER_S` and that matter — hosting an `Active` VM,
    or heard from in the last `SILENT_MINER_HORIZON_S` (an abandoned
    registration does not hold the worker forever) — a failover-quarantined
    miner aside, it was proven dead once already. The second catches vali's
    own heartbeat intake failing, which would leave every miner silent."""
    from apps.miners.models import MinerIdentity, MinerStatus

    from .models import FailoverQuarantine

    now = now or timezone.now()
    quarantined = FailoverQuarantine.objects.filter(cleared_at__isnull=True).values_list(
        "miner_id", flat=True
    )
    hosts = set(
        Vm.objects.filter(state=VmState.ACTIVE).exclude(host="").values_list("host", flat=True)
    )
    silent = {
        miner_id
        for miner_id, seen in MinerIdentity.objects.filter(status=MinerStatus.ACTIVE)
        .exclude(miner_id__in=quarantined)
        # Never heard from at all is not a fleet member going silent.
        .exclude(last_seen_at__isnull=True)
        .exclude(last_seen_at__gte=now - timedelta(seconds=after_s()))
        .values_list("miner_id", "last_seen_at")
        if miner_id in hosts or (now - seen).total_seconds() < SILENT_MINER_HORIZON_S
    }
    watched = set(FailoverDeadWatch.objects.values_list("miner_id", flat=True))
    return len(silent | watched)


def held(*, now: Any = None) -> bool:
    """More miners dead at once than `VALI_FAILOVER_AUTO_MAX_DEAD_MINERS`:
    more likely vali's own view of the fleet failing (its heartbeat intake,
    NetBird, the Edge) than that many hosts dying together. Nothing starts
    while it holds."""
    return dead_count(now=now) > max_dead_miners()


def saw_alive(miner_id: str, why: str) -> None:
    """A live signal from `miner_id`: the unbroken run of dead verdicts is
    over, and the VMs waiting for room off it no longer need to move."""
    _forget_skips(miner_id)
    deleted, _ = FailoverDeadWatch.objects.filter(miner_id=miner_id).delete()
    if deleted:
        log.warning("failover-auto: miner %s is back (%s)", miner_id, why)
    _cancel_pending(
        AutoFailover.objects.filter(
            state=AutoFailoverState.PENDING_CAPACITY, source_node_id=miner_id
        ),
        f"cancelled: {why}",
    )


def _actor() -> Any:
    from apps.identity.models import PrincipalScope, ServiceClient

    actor, _ = ServiceClient.objects.get_or_create(
        name=ACTOR,
        defaults={
            "description": "Automatic failover off a dead miner (backup-failover.md §9.4).",
            # The `decided_by` of failovers across every tenant: an operator
            # action by definition. It holds no token.
            "scope": PrincipalScope.OPERATOR.value,
        },
    )
    return actor


def tick(*, now: Any = None) -> int:
    """One pass. Returns how many failover jobs it opened. Each miner reads
    the clock when its turn comes, so a slow probe of one never backdates
    another's proof; `now` pins it instead (tests)."""
    if not enabled():
        _reconcile_rows()
        _off()
        global _pushed_undecided
        undecided = _fence_undecided().exists()
        if undecided or _pushed_undecided:
            # A failover (manual included) waits at the fence: its alert
            # needs the gauges whatever the worker's switch — and one more
            # push once it settled, to withdraw them.
            _push_metrics(now=now or timezone.now(), force=not undecided)
            _pushed_undecided = undecided
        return 0
    from apps.backup.models import BackupPolicy, FailoverMode

    _reconcile_rows()
    by_miner: dict[str, list[int]] = {}
    hosts: dict[str, str] = {}
    for vm_pk, vm_id, host in (
        BackupPolicy.objects.filter(
            enabled=True, failover_mode=FailoverMode.AUTO, vm__state=VmState.ACTIVE
        )
        .exclude(vm__host="")
        .order_by("vm__vm_id")
        .values_list("vm_id", "vm__vm_id", "vm__host")
    ):
        by_miner.setdefault(host, []).append(vm_pk)
        hosts[vm_id] = host
    # A VM no longer an auto VM on the miner it was passed over on (moved by
    # hand, switched to manual, destroyed) is no longer a skip.
    for vm_id in [v for v, (m, _) in _skips.items() if hosts.get(v) != m]:
        del _skips[vm_id]
    # A wait whose VM is no longer an auto VM, or no longer on the miner it
    # waited to leave (moved by hand), is over: left alone, it would page
    # NoCapacity forever.
    _cancel_pending(
        AutoFailover.objects.filter(state=AutoFailoverState.PENDING_CAPACITY).exclude(
            vm_id__in=[pk for pks in by_miner.values() for pk in pks],
            source_node_id=F("vm__host"),
        ),
        "the vm no longer qualifies for an automatic failover",
    )
    # A miner no auto VM is left on is no longer watched (its VMs moved).
    FailoverDeadWatch.objects.exclude(miner_id__in=list(by_miner)).delete()
    started = 0
    began = time.monotonic()
    for miner_id in sorted(by_miner):
        try:
            started += _tick_miner(miner_id, by_miner[miner_id], now or timezone.now())
        except Exception:  # noqa: BLE001 — one miner must not stop the others.
            log.exception("failover-auto: unhandled error on miner %s", miner_id)
    global _last_pass_s
    _last_pass_s = time.monotonic() - began
    _push_metrics(now=now or timezone.now())
    return started


def _off() -> None:
    """The worker is off: nothing it watched counts once it is on again,
    and nothing waits for it."""
    FailoverDeadWatch.objects.all().delete()
    _skips.clear()
    _skips_logged.clear()
    _cancel_pending(
        AutoFailover.objects.filter(state=AutoFailoverState.PENDING_CAPACITY),
        "cancelled: automatic failover turned off",
    )


def _probe(vm_pk: int, miner_id: str, now: Any) -> dict[str, Any]:
    from . import restore

    return restore.dead_evidence(Vm.objects.get(pk=vm_pk), miner_id, now=now, after=after_s())


def _tick_miner(miner_id: str, vm_pks: list[int], now: Any) -> int:
    from apps.miners.models import MinerIdentity

    seen = (
        MinerIdentity.objects.filter(miner_id=miner_id)
        .values_list("last_seen_at", flat=True)
        .first()
    )
    if seen is not None and (now - seen).total_seconds() < after_s():
        # Heart-beating: alive, and no probe is spent on it.
        saw_alive(miner_id, "the miner heart-beats")
        return 0
    watch = FailoverDeadWatch.objects.filter(miner_id=miner_id).first()
    # A pass slower than usual is not a gap: the tolerance follows it.
    if watch is not None and (now - watch.checked_at).total_seconds() > max(
        WATCH_GAP_S, 2 * _last_pass_s
    ):
        # Nobody looked for a while: the run starts again from this check.
        watch.delete()
        watch = None
    if watch is None or (now - watch.checked_at).total_seconds() >= PROBE_INTERVAL_S:
        evidence = _probe(vm_pks[0], miner_id, now)
        if not evidence.get("dead"):
            saw_alive(miner_id, "the miner is not proven dead")
            return 0
        watch, _ = FailoverDeadWatch.objects.update_or_create(
            miner_id=miner_id,
            defaults={"checked_at": now, "evidence": evidence},
            create_defaults={"dead_since": now, "checked_at": now, "evidence": evidence},
        )
        log.warning(
            "failover-auto: miner %s dead since %s (heartbeat %s, netbird %s, edge %s)",
            miner_id,
            watch.dead_since.isoformat(),
            evidence.get("heartbeat_last_seen_at"),
            evidence.get("netbird"),
            evidence.get("edge"),
        )
    if (now - watch.dead_since).total_seconds() < after_s():
        return 0
    if held(now=now):
        log.error(
            "failover-auto: HELD — %d miners look dead at once (max %d); starting nothing "
            "off %s",
            dead_count(now=now),
            max_dead_miners(),
            miner_id,
        )
        return 0
    if _open_auto_job(miner_id):
        return 0
    pending = {
        af.vm_id: af
        for af in AutoFailover.objects.filter(
            state=AutoFailoverState.PENDING_CAPACITY, source_node_id=miner_id
        )
    }
    # The VMs that have waited longest first.
    vm_ids = dict(Vm.objects.filter(pk__in=vm_pks).values_list("pk", "vm_id"))
    order = sorted(
        vm_pks,
        key=lambda pk: (pk not in pending, pending[pk].created_at if pk in pending else now),
    )
    for vm_pk in order:
        _skips.pop(vm_ids[vm_pk], None)
        verdict = _try_one(vm_pk, miner_id, pending.get(vm_pk), watch, now)
        if verdict == "started":
            return 1
        if verdict == "alive":
            return 0
    return 0


def _try_one(
    vm_pk: int, miner_id: str, af: AutoFailover | None, watch: FailoverDeadWatch, now: Any
) -> str:
    """Open the VM's failover if it qualifies and a destination has room.
    `started` (a job was opened, or found already open for it), `alive`
    (the fresh proof failed: stop), or `skipped`."""
    from apps.backup import service as backup_service
    from apps.backup.models import BackupPolicy, FailoverMode

    from . import restore, service

    vm = Vm.objects.get(pk=vm_pk)
    policy = BackupPolicy.objects.filter(vm_id=vm_pk).select_related("vm").first()
    if (
        policy is None
        or policy.failover_mode != FailoverMode.AUTO
        or vm.state != VmState.ACTIVE
        or vm.host != miner_id
    ):
        # No longer an auto VM on this miner: nothing to report.
        return "skipped"
    eligible, blocker = backup_service.failover_auto_status(policy)
    if not eligible:
        # No peer right now (one cordoned, quarantined, unlocated) is the
        # room the wait already waits for: it keeps its id. Anything else
        # ends it.
        if af is not None and blocker != "no-failover-peer":
            _cancel_pending(AutoFailover.objects.filter(pk=af.pk), f"not eligible: {blocker}")
        return _skip(vm, miner_id, f"not-eligible:{blocker}")
    if vm.power_state in (VmPowerState.STARTING, VmPowerState.STOPPING):
        # A power order in flight: whatever it does decides what to restore.
        return _skip(vm, miner_id, f"power-{vm.power_state}")
    if service._has_active_job(vm):
        return _skip(vm, miner_id, "job-in-flight")
    if (
        LaunchJob.objects.filter(vm_id=vm.vm_id)
        .exclude(state__in=TERMINAL_LAUNCH_STATES)
        .exists()
    ):
        return _skip(vm, miner_id, "launch-in-flight")
    reason, backoff = _backoff(vm, miner_id, now)
    if backoff:
        if af is not None:
            AutoFailover.objects.filter(pk=af.pk).update(reason=backoff[:256], updated_at=now)
        return _skip(vm, miner_id, reason, detail=backoff)
    failover_id = af.failover_id if af is not None else secrets.token_hex(16)
    try:
        dest = restore._pick_failover_dest(vm, miner_id, region=backup_service.vm_region(vm))
    except restore.RestoreError as exc:
        return _refused(vm, miner_id, af, failover_id, watch, exc, now)
    # The proof, taken afresh right before the job opens: never a cached
    # verdict, whatever the probe interval.
    evidence = _probe(vm_pk, miner_id, now)
    if not evidence.get("dead"):
        saw_alive(miner_id, "alive at the final check before the job")
        return "alive"
    evidence = {**evidence, "dead_since": watch.dead_since.isoformat(), "auto_after_s": after_s()}
    try:
        job, created = restore.start_failover(
            vm=vm,
            request_id=f"auto-{failover_id}",
            decided_by=_actor(),
            dest_node_id=dest,
            trigger="auto",
            job_id=failover_id,
            evidence=evidence,
        )
    except restore.RestoreError as exc:
        return _refused(vm, miner_id, af, failover_id, watch, exc, now)
    _record_started(vm, miner_id, af, evidence, job, now)
    log.error(
        "failover-auto: STARTED failover %s of vm %s off dead miner %s → %s (dead since %s)%s",
        job.job_id,
        vm.vm_id,
        miner_id,
        job.dest_node_id,
        evidence.get("dead_since"),
        "" if created else " (replayed)",
    )
    return "started"


def _refused(
    vm: Vm,
    miner_id: str,
    af: AutoFailover | None,
    failover_id: str,
    watch: FailoverDeadWatch,
    exc: Any,
    now: Any,
) -> str:
    if exc.code != "no-eligible-miner":
        return _skip(vm, miner_id, f"refused:{exc.code}", detail=exc.detail)
    evidence = {
        **watch.evidence,
        "dead_since": watch.dead_since.isoformat(),
        "auto_after_s": after_s(),
    }
    _wait_for_room(vm, miner_id, af, failover_id, evidence, exc.detail, now)
    return "skipped"


def _skip(vm: Vm, miner_id: str, reason: str, *, detail: str = "") -> str:
    """Pass over an auto VM on a dead miner, LOUDLY: logged at ERROR once per
    (vm, reason), and kept for the `hippius_failover_auto_skipped` gauge —
    a dead miner whose auto VMs are never failed over must not be silent."""
    _skips[vm.vm_id] = (miner_id, reason)
    if (vm.vm_id, miner_id, reason) not in _skips_logged:
        _skips_logged.add((vm.vm_id, miner_id, reason))
        log.error(
            "failover-auto: dead miner %s: auto vm %s skipped (%s)%s",
            miner_id,
            vm.vm_id,
            reason,
            f" — {detail}" if detail else "",
        )
    return "skipped"


def _forget_skips(miner_id: str) -> None:
    """The miner is back: its skips and their log memo go."""
    for vm_id in [v for v, (m, _) in _skips.items() if m == miner_id]:
        del _skips[vm_id]
    for key in [k for k in _skips_logged if k[1] == miner_id]:
        _skips_logged.discard(key)


def _backoff(vm: Vm, miner_id: str, now: Any) -> tuple[str, str]:
    """`(reason, why)` the VM must not be tried again yet after failed
    automatic failovers off `miner_id`, or `("", "")`. Two reasons —
    `backoff-retry` (later) and `backoff-exhausted` (an operator must reset
    it) — so giving up is logged even after the retries were."""
    from . import restore
    from .models import AutoFailoverReset

    jobs = MigrationJob.objects.filter(
        vm=vm,
        kind=MigrationKind.FAILOVER.value,
        trigger="auto",
        source_node_id=miner_id,
        state__in=TERMINAL_MIGRATION_STATES,
    ).order_by("-finished_at")
    reset = AutoFailoverReset.objects.filter(vm=vm).order_by("-reset_at").first()
    if reset is not None:
        # An operator looked (`vali_failover_auto reset`): only what failed
        # since counts.
        jobs = jobs.filter(finished_at__gt=reset.reset_at)
    failed = [job for job in jobs if restore.outcome(job) in ("failed", "reverted")]
    if len(failed) >= MAX_FAILED_ATTEMPTS:
        return (
            "backoff-exhausted",
            f"{len(failed)} automatic failovers failed; an operator must look "
            "(then `manage.py vali_failover_auto reset --vm-id ...`)",
        )
    last = failed[0].finished_at if failed else None
    if last is not None and (now - last).total_seconds() < RETRY_BACKOFF_S:
        return (
            "backoff-retry",
            f"the last automatic failover failed at {last.isoformat()}; retrying later",
        )
    return "", ""


def _wait_for_room(
    vm: Vm,
    miner_id: str,
    af: AutoFailover | None,
    failover_id: str,
    evidence: dict[str, Any],
    why: str,
    now: Any,
) -> None:
    if af is None:
        try:
            with transaction.atomic():
                af = AutoFailover.objects.create(
                    failover_id=failover_id,
                    vm=vm,
                    source_node_id=miner_id,
                    state=AutoFailoverState.PENDING_CAPACITY,
                    evidence=evidence,
                )
        except IntegrityError:
            log.error(
                "failover-auto: vm %s already has an open wait; not recording another", vm.vm_id
            )
            return
        log.error(
            "failover-auto: vm %s off dead miner %s is PENDING CAPACITY (%s): %s",
            vm.vm_id,
            miner_id,
            failover_id,
            why,
        )
    AutoFailover.objects.filter(pk=af.pk).update(
        attempts=af.attempts + 1, last_tried_at=now, reason=why[:256], updated_at=now
    )


def _record_started(
    vm: Vm,
    miner_id: str,
    af: AutoFailover | None,
    evidence: dict[str, Any],
    job: MigrationJob,
    now: Any,
) -> None:
    fields = {"state": AutoFailoverState.STARTED, "job": job, "last_tried_at": now, "reason": ""}
    if af is not None:
        AutoFailover.objects.filter(pk=af.pk).update(
            **fields, attempts=af.attempts + 1, updated_at=now
        )
        return
    AutoFailover.objects.update_or_create(
        failover_id=job.job_id,
        defaults=fields,
        create_defaults={
            **fields,
            "failover_id": job.job_id,
            "vm": vm,
            "source_node_id": miner_id,
            "evidence": evidence,
            "attempts": 1,
        },
    )


def _reconcile_rows() -> None:
    """Repair a crash between a job opening and its `AutoFailover` update:
    a wait whose id is now a job's is that job's; an automatic job with no
    row gets one (the audit trail)."""
    for af in AutoFailover.objects.filter(job__isnull=True).exclude(
        state=AutoFailoverState.STARTED
    ):
        job = MigrationJob.objects.filter(job_id=af.failover_id).first()
        if job is not None:
            AutoFailover.objects.filter(pk=af.pk).update(
                state=AutoFailoverState.STARTED, job=job, reason=""
            )
            log.warning("failover-auto: linked wait %s to its job", af.failover_id)
    for job in MigrationJob.objects.filter(
        kind=MigrationKind.FAILOVER.value, trigger="auto", auto_failover__isnull=True
    ).select_related("authorization"):
        AutoFailover.objects.get_or_create(
            failover_id=job.job_id,
            defaults={
                "vm_id": job.vm_id,
                "source_node_id": job.source_node_id,
                "state": AutoFailoverState.STARTED,
                "job": job,
                "evidence": job.authorization.evidence if job.authorization else {},
                "attempts": 1,
            },
        )
        log.warning("failover-auto: recorded the missing audit row of job %s", job.job_id)


def _open_auto_job(miner_id: str) -> bool:
    return (
        MigrationJob.objects.filter(
            kind=MigrationKind.FAILOVER.value, trigger="auto", source_node_id=miner_id
        )
        .exclude(state__in=TERMINAL_MIGRATION_STATES)
        .exists()
    )


def _cancel_pending(rows: Any, why: str) -> None:
    now = timezone.now()
    for af in rows.filter(state=AutoFailoverState.PENDING_CAPACITY):
        n = AutoFailover.objects.filter(
            pk=af.pk, state=AutoFailoverState.PENDING_CAPACITY
        ).update(state=AutoFailoverState.CANCELLED, reason=why[:256], finished_at=now)
        if n:
            log.warning(
                "failover-auto: %s for vm %s CANCELLED (%s)", af.failover_id, af.vm_id, why
            )


# ── gauges ───────────────────────────────────────────────────────────


def report_metrics(*, now: Any = None) -> Any:
    from apps.synthetic import metrics

    from . import restore

    now = now or timezone.now()
    ms = metrics.MetricSet()
    ms.gauge(M_ENABLED, 1 if enabled() else 0, help_text="1 while automatic failover is on.")
    for job in (
        MigrationJob.objects.filter(kind=MigrationKind.FAILOVER.value, trigger="auto")
        .exclude(state__in=TERMINAL_MIGRATION_STATES)
        .select_related("vm")
    ):
        ms.gauge(
            M_JOBS,
            1,
            help_text="1 per open automatic failover job, labelled with its phase.",
            failover_id=job.job_id,
            vm=job.vm.vm_id,
            miner=job.source_node_id,
            phase=restore.phase(job),
        )
    for job in _fence_undecided().select_related("vm", "authorization"):
        since = restore._parse_ts(job.authorization.evidence.get("fence_undecided_since"))
        if since is not None:
            ms.gauge(
                M_UNDECIDED,
                int(since.timestamp()),
                help_text="Since when (unix ts) a failover waits at the fence: its source "
                "answers again but vali cannot tell whether the KBS moved.",
                failover_id=job.job_id,
                vm=job.vm.vm_id,
                miner=job.source_node_id,
                trigger=job.trigger,
            )
    for af in AutoFailover.objects.filter(
        state=AutoFailoverState.PENDING_CAPACITY
    ).select_related("vm"):
        ms.gauge(
            M_PENDING,
            int(af.created_at.timestamp()),
            help_text="Since when (unix ts) a VM off a dead miner waits for a destination "
            "with room.",
            failover_id=af.failover_id,
            vm=af.vm.vm_id,
            miner=af.source_node_id,
        )
    for job in MigrationJob.objects.filter(
        kind=MigrationKind.FAILOVER.value,
        trigger="auto",
        state__in=TERMINAL_MIGRATION_STATES,
        finished_at__gte=now - timedelta(hours=24),
    ).select_related("vm"):
        outcome = restore.outcome(job)
        labels = {"failover_id": job.job_id, "vm": job.vm.vm_id, "miner": job.source_node_id}
        if outcome in ("failed", "reverted"):
            ms.gauge(
                M_FAILED,
                1,
                help_text="1 per automatic failover that ended failed or reverted in the "
                "last 24 h.",
                outcome=outcome,
                **labels,
            )
        elif outcome == "cancelled":
            ms.gauge(
                M_CANCELLED,
                1,
                help_text="1 per automatic failover cancelled at the fence in the last 24 h "
                "(`why`: miner-back / held).",
                why=restore.cancelled_at_fence(job) or "unknown",
                **labels,
            )
    for vm_id, (miner_id, reason) in sorted(_skips.items()):
        ms.gauge(
            M_SKIPPED,
            1,
            help_text="1 per auto VM on a dead miner the worker passed over, and why.",
            vm=vm_id,
            miner=miner_id,
            reason=reason,
        )
    open_since: dict[str, Any] = {}
    for miner_id, created_at in FailoverQuarantine.objects.filter(
        cleared_at__isnull=True
    ).values_list("miner_id", "created_at"):
        if miner_id not in open_since or created_at < open_since[miner_id]:
            open_since[miner_id] = created_at
    for miner_id, since in sorted(open_since.items()):
        # Not dispatchable while open: it also counts as no failover peer,
        # so its region's `failover_capable` can read false.
        ms.gauge(
            M_QUARANTINE_OPEN,
            max(0, int((now - since).total_seconds())),
            help_text="Seconds a miner has been failover-quarantined (open, not cleared).",
            miner=miner_id,
        )
    for miner_id, n in _blocked_miners(now).items():
        ms.gauge(
            M_BLOCKED,
            n,
            help_text="Auto VMs on a miner dead for VALI_FAILOVER_AUTO_AFTER_S with no "
            "automatic failover job open nor waiting for room.",
            miner=miner_id,
        )
    ms.gauge(
        M_DEAD,
        dead_count(now=now),
        help_text="Miners that look dead now (watched by the worker, or silent).",
    )
    ms.gauge(
        M_HELD,
        1 if enabled() and held(now=now) else 0,
        help_text="1 while too many miners look dead at once for the worker to act.",
    )
    ms.gauge(M_TIMESTAMP, int(now.timestamp()), help_text="Unix ts of this report.")
    return ms


def _fence_undecided() -> Any:
    return (
        MigrationJob.objects.filter(kind=MigrationKind.FAILOVER.value)
        .exclude(state__in=TERMINAL_MIGRATION_STATES)
        .filter(authorization__evidence__has_key="fence_undecided_since")
    )


def _blocked_miners(now: Any) -> dict[str, int]:
    """`{miner_id: auto VMs on it}` for each miner the worker has seen dead
    for at least `VALI_FAILOVER_AUTO_AFTER_S` whose auto VMs have neither an
    open automatic failover job nor a wait for room — dead, and nothing is
    happening (`HippiusAutoFailoverBlocked`). Empty while the worker is off
    or held: `HippiusAutoFailoverHeld` already says why nothing moves."""
    from apps.backup.models import BackupPolicy, FailoverMode

    out: dict[str, int] = {}
    if not enabled() or held(now=now):
        return out
    for watch in FailoverDeadWatch.objects.filter(
        dead_since__lte=now - timedelta(seconds=after_s())
    ):
        vms = list(
            BackupPolicy.objects.filter(
                enabled=True,
                failover_mode=FailoverMode.AUTO,
                vm__state=VmState.ACTIVE,
                vm__host=watch.miner_id,
            ).values_list("vm_id", flat=True)
        )
        if not vms or _open_auto_job(watch.miner_id):
            continue
        if AutoFailover.objects.filter(
            vm_id__in=vms,
            state=AutoFailoverState.PENDING_CAPACITY,
            source_node_id=watch.miner_id,
        ).exists():
            continue
        out[watch.miner_id] = len(vms)
    return out


def _push_metrics(*, now: Any = None, force: bool = False) -> None:
    global _last_push
    from apps.synthetic import metrics

    if not force and time.monotonic() - _last_push < PUSH_INTERVAL_S:
        return
    _last_push = time.monotonic()
    try:
        metrics.push(
            report_metrics(now=now),
            gateway_url=settings.VALI_SYNTHETIC_PUSHGATEWAY_URL,
            job=settings.VALI_GUEST_REPORT_PUSH_JOB,
            grouping_key={"report": "failover-auto"},
            replace=True,
        )
    except Exception:  # noqa: BLE001 — the gauges must not break the pass.
        log.exception("failover-auto: metrics push failed")
