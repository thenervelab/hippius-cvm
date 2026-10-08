"""Guest upgrade report — the gauges the `hippius-guest-upgrade` alerts read
(docs/design/guest-component-rollout.md, "Detection and metrics").

Run by the `guest-report` CronJob (`vali_guest_report`), DB-only, pushed
to the Pushgateway like the golden freshness report:

- rollouts: `hippius_guest_rollout_state{rollout,release,state}` (1) and
  `hippius_guest_rollout_jobs{rollout,state}`;
- jobs: `hippius_guest_upgrade_jobs{state}` (in flight),
  `hippius_guest_upgrade_outcomes_24h{state}` (terminal in the last 24 h),
  `hippius_guest_upgrade_failures_24h{state,outcome,suspect}` (those that
  failed their target, by WHY — `guest_upgrade.OUTCOMES` — and whose side
  it points at: `release` = our build, `miner` = possibly an obstructing
  miner),
  `hippius_guest_upgrade_overdue_seconds{upgrade_job,vm,state}` (past its
  state's deadline — a parking job that cannot confirm DOWN, an open
  attempt);
- VMs needing an operator: `hippius_guest_vm_upgrade_stuck{vm,upgrade_job,
  state,outcome,suspect,power,tenant}` — since when (unix ts) an active VM's
  latest job (cancelled ones and a pending retry aside) is `upgrade_blocked`
  / `failed` (not one a §25 move ended), or parking; `power` is the VM's
  power state (`stopped` = an outage), `tenant` whether it has a tenant
  (`yes` / `no`). It holds until a later job (a retry) that took the VM
  replaces it — a recovery start only moves `power`;
- VMs: `hippius_guest_vm_behind_since_seconds{vm,lag}` — since when a build
  of a newer release (`lag="release"`) or of a release with a higher
  security epoch (`lag="security"`) has existed for the VM's base, judged
  on the release the VM actually BOOTED (a staged swap not relaunched yet
  does not count);
- T4, two signals:
  - `hippius_guest_superseded_attestations_24h{vm,node}` — live
    attestations of a launch of the VM a later accepted launch superseded
    (`VmLiveAttestation.resource_verdict == "superseded"`, judged at
    ingest with its own grace): a guest that should be gone still runs;
  - `hippius_guest_kbs_superseded_refusals_24h{vm,reason}` — keepalives the
    KBS REFUSED because they came from the VM's own superseded guest:
    `superseded-launch` (its released guest, launch no longer current) or
    `superseded-guest` (the guest released before the current one), read
    from the verified KBS release audit log (`kbs_audit` ingest; inert
    until `VALI_KBS_AUDIT_INGEST_ENABLED`). Only keepalive denials
    (`ticket_id` empty), only chain-verified entries, only past the VM's
    last launch transition plus the stop margin (a request in flight at an
    honest hand-over is not a finding);
  - `hippius_guest_live_on_stopped{vm,node}` — a live attestation of a VM
    recorded stopped by a completed power stop, verified well after the
    stop (past the KBS clock skew and the nonce lifetime): the miner kept
    the domain;
- the KBS audit ingest (`kbs_audit`), per chain: `hippius_kbs_audit_lag_records
  {log}` — how many records the KBS head seen by the last run is ahead of
  what vali holds — and `hippius_kbs_audit_checked_timestamp_seconds{log}` —
  when an ingest run last read that head (0 = never): a stale one means the
  ingest does not run;
- `hippius_guest_report_timestamp_seconds`.

Labels never use `job` or `kind`: the Pushgateway's grouping labels would
overwrite them.
"""

from __future__ import annotations

import time
from collections import defaultdict
from datetime import timedelta

from django.conf import settings
from django.db.models import Count
from django.utils import timezone

from apps.lifecycle.models import Vm, VmPowerState, VmState
from apps.synthetic import metrics

from . import guest_upgrade
from .models import (
    TERMINAL_GUEST_ROLLOUT_STATES,
    TERMINAL_GUEST_UPGRADE_STATES,
    GuestInitrdBuild,
    GuestRollout,
    GuestUpgradeJob,
    LaunchJob,
    LaunchJobState,
)
from .services import launch_record

M_ROLLOUT_STATE = "hippius_guest_rollout_state"
M_ROLLOUT_JOBS = "hippius_guest_rollout_jobs"
M_JOBS = "hippius_guest_upgrade_jobs"
M_OUTCOMES = "hippius_guest_upgrade_outcomes_24h"
M_FAILURES = "hippius_guest_upgrade_failures_24h"
M_STUCK = "hippius_guest_vm_upgrade_stuck"
M_OVERDUE = "hippius_guest_upgrade_overdue_seconds"
M_BEHIND = "hippius_guest_vm_behind_since_seconds"
M_SUPERSEDED = "hippius_guest_superseded_attestations_24h"
M_LIVE_ON_STOPPED = "hippius_guest_live_on_stopped"
M_KBS_SUPERSEDED = "hippius_guest_kbs_superseded_refusals_24h"

#: The KBS keepalive refusals that name the VM's OWN guest (its identity
#: checked against the release-recorded binding first, kbs-core #1405):
#: matched EXACTLY — `superseded-launch-unbound` (identity not verified)
#: shares the first one's prefix and proves nothing.
KBS_T4_REASONS: dict[str, str] = {
    "lifecycle: superseded-launch:": "superseded-launch",
    "attestation: superseded-guest:": "superseded-guest",
}
M_REPORT_TS = "hippius_guest_report_timestamp_seconds"
M_KBS_AUDIT_LAG = "hippius_kbs_audit_lag_records"
M_KBS_AUDIT_CHECKED = "hippius_kbs_audit_checked_timestamp_seconds"

#: How far back the T4 detectors look.
T4_WINDOW_S = 24 * 3600


def _kbs_nonce_ttl_s() -> int:
    """The KBS nonce lifetime (its `nonce_ttl_secs`, chart
    `kbs.nonceTtlSecs`): a report may be taken up to this long before the
    KBS verifies it. `VALI_KBS_NONCE_TTL_S` must follow the KBS value."""
    return int(getattr(settings, "VALI_KBS_NONCE_TTL_S", 300))


def _live_on_stopped_margin_s() -> int:
    """A live attestation verified this long after a completed power stop
    cannot be one in flight at the stop: the KBS's clock may run the
    accepted skew (`VALI_UPTIME_LIVENESS_SKEW_S`) ahead of vali's, and the
    report may predate its verification by a nonce lifetime."""
    skew = int(getattr(settings, "VALI_UPTIME_LIVENESS_SKEW_S", 300))
    return skew + _kbs_nonce_ttl_s() + 60


#: kernel, rootfs.img, rootfs.verity, verity root hash, base initrd.
Base = tuple[str, str, str, str, str]


def _base(spec: dict, by_initrd: dict[str, GuestInitrdBuild]) -> Base:
    initrd = str(spec.get("initrd_sha256_hex") or "").lower()
    build = by_initrd.get(initrd)
    return (
        str(spec.get("kernel_sha256_hex") or "").lower(),
        str(spec.get("rootfs_img_sha256_hex") or "").lower(),
        str(spec.get("rootfs_verity_sha256_hex") or "").lower(),
        str(spec.get("verity_root_hash_hex") or "").lower(),
        build.base_initrd_sha256 if build is not None else initrd,
    )


def _behind(ms: metrics.MetricSet) -> None:
    """One pass: the usable builds by base, the latest launch record of
    every active VM, then a dict lookup per VM."""
    builds = list(
        GuestInitrdBuild.objects.filter(
            withdrawn_at__isnull=True, release__withdrawn_at__isnull=True
        ).select_related("release")
    )
    if not builds:
        return
    by_base: dict[Base, list[GuestInitrdBuild]] = defaultdict(list)
    by_initrd: dict[str, GuestInitrdBuild] = {}
    for b in builds:
        by_base[
            (
                b.kernel_sha256,
                b.rootfs_img_sha256,
                b.rootfs_verity_sha256,
                b.verity_root_hash,
                b.base_initrd_sha256,
            )
        ].append(b)
    for b in GuestInitrdBuild.objects.select_related("release"):
        by_initrd[b.initrd_sha256] = b
    active = set(Vm.objects.filter(state=VmState.ACTIVE).values_list("vm_id", flat=True))
    latest: dict[str, LaunchJob] = {}
    for job in LaunchJob.objects.filter(
        vm_id__in=active, state=LaunchJobState.SUCCEEDED.value
    ).order_by("vm_id", "-finished_at"):
        latest.setdefault(job.vm_id, job)
    for vm_id in sorted(latest):
        record = latest[vm_id]
        candidates = by_base.get(_base(record.spec_json or {}, by_initrd), [])
        if not candidates:
            continue
        booted = by_initrd.get(launch_record.booted_artifacts(record)[1].lower())
        version = int(booted.release_id) if booted is not None else 0
        epoch = int(booted.release.security_epoch) if booted is not None else 0
        newer = [b for b in candidates if int(b.release_id) > version]
        if newer:
            ms.gauge(
                M_BEHIND,
                min(b.registered_at for b in newer).timestamp(),
                help_text="Unix ts since a build of a newer guest release (lag=release) or of "
                "a higher security epoch (lag=security) has existed for the VM's base.",
                vm=vm_id,
                lag="release",
            )
        raising = [b for b in newer if int(b.release.security_epoch) > epoch]
        if raising:
            ms.gauge(
                M_BEHIND,
                min(b.registered_at for b in raising).timestamp(),
                help_text="",
                vm=vm_id,
                lag="security",
            )


def _kbs_superseded(ms: metrics.MetricSet, since: int) -> None:
    """The KBS-refused keepalives of a VM's own superseded guest (see the
    module docs). Alert-only: nothing here penalises a miner. Off until
    `VALI_GUEST_KBS_T4_ENABLED`: a KBS before #1405 evaluates
    `superseded-launch` before the guest binding, and its refusals prove
    nothing — turn it on only once the KBS carries #1405."""
    from django.db.models import Max, Q

    from .models import KbsAuditEntry, MeasurementLedger

    if not getattr(settings, "VALI_GUEST_KBS_T4_ENABLED", False):
        return
    match = Q()
    for prefix in KBS_T4_REASONS:
        match |= Q(reason__startswith=prefix)
    rows = list(
        KbsAuditEntry.objects.filter(
            match,
            log="release",
            granted=False,
            chain_ok=True,
            ticket_id="",
            event_unix__gte=since,
        )
        .order_by()
        .values_list("vm_id", "reason", "event_unix")
    )
    if not rows:
        return
    # Each VM's last hand-over: a superseding register, a launch accepted,
    # or ANY release the KBS granted (an in-guest reboot keeps the launch
    # but releases to a new guest, whose binding replaces the old one: an
    # old request in flight then reads `superseded-guest`).
    transitions: dict[str, int] = {}
    for vm_id, sup, launched in (
        MeasurementLedger.objects.filter(vm_id__in={r[0] for r in rows})
        .values("vm_id")
        .annotate(sup=Max("superseded_at_register"), launched=Max("launched_at"))
        .values_list("vm_id", "sup", "launched")
    ):
        times = [t.timestamp() for t in (sup, launched) if t is not None]
        transitions[vm_id] = int(max(times)) if times else 0
    for vm_id, released in (
        KbsAuditEntry.objects.filter(
            vm_id__in={r[0] for r in rows}, log="release", granted=True, chain_ok=True
        )
        .exclude(ticket_id="")
        .order_by()
        .values("vm_id")
        .annotate(t=Max("event_unix"))
        .values_list("vm_id", "t")
    ):
        if released is not None:
            transitions[vm_id] = max(transitions.get(vm_id, 0), int(released))
    margin = _live_on_stopped_margin_s()
    counts: dict[tuple[str, str], int] = defaultdict(int)
    for vm_id, reason, at in rows:
        label = next((v for k, v in KBS_T4_REASONS.items() if reason.startswith(k)), None)
        if label is None or at is None or at <= transitions.get(vm_id, 0) + margin:
            continue
        counts[(vm_id, label)] += 1
    for (vm_id, label), n in sorted(counts.items()):
        ms.gauge(
            M_KBS_SUPERSEDED,
            n,
            help_text="Keepalives the KBS refused in the last 24 h because they came from the "
            "VM's own superseded guest (T4: the miner kept an earlier guest running).",
            vm=vm_id,
            reason=label,
        )


def _t4(ms: metrics.MetricSet, now_unix: float) -> None:
    from apps.telemetry.models import VmLiveAttestation

    since = int(now_unix - T4_WINDOW_S)
    # Counted in SQL on the partial index (`telemetry_vla_superseded_idx`).
    superseded = (
        VmLiveAttestation.objects.filter(verified_at_unix__gte=since, resource_verdict="superseded")
        .order_by()
        .values_list("vm_id", "node_id_hex")
        .annotate(n=Count("id"))
    )
    for vm_id, node, n in sorted(superseded):
        ms.gauge(
            M_SUPERSEDED,
            n,
            help_text="Live attestations in the last 24 h of a launch a later accepted "
            "launch superseded (T4: a guest that should be gone still runs).",
            vm=vm_id,
            node=node,
        )
    _kbs_superseded(ms, since)
    margin = _live_on_stopped_margin_s()
    stopped = [
        vm
        for vm in Vm.objects.filter(state=VmState.ACTIVE, power_state=VmPowerState.STOPPED)
        if vm.stopped_by_order
    ]
    if not stopped:
        return
    newest: dict[str, int] = {}
    for vm_id, at in VmLiveAttestation.objects.filter(
        vm_id__in=[vm.vm_id for vm in stopped], verified_at_unix__gte=since
    ).values_list("vm_id", "verified_at_unix"):
        newest[vm_id] = max(newest.get(vm_id, 0), at)
    for vm in stopped:
        if newest.get(vm.vm_id, 0) > vm.power_state_at.timestamp() + margin:
            ms.gauge(
                M_LIVE_ON_STOPPED,
                1,
                help_text="A VM recorded stopped by a completed power stop whose guest a live "
                "attestation shows running well after it (T4: the miner kept the domain).",
                vm=vm.vm_id,
                node=vm.host or "",
            )


def _stuck(ms: metrics.MetricSet) -> None:
    """The active VMs whose latest guest upgrade job needs an operator."""
    from .models import GuestUpgradeState as S

    # Each VM's anchor job (`guest_upgrade.anchor_job`): a cancelled job
    # never moved anything, and a pending retry has not taken the VM yet —
    # the VM stays down (and alerting) until the retry runs.
    latest: dict[str, GuestUpgradeJob] = {}
    for job in (
        GuestUpgradeJob.objects.filter(vm__state=VmState.ACTIVE)
        .exclude(state=S.CANCELLED.value)
        .exclude(state=S.PENDING.value, retry_of__isnull=False)
        .select_related("vm")
        .order_by("vm_id", "-started_at")
    ):
        latest.setdefault(job.vm_id, job)
    for job in sorted(latest.values(), key=lambda j: j.vm.vm_id):
        if job.state == S.PARKING:
            since = job.phase_started_at
        elif (
            job.state in guest_upgrade.RECOVERABLE_STATES and job.outcome != guest_upgrade.VM_MOVED
        ):
            since = job.finished_at or job.phase_started_at
        else:
            continue
        ms.gauge(
            M_STUCK,
            since.timestamp(),
            help_text="Unix ts since an active VM's latest guest upgrade job ended "
            "upgrade_blocked / failed (or parks): the VM needs an operator.",
            vm=job.vm.vm_id,
            upgrade_job=job.job_id,
            state=job.state,
            outcome=job.outcome or "unknown",
            suspect=guest_upgrade.OUTCOME_SUSPECT.get(job.outcome, "unknown"),
            power=job.vm.power_state or "unknown",
            tenant="yes" if job.vm.tenant_id else "no",
        )


def _kbs_audit(ms: metrics.MetricSet) -> None:
    """How far the KBS audit ingest is behind each chain, and when it last
    read the head. A chain vali never ingested has no cursor and no gauge."""
    from .models import KbsAuditCursor

    for cursor in KbsAuditCursor.objects.order_by("log"):
        if cursor.head_seq is not None:
            ms.gauge(
                M_KBS_AUDIT_LAG,
                max(0, cursor.head_seq - cursor.last_seq),
                help_text="Records of the KBS audit chain past what vali holds, at the head "
                "the last ingest run saw.",
                log=cursor.log,
            )
        ms.gauge(
            M_KBS_AUDIT_CHECKED,
            int(cursor.checked_at.timestamp()) if cursor.checked_at is not None else 0,
            help_text="Unix ts an ingest run last read the KBS audit chain's head (0 = never).",
            log=cursor.log,
        )


def report_metrics() -> metrics.MetricSet:
    now = timezone.now()
    ms = metrics.MetricSet()

    for rollout in GuestRollout.objects.exclude(state__in=TERMINAL_GUEST_ROLLOUT_STATES):
        ms.gauge(
            M_ROLLOUT_STATE,
            1,
            help_text="1 per open guest rollout, labelled with its state.",
            rollout=rollout.rollout_id,
            release=str(rollout.release_id),
            state=rollout.state,
        )
        counts: dict[str, int] = defaultdict(int)
        for state in rollout.jobs.values_list("state", flat=True):
            counts[state] += 1
        for state, n in sorted(counts.items()):
            ms.gauge(
                M_ROLLOUT_JOBS,
                n,
                help_text="A guest rollout's jobs by state.",
                rollout=rollout.rollout_id,
                state=state,
            )

    in_flight: dict[str, int] = defaultdict(int)
    for job in GuestUpgradeJob.objects.exclude(
        state__in=TERMINAL_GUEST_UPGRADE_STATES
    ).select_related("vm"):
        in_flight[job.state] += 1
        if job.state == "pending":
            continue
        over = (now - job.phase_started_at).total_seconds() - guest_upgrade._state_timeout(job)
        if over > 0:
            ms.gauge(
                M_OVERDUE,
                round(over),
                help_text="Seconds a guest upgrade job is past its state's deadline.",
                upgrade_job=job.job_id,
                vm=job.vm.vm_id,
                state=job.state,
            )
    for state, n in sorted(in_flight.items()):
        ms.gauge(M_JOBS, n, help_text="Guest upgrade jobs in flight, by state.", state=state)

    recent: dict[str, int] = defaultdict(int)
    for state in GuestUpgradeJob.objects.filter(
        state__in=TERMINAL_GUEST_UPGRADE_STATES, finished_at__gte=now - timedelta(hours=24)
    ).values_list("state", flat=True):
        recent[state] += 1
    for state in TERMINAL_GUEST_UPGRADE_STATES:
        ms.gauge(
            M_OUTCOMES,
            recent.get(state, 0),
            help_text="Guest upgrade jobs that ended in the last 24 h, by outcome.",
            state=state,
        )

    failures: dict[tuple[str, str], int] = defaultdict(int)
    for state, outcome in GuestUpgradeJob.objects.filter(
        state__in=TERMINAL_GUEST_UPGRADE_STATES, finished_at__gte=now - timedelta(hours=24)
    ).values_list("state", "outcome"):
        if outcome or state in guest_upgrade.RECOVERABLE_STATES:
            # A job that ended before outcomes were recorded: `unknown`.
            failures[(state, outcome or "unknown")] += 1
    for (state, outcome), n in sorted(failures.items()):
        ms.gauge(
            M_FAILURES,
            n,
            help_text="Guest upgrade jobs whose target failed, ended in the last 24 h, by "
            "outcome and whose side it points at.",
            state=state,
            outcome=outcome,
            suspect=guest_upgrade.OUTCOME_SUSPECT.get(outcome, "unknown"),
        )

    _stuck(ms)
    _behind(ms)
    _t4(ms, time.time())
    _kbs_audit(ms)
    ms.gauge(M_REPORT_TS, metrics.now(), help_text="Unix ts of the last guest upgrade report.")
    return ms
