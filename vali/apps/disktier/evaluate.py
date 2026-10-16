"""The passive disk-health evaluator (design §3.5, phase P2) — RECORD ONLY.

Each run grades the last `VALI_DISK_EVALUATE_HOURS` closed hours of
`VmDiskIoHourly` into one `MinerDiskHealthHourly` row per (miner, pool) and
per (miner, dedicated disk). It writes those rows, `DiskPassiveEvent` rows
and metrics, and nothing else: no tier, health, cordon, placement, reward
or probe is ever touched, whatever `VALI_DISK_TIER_CONSEQUENCES` says
(passive evidence comes from in-VM root, so it may only ever lead to a
probe, and the probe orchestrator is phase R1).

The grading, per target and hour:

1. Samples: every resolved VM device hour (a pool or a dedicated disk) with
   at least `VALI_DISK_PASSIVE_MIN_QD4_READS` reads in QD >= 4 small-I/O
   windows; its value is the read await of those windows,
   `qd4_small_r_ticks_ms * 1000 / qd4_small_r_ios` (µs). Unresolved
   devices (no slot serial, or a slot the placement does not hold) are
   never graded.
2. Per owner (`Placement.owner`; a blank owner is one shared "unknown"
   vote), the median of its samples; then the median and p90 (nearest
   rank) across owners: one owner, one vote, whatever its VM count.
3. Threshold: the target's tier — a pool's effective tier (override, else
   verified), else its declared class (a hint, still a better grade than
   none); a dedicated disk's verified tier. No tier ⇒ the hour is recorded
   ungraded (blank `tier` and `verdict`). nvme 3 ms, ssd 8 ms, hdd 80 ms.
4. An owner is suspect when its median exceeded the threshold in each of
   the last `VALI_DISK_PASSIVE_SUSTAIN_HOURS` hours (>= 2 h) on that target.
5. Verdict `suspect` when:
   - an internal owner (`VALI_DISK_PASSIVE_INTERNAL_OWNERS`, our trusted
     witnesses) is suspect — on its own, uncapped (internal-witness rule);
   - or >= 2 non-internal owners are suspect;
   - or exactly one non-internal owner is, and that lone owner has not
     already raised a suspicion on `VALI_DISK_PASSIVE_LONE_OWNER_MAX_MINERS`
     other miners in the cooldown window (single-griefer cap: one tenant
     with VMs everywhere cannot flag the whole fleet). A capped lone owner
     leaves the verdict `ok` and writes a `griefer-capped` event instead.
   Otherwise `ok`.
6. A `suspect` target writes a `would-reprobe` event, at most one per miner
   per `VALI_DISK_PASSIVE_REPROBE_COOLDOWN_S` (design: <= 1 re-probe per
   24 h per miner). Nothing is scheduled.

Re-grading an hour is idempotent: the rollup row is upserted, and the
event rate limit makes a second pass emit nothing new.
"""

from __future__ import annotations

import logging
import math
import statistics
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from django.conf import settings
from django.db import transaction
from django.db.models import Count, Max
from django.utils import timezone

from apps.synthetic import metrics

from .ingest import owner_key
from .models import (
    DedicatedDisk,
    DiskHealth,
    DiskIngestCounter,
    DiskPassiveEvent,
    DiskPassiveEventKind,
    MinerDiskHealthHourly,
    MinerStoragePool,
    VmDiskIoHourly,
)
from .tiers import DiskTier

log = logging.getLogger("apps.disktier.evaluate")

#: Design §3.5: suspect above this hourly per-owner median read await.
THRESHOLD_US: dict[str, int] = {
    DiskTier.NVME.value: 3_000,
    DiskTier.SSD.value: 8_000,
    DiskTier.HDD.value: 80_000,
}
#: The owner key of placements that name none.
UNKNOWN_OWNER = "(unknown)"
#: Clamp for the `PositiveIntegerField` medians.
_US_MAX = 2_147_483_647


@dataclass(frozen=True, order=True)
class Target:
    miner_node_id: str
    pool_id: str
    disk_id: str

    @property
    def scope(self) -> str:
        return "pool" if self.pool_id else "disk"

    @property
    def name(self) -> str:
        return self.pool_id or self.disk_id


@dataclass
class _HourSamples:
    #: owner → that owner's per-device-hour read awaits (µs).
    samples: dict[str, list[int]] = field(default_factory=lambda: defaultdict(list))
    vms: set[str] = field(default_factory=set)

    def owner_medians(self) -> dict[str, int]:
        return {o: _median(v) for o, v in self.samples.items() if v}


@dataclass
class EvaluateReport:
    hours: list[datetime] = field(default_factory=list)
    rows: int = 0
    verdicts: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    would_reprobe: int = 0
    rate_limited: int = 0
    griefer_capped: int = 0


def _median(values: list[int]) -> int:
    return min(_US_MAX, int(statistics.median(values)))


def _p90(values: list[int]) -> int:
    ordered = sorted(values)
    return min(_US_MAX, ordered[max(0, math.ceil(0.9 * len(ordered)) - 1)])


def _hour_floor(at: datetime) -> datetime:
    at = at.astimezone(UTC)
    return at.replace(minute=0, second=0, microsecond=0)


def _samples(hour: datetime) -> dict[Target, _HourSamples]:
    """Every resolved device hour of `hour`, grouped by target."""
    min_reads = int(settings.VALI_DISK_PASSIVE_MIN_QD4_READS)
    out: dict[Target, _HourSamples] = defaultdict(_HourSamples)
    rows = (
        VmDiskIoHourly.objects.filter(hour=hour)
        .exclude(pool_id="", disk_id="")
        .values_list(
            "miner_node_id",
            "pool_id",
            "disk_id",
            "vm_id",
            "owner",
            "qd4_small_r_ios",
            "qd4_small_r_ticks_ms",
        )
    )
    for miner, pool_id, disk_id, vm_id, owner, r_ios, r_ticks in rows.iterator():
        if pool_id and disk_id:
            continue  # never written by the ingest; not one target
        bucket = out[Target(miner, pool_id, disk_id)]
        bucket.vms.add(vm_id)
        if r_ios >= max(1, min_reads):
            bucket.samples[owner or UNKNOWN_OWNER].append(r_ticks * 1000 // r_ios)
    return out


def _tiers(targets: list[Target]) -> dict[Target, str]:
    """The tier each target is graded against ("" = none)."""
    miners = {t.miner_node_id for t in targets}
    pools = {
        (p.miner_node_id, p.pool_id): p
        for p in MinerStoragePool.objects.filter(miner_node_id__in=miners)
    }
    disks = {
        (d.miner_node_id, d.disk_id): d.verified_tier
        for d in DedicatedDisk.objects.filter(miner_node_id__in=miners)
    }
    out: dict[Target, str] = {}
    for t in targets:
        tier = ""
        if t.pool_id:
            pool = pools.get((t.miner_node_id, t.pool_id))
            if pool is not None:
                tier = pool.effective_tier
                if tier not in THRESHOLD_US:
                    tier = pool.declared_class
        else:
            tier = disks.get((t.miner_node_id, t.disk_id), "")
        out[t] = tier if tier in THRESHOLD_US else ""
    return out


def _lone_owner_capped(owner: str, miner_node_id: str, now: datetime) -> bool:
    """The single-griefer cap: has `owner`, alone, already raised a
    suspicion on enough OTHER miners inside the cooldown window?"""
    since = now - timedelta(seconds=int(settings.VALI_DISK_PASSIVE_REPROBE_COOLDOWN_S))
    elsewhere = (
        DiskPassiveEvent.objects.filter(
            kind=DiskPassiveEventKind.WOULD_REPROBE,
            trigger_owner=owner,
            created_at__gte=since,
        )
        .exclude(miner_node_id=miner_node_id)
        .values("miner_node_id")
        .distinct()
        .count()
    )
    return elsewhere >= int(settings.VALI_DISK_PASSIVE_LONE_OWNER_MAX_MINERS)


def _recent_event(kind: str, miner_node_id: str, now: datetime, **match: str) -> bool:
    since = now - timedelta(seconds=int(settings.VALI_DISK_PASSIVE_REPROBE_COOLDOWN_S))
    return DiskPassiveEvent.objects.filter(
        kind=kind, miner_node_id=miner_node_id, created_at__gte=since, **match
    ).exists()


@dataclass(frozen=True)
class _Decision:
    verdict: str
    reason: str
    #: The lone non-internal owner behind the suspicion, if that is what it is.
    lone_owner: str = ""
    capped: bool = False


def decide(suspects: list[str], *, target: Target, now: datetime) -> _Decision:
    """The §3.5 verdict from the target's suspect owners (see the module
    docstring, step 5)."""
    # Stored owners pass through `owner_key` (long ids are hashed).
    internal = {owner_key(o) for o in settings.VALI_DISK_PASSIVE_INTERNAL_OWNERS}
    witnesses = [o for o in suspects if o in internal]
    others = [o for o in suspects if o not in internal]
    if witnesses:
        return _Decision(DiskHealth.SUSPECT, "internal-witness")
    if len(others) >= 2:
        return _Decision(DiskHealth.SUSPECT, "owners")
    if len(others) == 1:
        lone = others[0]
        if _lone_owner_capped(lone, target.miner_node_id, now):
            return _Decision(DiskHealth.OK, "lone-owner-capped", lone_owner=lone, capped=True)
        return _Decision(DiskHealth.SUSPECT, "lone-owner", lone_owner=lone)
    return _Decision(DiskHealth.OK, "")


def evaluate_hour(hour: datetime, *, now: datetime, report: EvaluateReport) -> None:
    sustain = max(1, int(settings.VALI_DISK_PASSIVE_SUSTAIN_HOURS))
    current = _samples(hour)
    if not current:
        return
    history = [_samples(hour - timedelta(hours=k)) for k in range(1, sustain)]
    tiers = _tiers(list(current))
    for target in sorted(current):
        bucket = current[target]
        medians = bucket.owner_medians()
        tier = tiers[target]
        threshold = THRESHOLD_US.get(tier)
        suspects: list[str] = []
        if threshold is not None:
            for owner, median in sorted(medians.items()):
                past = [h.get(target) for h in history]
                if median > threshold and all(
                    p is not None and p.owner_medians().get(owner, 0) > threshold for p in past
                ):
                    suspects.append(owner)
        if threshold is None or not medians:
            decision = _Decision("", "")
        else:
            decision = decide(suspects, target=target, now=now)
        values = list(medians.values())
        with transaction.atomic():
            MinerDiskHealthHourly.objects.update_or_create(
                miner_node_id=target.miner_node_id,
                pool_id=target.pool_id,
                disk_id=target.disk_id,
                hour=hour,
                defaults={
                    "owners": len(medians),
                    "vms": len(bucket.vms),
                    "median_owner_await_us": _median(values) if values else None,
                    "p90_owner_await_us": _p90(values) if values else None,
                    "suspect_owners": len(suspects),
                    "verdict": decision.verdict,
                    "tier": tier if threshold is not None else "",
                },
            )
            _record_events(
                target,
                hour=hour,
                now=now,
                decision=decision,
                detail={
                    "tier": tier,
                    "threshold_us": threshold,
                    "owners": len(medians),
                    "suspect_owners": len(suspects),
                    "median_owner_await_us": _median(values) if values else None,
                    "reason": decision.reason,
                },
                report=report,
            )
        report.rows += 1
        report.verdicts[decision.verdict or "ungraded"] += 1


def _record_events(
    target: Target,
    *,
    hour: datetime,
    now: datetime,
    decision: _Decision,
    detail: dict[str, object],
    report: EvaluateReport,
) -> None:
    if decision.capped:
        # One `griefer-capped` row per (miner, owner) per cooldown.
        if not _recent_event(
            DiskPassiveEventKind.GRIEFER_CAPPED,
            target.miner_node_id,
            now,
            trigger_owner=decision.lone_owner,
        ):
            DiskPassiveEvent.objects.create(
                miner_node_id=target.miner_node_id,
                pool_id=target.pool_id,
                disk_id=target.disk_id,
                hour=hour,
                kind=DiskPassiveEventKind.GRIEFER_CAPPED,
                trigger_owner=decision.lone_owner,
                detail=detail,
                created_at=now,
            )
            report.griefer_capped += 1
            log.info(
                "disk passive: lone-owner suspicion capped on %s/%s hour=%s",
                target.miner_node_id[:12],
                target.name,
                hour.isoformat(),
            )
        return
    if decision.verdict != DiskHealth.SUSPECT:
        return
    if _recent_event(DiskPassiveEventKind.WOULD_REPROBE, target.miner_node_id, now):
        report.rate_limited += 1
        return
    DiskPassiveEvent.objects.create(
        miner_node_id=target.miner_node_id,
        pool_id=target.pool_id,
        disk_id=target.disk_id,
        hour=hour,
        kind=DiskPassiveEventKind.WOULD_REPROBE,
        trigger_owner=decision.lone_owner,
        detail=detail,
        created_at=now,
    )
    report.would_reprobe += 1
    # RECORD ONLY: the re-probe itself is phase R1.
    log.warning(
        "disk passive: %s %s/%s suspect (%s) hour=%s — would schedule a re-probe (record only)",
        target.scope,
        target.miner_node_id[:12],
        target.name,
        decision.reason,
        hour.isoformat(),
    )


def evaluate(*, now: datetime | None = None, hours: int | None = None) -> EvaluateReport:
    """Grade the last `hours` closed hours (default
    `VALI_DISK_EVALUATE_HOURS`), oldest first."""
    now = now or timezone.now()
    if settings.VALI_DISK_TIER_CONSEQUENCES == "enforce":
        log.info("disk passive: evaluator is record-only; `enforce` changes nothing here")
    n = max(1, hours if hours is not None else int(settings.VALI_DISK_EVALUATE_HOURS))
    current = _hour_floor(now)
    report = EvaluateReport()
    for k in range(n, 0, -1):
        hour = current - timedelta(hours=k)
        evaluate_hour(hour, now=now, report=report)
        report.hours.append(hour)
    return report


# ─── metrics (pushed by `vali_disktier_evaluate`) ─────────────────────

M_INGEST = "hippius_disk_ingest_total"
M_TARGETS = "hippius_disk_health_targets"
M_TARGET_AWAIT = "hippius_disk_target_median_await_us"
M_TARGET_SUSPECT = "hippius_disk_target_suspect"
M_EVENTS_24H = "hippius_disk_passive_events_24h"
M_IO_ROWS = "hippius_disk_io_rows"
M_EVAL_TS = "hippius_disk_evaluate_timestamp_seconds"
M_LATEST_HOUR = "hippius_disk_health_latest_hour_seconds"


def report_metrics(*, now: datetime | None = None) -> metrics.MetricSet:
    """The gauges of the last closed hour plus the ingest counters. Labels
    never use `job` or `kind` (the Pushgateway's grouping labels)."""
    now = now or timezone.now()
    hour = _hour_floor(now) - timedelta(hours=1)
    ms = metrics.MetricSet()
    for name, value in DiskIngestCounter.objects.order_by("name").values_list("name", "value"):
        ms.gauge(
            M_INGEST, value, help_text="Passive disk ingest counters (cumulative).", counter=name
        )
    rows = VmDiskIoHourly.objects.filter(hour=hour)
    ms.gauge(M_IO_ROWS, rows.count(), help_text="VM device rows of the last hour.", resolved="any")
    ms.gauge(
        M_IO_ROWS,
        rows.filter(pool_id="", disk_id="").count(),
        resolved="no",
    )
    by_verdict = {
        r["verdict"]: r["n"]
        for r in MinerDiskHealthHourly.objects.filter(hour=hour)
        .order_by()
        .values("verdict")
        .annotate(n=Count("id"))
    }
    for verdict in ("ok", "suspect", ""):
        ms.gauge(
            M_TARGETS,
            by_verdict.get(verdict, 0),
            help_text="Graded pools / dedicated disks of the last hour, by verdict.",
            verdict=verdict or "ungraded",
        )
    for row in MinerDiskHealthHourly.objects.filter(hour=hour).order_by(
        "miner_node_id", "pool_id", "disk_id"
    ):
        scope = "pool" if row.pool_id else "disk"
        labels = {"node": row.miner_node_id, "scope": scope, "target": row.pool_id or row.disk_id}
        if row.median_owner_await_us is not None:
            ms.gauge(
                M_TARGET_AWAIT,
                row.median_owner_await_us,
                help_text="Median across owners of the per-owner QD>=4 read await (µs).",
                **labels,
            )
        ms.gauge(
            M_TARGET_SUSPECT,
            1 if row.verdict == DiskHealth.SUSPECT else 0,
            help_text="1 when the passive evaluator graded the target suspect (record only).",
            **labels,
        )
    since = now - timedelta(hours=24)
    events = {
        r["kind"]: r["n"]
        for r in DiskPassiveEvent.objects.filter(created_at__gte=since)
        .order_by()
        .values("kind")
        .annotate(n=Count("id"))
    }
    for kind in DiskPassiveEventKind.values:
        ms.gauge(
            M_EVENTS_24H,
            events.get(kind, 0),
            help_text="Passive evaluator events over the last 24 h (record only).",
            event=kind,
        )
    latest = MinerDiskHealthHourly.objects.aggregate(h=Max("hour"))["h"]
    ms.gauge(
        M_LATEST_HOUR,
        latest.timestamp() if latest else 0,
        help_text="The newest graded hour (unix s; 0 = none yet).",
    )
    ms.gauge(M_EVAL_TS, time.time(), help_text="When the evaluator last pushed.")
    return ms
