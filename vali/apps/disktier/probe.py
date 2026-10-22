"""The disk-tier probe orchestrator (docs/design/disk-tier-verification.md
§2, §3.2, §4.4, §10 phase R1) — RECORD ONLY.

One `tick` (the `vali_disk_probe` CronJob):

1. **Advance** the runs in flight: `launching` → `running` once the launch
   job succeeds, `failed` (`launch-failed:`) when it fails, `timeout`
   (`probe-timeout`) once `deadline_at` passes with no verdict.
2. **Tear down** every run with a verdict whose lifetime jitter ran out,
   and every timed-out or failed one at once: an in-process §24 first; if
   that has not destroyed the VM after `VALI_DISK_PROBE_TEARDOWN_TIMEOUT_S`
   (or the VM row never materialised), the shared no-leak teardown
   (`apps.orchestration.teardown`). A run is closed (`torn_down_at`) only
   once its VM is destroyed, or provably never existed.
3. **Launch** (only while `VALI_DISK_PROBE_ENABLED`): the due set, in
   order — pools never verified (`onboarding`), then periodic ones
   (`PERIOD ± JITTER` after the last verified probe), then queued runs
   (operator requests, `vali_disk_probe --request <node> [--pool <id>]`).
   Skipped, and retried next tick: a node not dispatchable or hard-gated
   (cordoned, epoch-stale, zombie), a node with a run already in flight
   (1 per miner), the fleet-wide cap (`VALI_DISK_PROBE_MAX_CONCURRENT`),
   fewer than `VALI_DISK_PROBE_MIN_FREE_SLOTS` free admission slots for
   the probe flavor, the node's boot cap reached (the scheduler's own
   capacity and gate-(g) reads), or a queued run whose pool cannot take
   the probe's OS disk any more (`os_pool_skip`).

A run launches ONE probe VM, in-process and pinned to the node's chip
(`launch_jobs.start_launch(..., disk_probe=True)`), with a probe owner
(`VALI_DISK_PROBE_OWNERS`), the `medium` flavor (§3.2), the blessed golden
image, NetBird on, and a request whose `start_delay_s` is random in
`[VALI_DISK_PROBE_START_DELAY_MIN_S, _MAX_S]` (6-48 h): the miner must not
pair a launch with the I/O burst (§2). The run's targets are the OS slot
on the pool the VM's OS disk sits on.

**Pools.** A node without a storage report has one implicit pool,
`default`. A probe of pool P puts its OS disk ON P: the run's
`os_pool_id` rides the launch intent (`os_pool`, accepted from a
disk-probe launch only) to the order's `os_pool` (A4b), every same-miner
retry names it again, and the verdict is recorded against it. `default`
is always probeable and its order carries no `os_pool` (byte for byte
today's). Another pool is probeable when the node's agent takes
`os_pool` (else `needs-os-pool-order`) and the pool is one A4b could
name — active, recently reported, not retired (else `pool-not-active`)
— with room for the probe's OS disk (else `no-room`), whatever its tier
or health (`probe_os_pool`). Hdd-only pools (`os_disks=false`) are R3's
(a dedicated-style extra disk), counted `not-os-eligible`.

**Record only.** A verdict is stored on the run (per target: metrics, the
tier it classifies as, the verdict detail) and in metrics. Nothing here
writes `MinerStoragePool`, a cordon, placement or rewards; the
hysteresis and the consequences are C1. (Writing `last_run` /
`next_probe_due_at` is also left to C1: the operator storage view serves
`last_run` as "last probe on", and must only learn of a probe after its
result, never at launch.)
"""

from __future__ import annotations

import hashlib
import logging
import secrets
import time
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from django.conf import settings
from django.utils import timezone

from apps.synthetic import metrics

from . import probe_userdata, routing
from .models import OS_SLOT, DiskKind, DiskProbeRun, MinerStoragePool, ProbeRunState, ProbeTrigger
from .probe_owners import ProbeOwner, probe_owners
from .storage_doc import DEFAULT_POOL_ID, is_valid_pool_id
from .tiers import DiskTier

log = logging.getLogger("apps.disktier.probe")

#: The ServiceClient every probe launch and §24 is attributed to.
ACTOR_NAME = "disk-probe"
#: The teardown's job reasons and log label.
_CANCEL_REASON = "cancelled by disk-probe teardown (no-leak)"
_HANDOFF_REASON = "disk-probe:destroy-undeliverable"
_LABEL = "disk-probe"
#: How long the fallback teardown waits on a §24 before forcing.
_FALLBACK_WAIT_S = 60.0
_FALLBACK_POLL_S = 5.0

#: States with a probe VM (possibly) alive and no verdict yet.
IN_FLIGHT = (ProbeRunState.LAUNCHING, ProbeRunState.RUNNING)
#: States with a verdict.
VERDICTS = (ProbeRunState.VERIFIED, ProbeRunState.FAILED, ProbeRunState.TIMEOUT)

_rng = secrets.SystemRandom()


# ─── pools and the due set ───────────────────────────────────────────


def probe_os_disk_gb() -> int:
    """What the probe VM's OS disk takes on its pool: the probe flavor's
    data disk plus the rootfs (`launch._os_disk_need_gb` of the probe's
    spec, which is never resized)."""
    from apps.orchestration.services.flavors import ROOTFS_DISK_GB, resolve_flavor

    return resolve_flavor(str(settings.VALI_DISK_PROBE_FLAVOR)).data_disk_size_gb + ROOTFS_DISK_GB


@dataclass(frozen=True)
class _NodeRouting:
    """What `_routed_pool_skip` reads of a node, read once per node: its
    agent takes `os_pool`, and its pools A4b could name (by pk)."""

    supported: bool
    nameable: frozenset[int]

    @classmethod
    def of(cls, node_id: str) -> _NodeRouting:
        if not routing.supported(node_id):
            return cls(supported=False, nameable=frozenset())
        pks = routing.os_disk_pools(node_id).values_list("pk", flat=True)
        return cls(supported=True, nameable=frozenset(pks))


def _routed_pool_skip(pool: MinerStoragePool, node: _NodeRouting, need_gb: int) -> str:
    """Why a launch order cannot name `pool` (not `default`, OS-eligible)
    as the probe's `os_pool`, `""` when it can: the node's agent takes
    `os_pool` (`needs-os-pool-order`), the pool is one A4b would name
    (`routing.os_disk_pools`: active, recently reported, not retired —
    else `pool-not-active`) and it has room for the probe's `need_gb` OS
    disk (`routing.free_gb`, else `no-room`). Its tier and health do not
    matter: measuring them is the point."""
    if not node.supported:
        return "needs-os-pool-order"
    if pool.pk not in node.nameable:
        return "pool-not-active"
    free = routing.free_gb(pool)
    if free is None or free < need_gb:
        return "no-room"
    return ""


def os_pool_skip(node_id: str, pool_id: str) -> str:
    """Why a probe of `node_id`'s pool `pool_id` cannot put its OS disk on
    that pool now, `""` when it can. `default` always can: an order
    without `os_pool` lands there, byte for byte today's."""
    if pool_id == DEFAULT_POOL_ID:
        return ""
    pool = MinerStoragePool.objects.filter(
        miner_node_id=node_id, pool_id=pool_id, retired_at__isnull=True
    ).first()
    if pool is None:
        return "pool-not-active"
    if not pool.os_disks:
        return "not-os-eligible"
    return _routed_pool_skip(pool, _NodeRouting.of(node_id), probe_os_disk_gb())


def probe_os_pool(node_id: str, pool_id: str) -> str | None:
    """The pool a probe of `node_id`'s `pool_id` puts its OS disk on —
    the pool itself, named in the launch (`os_pool`) — or `None` when it
    cannot be probed now (`os_pool_skip` says why)."""
    return None if os_pool_skip(node_id, pool_id) else pool_id


@dataclass(frozen=True)
class Due:
    node_id: str
    pool_id: str
    trigger: str
    #: Ordering key within the trigger: how long it has been due (s).
    overdue_s: float = 0.0
    #: A queued run (operator request), launched as is.
    run: DiskProbeRun | None = None


@dataclass
class TickReport:
    enabled: bool = False
    due: int = 0
    launched: int = 0
    skipped: Counter[str] = field(default_factory=Counter)
    transitions: Counter[str] = field(default_factory=Counter)
    torn_down: int = 0
    forced: int = 0
    refused: int = 0
    #: Fallback teardowns run this tick (bounded per tick).
    fallbacks: int = 0


def _period_jitter_s(run: DiskProbeRun) -> int:
    """The run's fixed jitter on the period, in `[-J, +J]` (from its
    run id: stable across ticks, unknown to the miner)."""
    j = max(0, int(settings.VALI_DISK_PROBE_PERIOD_JITTER_S))
    if j == 0:
        return 0
    h = int.from_bytes(hashlib.sha256(b"disk-probe-period:" + run.run_id.bytes).digest()[:8], "big")
    return h % (2 * j + 1) - j


def _ended_at(run: DiskProbeRun) -> datetime:
    return run.finished_at or run.torn_down_at or run.scheduled_at


def _pool_due(pool_runs: list[DiskProbeRun], now: datetime) -> tuple[str, float] | None:
    """`(trigger, overdue_s)` when the pool is due, else `None`.
    `pool_runs` are the pool's CLOSED-or-ended runs, newest first."""
    retry = timedelta(seconds=int(settings.VALI_DISK_PROBE_RETRY_S))
    last = pool_runs[0] if pool_runs else None
    if last is not None and last.state != ProbeRunState.VERIFIED and now < _ended_at(last) + retry:
        return None
    verified = next((r for r in pool_runs if r.state == ProbeRunState.VERIFIED), None)
    if verified is None:
        since = _ended_at(last) + retry if last is not None else None
        return ProbeTrigger.ONBOARDING, (now - since).total_seconds() if since else float("inf")
    due_at = _ended_at(verified) + timedelta(
        seconds=int(settings.VALI_DISK_PROBE_PERIOD_S) + _period_jitter_s(verified)
    )
    if now < due_at:
        return None
    return ProbeTrigger.PERIODIC, (now - due_at).total_seconds()


def _node_pools(
    node_id: str, rows: list[MinerStoragePool], *, need_gb: int
) -> list[tuple[str, str]]:
    """`[(pool_id, skip_reason)]` for the node's live pools; `""` = probeable
    (for a `need_gb` probe OS disk)."""
    if not rows:
        # No storage report: the implicit `default` pool (design §4.1).
        return [(DEFAULT_POOL_ID, "")]
    node: _NodeRouting | None = None
    out = []
    for p in rows:
        if not p.os_disks:
            out.append((p.pool_id, "not-os-eligible"))
        elif p.reported_state not in ("", "active"):
            out.append((p.pool_id, "pool-not-active"))
        elif p.pool_id == DEFAULT_POOL_ID:
            out.append((p.pool_id, ""))
        else:
            node = node or _NodeRouting.of(node_id)
            out.append((p.pool_id, _routed_pool_skip(p, node, need_gb)))
    return out


def _open_runs() -> list[DiskProbeRun]:
    """Runs whose VM may still exist (or that are queued)."""
    return list(
        DiskProbeRun.objects.filter(torn_down_at__isnull=True).exclude(
            state=ProbeRunState.TORN_DOWN
        )
    )


def due_set(*, nodes: Iterable[str], now: datetime, report: TickReport) -> list[Due]:
    """The ordered due set over `nodes` (lower-case node ids): onboarding,
    then periodic, then queued runs. Pool-level skips are counted in
    `report.skipped`; node-level ones are decided at launch."""
    node_ids = sorted({n.lower() for n in nodes})
    rows: dict[str, list[MinerStoragePool]] = {}
    for p in MinerStoragePool.objects.filter(
        miner_node_id__in=node_ids, retired_at__isnull=True
    ).order_by("pool_id"):
        rows.setdefault(p.miner_node_id.lower(), []).append(p)
    history: dict[tuple[str, str], list[DiskProbeRun]] = {}
    for r in (
        DiskProbeRun.objects.filter(miner_node_id__in=node_ids)
        .exclude(state__in=(ProbeRunState.SCHEDULED, *IN_FLIGHT))
        .order_by("-scheduled_at")
    ):
        history.setdefault((r.miner_node_id.lower(), r.os_pool_id), []).append(r)

    onboarding: list[Due] = []
    periodic: list[Due] = []
    need_gb = probe_os_disk_gb()
    for nid in node_ids:
        for pool_id, skip in _node_pools(nid, rows.get(nid, []), need_gb=need_gb):
            if skip:
                report.skipped[skip] += 1
                continue
            got = _pool_due(history.get((nid, pool_id), []), now)
            if got is None:
                continue
            trigger, overdue = got
            item = Due(node_id=nid, pool_id=pool_id, trigger=trigger, overdue_s=overdue)
            (onboarding if trigger == ProbeTrigger.ONBOARDING else periodic).append(item)
        if (
            rows.get(nid)
            and DEFAULT_POOL_ID not in {p.pool_id for p in rows[nid]}
            and not routing.supported(nid)
        ):
            # The node reports pools but no `default`, and its agent takes
            # no `os_pool`: its OS disks land on a pool vali cannot name.
            report.skipped["os-pool-unavailable"] += 1
    onboarding.sort(key=lambda d: (-d.overdue_s, d.node_id))
    periodic.sort(key=lambda d: (-d.overdue_s, d.node_id))
    queued = [
        Due(node_id=r.miner_node_id.lower(), pool_id=r.os_pool_id, trigger=r.trigger, run=r)
        for r in DiskProbeRun.objects.filter(state=ProbeRunState.SCHEDULED).order_by("scheduled_at")
    ]
    return onboarding + periodic + queued


# ─── the node gates (the scheduler's own reads) ──────────────────────


@dataclass(frozen=True)
class _Gates:
    #: Dispatchable nodes (the universe), and those not hard-gated.
    dispatchable: frozenset[str]
    eligible: frozenset[str]
    chip_by_node: dict[str, str]
    free_by_node: dict[str, int]
    booting: dict[str, int]
    boot_cap_by_node: dict[str, int]
    fleet_boot_cap: int


def _gates(flavor: str) -> _Gates:
    from apps.miners.models import MinerIdentity
    from apps.scheduler import service

    dispatchable = {n.lower() for n in service.dispatchable_node_ids()}
    gated = {n.lower() for n in service.hard_gated_node_ids()}
    chips = {
        n.lower(): (p or "")
        for n, p in MinerIdentity.objects.exclude(chain_node_id="")
        .exclude(chain_node_id__isnull=True)
        .values_list("chain_node_id", "platform_id")
    }
    views = service.capacity_views()
    return _Gates(
        dispatchable=frozenset(dispatchable),
        eligible=frozenset(dispatchable - gated),
        chip_by_node=chips,
        free_by_node={n.lower(): v.free_by_flavor.get(flavor, 0) for n, v in views.items()},
        booting={n.lower(): c for n, c in service.booting_by_node().items()},
        boot_cap_by_node={n.lower(): c for n, c in service.max_booting_overrides().items()},
        fleet_boot_cap=service.max_booting_per_miner(),
    )


def _boot_capped(g: _Gates, nid: str) -> bool:
    """Gate (g) exactly as `decide_placement` applies it."""
    n = g.booting.get(nid, 0)
    cap = g.boot_cap_by_node.get(nid, g.fleet_boot_cap)
    return (nid in g.boot_cap_by_node or cap > 0) and n >= cap


def _node_skip(g: _Gates, nid: str) -> str:
    if nid not in g.eligible:
        return "gated"
    if not g.chip_by_node.get(nid):
        return "no-chip-id"
    if g.free_by_node.get(nid, 0) < int(settings.VALI_DISK_PROBE_MIN_FREE_SLOTS):
        return "capacity"
    if _boot_capped(g, nid):
        return "boot-cap"
    return ""


# ─── launch ──────────────────────────────────────────────────────────


def _actor() -> Any:
    from apps.identity.models import PrincipalScope, ServiceClient

    actor, _ = ServiceClient.objects.get_or_create(
        name=ACTOR_NAME,
        defaults={
            "description": "Launches and tears down the disk-tier probe VMs.",
            # Holds no token (never authenticated over HTTP), like the CDN
            # fleet reconciler.
            "scope": PrincipalScope.OPERATOR.value,
        },
    )
    return actor


def _new_vm_id(owner: ProbeOwner) -> str:
    """`hipc-<user_id>-<8 hex>`, the backend's vm id shape, unused anywhere."""
    from apps.lifecycle.models import Vm
    from apps.orchestration.models import LaunchJob

    for _ in range(8):
        vm_id = f"hipc-{owner.user_id}-{secrets.token_hex(4)}"
        taken = (
            DiskProbeRun.objects.filter(vm_id=vm_id).exists()
            or Vm.objects.filter(vm_id=vm_id).exists()
            or LaunchJob.objects.filter(vm_id=vm_id).exists()
        )
        if not taken:
            return vm_id
    raise RuntimeError("no free disk-probe vm id")


def start_delay_s() -> int:
    lo = int(settings.VALI_DISK_PROBE_START_DELAY_MIN_S)
    hi = int(settings.VALI_DISK_PROBE_START_DELAY_MAX_S)
    return _rng.randint(lo, hi)


def linger_s() -> int:
    return _rng.randint(
        int(settings.VALI_DISK_PROBE_LINGER_MIN_S), int(settings.VALI_DISK_PROBE_LINGER_MAX_S)
    )


def new_run(
    *, node_id: str, pool_id: str, trigger: str, chip_id: str, now: datetime
) -> DiskProbeRun:
    """A fresh `scheduled` run: a new run id, a fresh 32-byte nonce, a
    probe owner and a tenant-shaped vm id. Raises `RuntimeError` when no
    probe owner is configured."""
    owners = probe_owners()
    if not owners:
        raise RuntimeError("VALI_DISK_PROBE_OWNERS is empty")
    owner = _rng.choice(owners)
    return DiskProbeRun.objects.create(
        nonce=secrets.token_bytes(32),
        vm_id=_new_vm_id(owner),
        miner_node_id=node_id.lower(),
        chip_id=chip_id,
        owner=owner.user_id,
        trigger=trigger,
        state=ProbeRunState.SCHEDULED,
        flavor=str(settings.VALI_DISK_PROBE_FLAVOR),
        os_pool_id=pool_id,
        start_delay_s=start_delay_s(),
        targets=[
            {"slot": OS_SLOT, "kind": DiskKind.POOL.value, "pool_id": pool_id, "profile": "v1"}
        ],
        scheduled_at=now,
    )


def render_request(run: DiskProbeRun) -> str:
    return probe_userdata.request_json(
        vm_id=run.vm_id,
        run_id_hex=run.run_id.hex,
        nonce=bytes(run.nonce),
        start_delay_s=int(run.start_delay_s or 0),
        slots=tuple(t["slot"] for t in run.targets),
    )


def launch_intent(run: DiskProbeRun, owner: ProbeOwner) -> dict[str, Any]:
    """The probe VM's launch intent: a tenant's shape (the backend's
    fields), pinned to the run's chip."""
    return {
        "tenant_id": owner.tenant_id,
        "user_id": owner.user_id,
        "vm_id": run.vm_id,
        # The backend sends `vm.lease_id or vm.vm_id`.
        "lease_id": run.vm_id,
        "flavor": run.flavor,
        "cmdline": str(settings.VALI_DISK_PROBE_CMDLINE),
        "image": str(settings.VALI_DISK_PROBE_IMAGE),
        "region": "",
        "platform_id": run.chip_id,
        "enable_netbird": bool(settings.VALI_DISK_PROBE_NETBIRD),
        "auto_pin_allowlist": True,
        # The pool under test: the OS disk goes ON it (`default` ⇒ the
        # order carries no `os_pool`). Only a disk-probe launch may pin it
        # (`launch_jobs._check_os_pool_pin`).
        "os_pool": run.os_pool_id,
        # One of OUR VMs (`orchestration.launch_purpose`): no pay, no bill,
        # no fill proof — on top of the probe owner's exclusion. Vali-side
        # only: the miner never sees it, so the probe still looks a tenant's.
        "purpose": "probe",
    }


def _owner_of(run: DiskProbeRun) -> ProbeOwner | None:
    return next((o for o in probe_owners() if o.user_id == run.owner), None)


def _launch_timeout() -> timedelta:
    return timedelta(seconds=int(settings.VALI_DISK_PROBE_LAUNCH_TIMEOUT_S))


def _retry_or_close(run: DiskProbeRun, reason: str, *, now: datetime) -> None:
    """A transient intake failure (Vault): the run stays queued, and the
    next tick retries the SAME vm id — the golden overlay KEK it may already
    have staged is first-write-wins and reused, never stranded. Closed as
    refused once the launch window is over."""
    if now < (run.first_attempt_at or now) + _launch_timeout():
        DiskProbeRun.objects.filter(pk=run.pk, state=ProbeRunState.SCHEDULED).update(
            failure_reason=f"launch-retry:{reason}"[:128]
        )
        return
    _close_refused(run, f"launch-refused:{reason}", now=now)


def launch(run: DiskProbeRun, *, now: datetime) -> bool:
    """Launch `run`'s probe VM. `True` once a launch job exists. A refusal
    of the intent closes the run `torn_down` (`launch-refused:<category>`:
    nothing was launched, and it is vali's refusal, not the miner's); an
    internal failure is retried (`_retry_or_close`)."""
    from apps.orchestration import launch_jobs

    owner = _owner_of(run)
    if owner is None:
        _close_refused(run, "launch-refused:owner-unconfigured", now=now)
        return False
    if run.first_attempt_at is None:
        run.first_attempt_at = now
        DiskProbeRun.objects.filter(pk=run.pk, first_attempt_at__isnull=True).update(
            first_attempt_at=now
        )
    request = render_request(run)
    userdata = probe_userdata.render(request, netbird=bool(settings.VALI_DISK_PROBE_NETBIRD))
    try:
        job = launch_jobs.start_launch(
            intent=launch_intent(run, owner),
            userdata=userdata,
            decided_by=_actor(),
            disk_probe=True,
        )
    except launch_jobs.LaunchIntentError as exc:
        log.error("disk-probe: launch refused for node %s: %s", run.miner_node_id[:12], exc.message)
        if exc.category == "internal":
            _retry_or_close(run, exc.category, now=now)
        else:
            _close_refused(run, f"launch-refused:{exc.category}", now=now)
        return False
    except Exception as exc:  # noqa: BLE001 — transient; retried (`_retry_or_close`).
        log.exception("disk-probe: launch failed for node %s", run.miner_node_id[:12])
        _retry_or_close(run, type(exc).__name__, now=now)
        return False
    # Until the launch succeeds the deadline is the launch window's; then
    # `advance` re-arms it from that moment (the guest's delay starts at boot).
    _adopt(run, job_id=job.job_id, launched_at=now)
    log.info(
        "disk-probe: launched run %s on node %s (pool %s, %s)",
        run.run_id,
        run.miner_node_id[:12],
        run.os_pool_id,
        run.trigger,
    )
    return True


def _adopt(run: DiskProbeRun, *, job_id: str, launched_at: datetime) -> bool:
    """`scheduled` → `launching` once `job_id` launches the run's VM."""
    return bool(
        DiskProbeRun.objects.filter(pk=run.pk, state=ProbeRunState.SCHEDULED).update(
            state=ProbeRunState.LAUNCHING,
            launch_job_id=job_id,
            launched_at=launched_at,
            deadline_at=launched_at + _launch_timeout(),
            failure_reason="",
        )
    )


def _close_refused(run: DiskProbeRun, reason: str, *, now: datetime) -> None:
    """A run that launched nothing: closed at once. The pool's next
    attempt waits `VALI_DISK_PROBE_RETRY_S` (`_pool_due`)."""
    from apps.orchestration.models import TERMINAL_LAUNCH_STATES, LaunchJob

    if (
        LaunchJob.objects.filter(vm_id=run.vm_id)
        .exclude(state__in=list(TERMINAL_LAUNCH_STATES))
        .exists()
    ):
        # Should not happen (a refusal raises before the job is written);
        # if it did, the teardown must find it.
        DiskProbeRun.objects.filter(pk=run.pk).update(
            state=ProbeRunState.FAILED,
            failure_reason=reason[:128],
            finished_at=now,
            teardown_after=now,
        )
        return
    DiskProbeRun.objects.filter(pk=run.pk).update(
        state=ProbeRunState.TORN_DOWN,
        failure_reason=reason[:128],
        torn_down_at=now,
        teardown_detail="nothing launched",
    )


def request_manual(
    node_id: str, *, pool_id: str = DEFAULT_POOL_ID, now: datetime | None = None
) -> DiskProbeRun:
    """Queue an operator-requested probe of `node_id`'s pool `pool_id`
    (default `default`; design §2: announced, so it runs `start_delay_s`
    later like any probe; at most one per node per
    `VALI_DISK_PROBE_MANUAL_INTERVAL_S`). The pool must be probeable now
    (`os_pool_skip`). Raises `ValueError`."""
    from apps.miners.models import MinerIdentity

    now = now or timezone.now()
    nid = node_id.strip().lower()
    if not is_valid_pool_id(pool_id):
        raise ValueError(f"{pool_id!r} is not a pool id ([a-z0-9-]{{1,32}})")
    since = now - timedelta(seconds=int(settings.VALI_DISK_PROBE_MANUAL_INTERVAL_S))
    if (
        DiskProbeRun.objects.filter(
            miner_node_id=nid, trigger=ProbeTrigger.MANUAL, scheduled_at__gte=since
        )
        # A request that never launched (refused, expired) does not count.
        .exclude(state=ProbeRunState.TORN_DOWN, launch_job_id="")
        .exists()
    ):
        raise ValueError(f"node {nid[:12]} already had an operator-requested probe this period")
    if any(r.miner_node_id.lower() == nid for r in _open_runs()):
        raise ValueError(f"node {nid[:12]} has a probe in flight")
    chip = (
        MinerIdentity.objects.filter(chain_node_id__iexact=nid)
        .values_list("platform_id", flat=True)
        .first()
    )
    if not chip:
        raise ValueError(f"node {nid[:12]} has no registered chip id")
    skip = os_pool_skip(nid, pool_id)
    if skip:
        raise ValueError(f"pool {pool_id!r} of node {nid[:12]} cannot be probed now: {skip}")
    return new_run(node_id=nid, pool_id=pool_id, trigger=ProbeTrigger.MANUAL, chip_id=chip, now=now)


def _image_ready() -> bool:
    """The probe image is blessed and carries a guest release with the
    probe (`VALI_DISK_PROBE_MIN_GUEST_RELEASE`; unset, 0, launches nothing:
    an image without the probe would time every node out)."""
    from apps.images.models import GoldenImage

    need = int(settings.VALI_DISK_PROBE_MIN_GUEST_RELEASE)
    if need <= 0:
        return False
    image = GoldenImage.objects.filter(image_name=str(settings.VALI_DISK_PROBE_IMAGE)).first()
    if image is None or image.restricted_tenant:
        return False
    return (image.guest_release or 0) >= need


def schedule(*, now: datetime, report: TickReport) -> None:
    """Launch what is due, within the gates (see the module docstring)."""
    if not probe_owners():
        report.skipped["no-probe-owner"] += 1
        return
    if not _image_ready():
        report.skipped["image-not-ready"] += 1
        return
    flavor = str(settings.VALI_DISK_PROBE_FLAVOR)
    g = _gates(flavor)
    open_runs = _open_runs()
    # 1 per miner: a node holding a launched run (its VM may be alive)
    # takes nothing; a node with a queued run takes only that one.
    holding = {r.miner_node_id.lower() for r in open_runs if r.state != ProbeRunState.SCHEDULED}
    queued = {r.miner_node_id.lower() for r in open_runs if r.state == ProbeRunState.SCHEDULED}
    active = len([r for r in open_runs if r.state != ProbeRunState.SCHEDULED])
    cap = max(0, int(settings.VALI_DISK_PROBE_MAX_CONCURRENT))
    due = due_set(nodes=g.dispatchable, now=now, report=report)
    report.due = len(due)
    for item in due:
        if item.node_id in holding or (item.run is None and item.node_id in queued):
            report.skipped["busy"] += 1
            continue
        if active >= cap:
            report.skipped["concurrency"] += 1
            continue
        skip = _node_skip(g, item.node_id)
        if not skip and item.run is not None:
            # A queued request's pool may have filled up or gone since:
            # it waits (and expires) rather than launch onto another pool.
            skip = os_pool_skip(item.node_id, item.pool_id)
        if skip:
            report.skipped[skip] += 1
            continue
        if item.run is not None:
            run = item.run
        else:
            run = new_run(
                node_id=item.node_id,
                pool_id=item.pool_id,
                trigger=item.trigger,
                chip_id=g.chip_by_node[item.node_id],
                now=now,
            )
        holding.add(item.node_id)
        if launch(run, now=now):
            report.launched += 1
            active += 1
        else:
            report.refused += 1


# ─── advance + timeout ───────────────────────────────────────────────


def _verdict(run: DiskProbeRun, state: str, reason: str, *, now: datetime) -> bool:
    """CAS an in-flight run to a verdict state, teardown due now."""
    n = DiskProbeRun.objects.filter(pk=run.pk, state__in=IN_FLIGHT).update(
        state=state, failure_reason=reason[:128], finished_at=now, teardown_after=now
    )
    return n == 1


def advance(*, now: datetime, report: TickReport) -> None:
    """Move every open run on: adopt a queued run whose launch job exists
    (a tick that died between the intake and its own update), drop an
    expired queued request, follow the launch job, and time out."""
    from apps.orchestration.models import LaunchJob, LaunchJobState

    ttl = timedelta(seconds=int(settings.VALI_DISK_PROBE_QUEUE_TTL_S))
    for run in DiskProbeRun.objects.filter(state=ProbeRunState.SCHEDULED).order_by("scheduled_at"):
        job = LaunchJob.objects.filter(vm_id=run.vm_id).order_by("-started_at").first()
        if job is not None:
            if _adopt(run, job_id=job.job_id, launched_at=job.started_at):
                report.transitions["adopted"] += 1
        elif now >= run.scheduled_at + ttl:
            DiskProbeRun.objects.filter(pk=run.pk, state=ProbeRunState.SCHEDULED).update(
                state=ProbeRunState.TORN_DOWN,
                failure_reason="request-expired",
                torn_down_at=now,
                teardown_detail="nothing launched",
            )
            report.transitions["expired"] += 1

    for run in DiskProbeRun.objects.filter(state__in=IN_FLIGHT).order_by("scheduled_at"):
        job = (
            LaunchJob.objects.filter(job_id=run.launch_job_id).first()
            if run.state == ProbeRunState.LAUNCHING and run.launch_job_id
            else None
        )
        if job is not None and job.state == LaunchJobState.SUCCEEDED.value:
            # The VM is up from here: the guest's start delay runs from its
            # boot, so the deadline is re-armed from this moment.
            launched = job.finished_at or now
            deadline = launched + timedelta(
                seconds=int(run.start_delay_s or 0) + int(settings.VALI_DISK_PROBE_TIMEOUT_S)
            )
            if DiskProbeRun.objects.filter(pk=run.pk, state=ProbeRunState.LAUNCHING).update(
                state=ProbeRunState.RUNNING, deadline_at=deadline
            ):
                report.transitions["running"] += 1
                run.state, run.deadline_at = ProbeRunState.RUNNING, deadline
        elif job is not None and job.state == LaunchJobState.FAILED.value:
            if _verdict(run, ProbeRunState.FAILED, f"launch-failed:{job.reason}", now=now):
                report.transitions["launch-failed"] += 1
            continue
        if run.deadline_at is not None and now >= run.deadline_at:
            if job is not None and job.state == LaunchJobState.QUEUED.value:
                # Never claimed by the launch worker: vali's own backlog, not
                # the miner's — a failure, not a timeout counted against it.
                verdict, reason = ProbeRunState.FAILED, "launch-timeout:queued"
            elif run.state == ProbeRunState.LAUNCHING:
                verdict, reason = ProbeRunState.TIMEOUT, "launch-timeout"
            else:
                verdict, reason = ProbeRunState.TIMEOUT, "probe-timeout"
            if _verdict(run, verdict, reason, now=now):
                report.transitions["timeout"] += 1


# ─── teardown ────────────────────────────────────────────────────────


def _wait_decommission(vm_id: str, deadline: float) -> None:
    """`teardown`'s §24 driver: start the VM's §24 if none runs, wait for
    it until `deadline` (monotonic); raise if the VM is not destroyed."""
    from apps.lifecycle.models import Vm, VmState
    from apps.orchestration.service import StartError, start_decommission

    vm = Vm.objects.filter(vm_id=vm_id).first()
    if vm is not None and vm.state == VmState.ACTIVE:
        try:
            start_decommission(vm=vm, decided_by=_actor())
        except StartError as exc:
            log.info("disk-probe teardown: §24 of %s not started: %s", vm_id, exc.message)
    while time.monotonic() < deadline:
        state = Vm.objects.filter(vm_id=vm_id).values_list("state", flat=True).first()
        if state == VmState.DESTROYED:
            return
        time.sleep(_FALLBACK_POLL_S)
    raise TimeoutError(f"§24 of {vm_id} did not finish")


def _force_destroy(vm_id: str) -> str:
    from apps.orchestration import teardown

    return teardown.force_destroy(vm_id, handoff_reason=_HANDOFF_REASON, label=_LABEL)


def _fallback_teardown(vm_id: str) -> tuple[str, bool]:
    from apps.orchestration import teardown

    return teardown.teardown_vm(
        vm_id,
        decommission=_wait_decommission,
        force_destroy=_force_destroy,
        timeout_s=_FALLBACK_WAIT_S,
        poll_interval_s=_FALLBACK_POLL_S,
        cancel_reason=_CANCEL_REASON,
        label=_LABEL,
    )


def _gone(vm_id: str) -> bool:
    """The VM is destroyed, or provably never existed (no row, no live
    launch job)."""
    from apps.lifecycle.models import Vm, VmState
    from apps.orchestration.models import TERMINAL_LAUNCH_STATES, LaunchJob

    state = Vm.objects.filter(vm_id=vm_id).values_list("state", flat=True).first()
    if state is not None:
        return state == VmState.DESTROYED
    return (
        not LaunchJob.objects.filter(vm_id=vm_id)
        .exclude(state__in=list(TERMINAL_LAUNCH_STATES))
        .exists()
    )


def _close(run: DiskProbeRun, detail: str, *, now: datetime) -> None:
    DiskProbeRun.objects.filter(pk=run.pk, torn_down_at__isnull=True).update(
        torn_down_at=now, teardown_detail=detail[:256]
    )


def teardown_one(run: DiskProbeRun, *, now: datetime, report: TickReport) -> None:
    """One step of `run`'s teardown (see the module docstring)."""
    from apps.lifecycle.models import Vm, VmState
    from apps.orchestration.service import StartError, start_decommission

    vm = Vm.objects.filter(vm_id=run.vm_id).first()
    if vm is not None and vm.state == VmState.DESTROYED:
        _close(run, run.teardown_detail or "destroyed (§24)", now=now)
        report.torn_down += 1
        return
    timeout = timedelta(seconds=int(settings.VALI_DISK_PROBE_TEARDOWN_TIMEOUT_S))
    if vm is not None and run.teardown_started_at is None:
        # The normal path: an in-process §24, driven by the orchestration
        # tick; a later tick sees the VM destroyed.
        if vm.state == VmState.ACTIVE:
            try:
                start_decommission(vm=vm, decided_by=_actor())
            except StartError as exc:
                # Another job holds the VM (its launch still settling, a
                # §25): wait for it; the fallback still runs after the
                # timeout.
                log.info("disk-probe: §24 of %s waits: %s", run.vm_id, exc.message)
        DiskProbeRun.objects.filter(pk=run.pk).update(teardown_started_at=now)
        return
    if vm is not None and run.teardown_started_at and now < run.teardown_started_at + timeout:
        return
    if vm is None and _gone(run.vm_id):
        _close(run, "no vm row and no pending launch — nothing to clean", now=now)
        report.torn_down += 1
        return
    # No VM row (a launch that never materialised one, or still might), or
    # a §24 that did not finish in time: the shared no-leak teardown. Each
    # can wait ~1-2 min, so a tick runs a bounded number; the rest wait.
    if report.fallbacks >= int(settings.VALI_DISK_PROBE_MAX_FALLBACKS_PER_TICK):
        return
    report.fallbacks += 1
    detail, forced = _fallback_teardown(run.vm_id)
    if forced:
        report.forced += 1
        log.error("disk-probe: forced teardown of %s: %s", run.vm_id, detail)
    if _gone(run.vm_id):
        _close(run, detail, now=now)
        report.torn_down += 1
    else:
        DiskProbeRun.objects.filter(pk=run.pk).update(teardown_detail=detail[:256])


def teardown_due(*, now: datetime, report: TickReport) -> None:
    for run in DiskProbeRun.objects.filter(
        state__in=VERDICTS, torn_down_at__isnull=True, teardown_after__lte=now
    ).order_by("teardown_after"):
        try:
            teardown_one(run, now=now, report=report)
        except Exception:  # noqa: BLE001 — one stuck VM must not stop the others.
            log.exception("disk-probe: teardown of %s failed; retried next tick", run.vm_id)


# ─── the tick ────────────────────────────────────────────────────────


def tick(*, now: datetime | None = None) -> TickReport:
    """One orchestrator pass. While `VALI_DISK_PROBE_ENABLED` is off it
    launches nothing; runs already in flight (if the flag was turned off
    under them) are still advanced and torn down, so no probe VM outlives
    the switch. With nothing in flight it writes nothing."""
    now = now or timezone.now()
    report = TickReport(enabled=bool(settings.VALI_DISK_PROBE_ENABLED))
    if not report.enabled and not _open_runs():
        return report
    advance(now=now, report=report)
    teardown_due(now=now, report=report)
    if report.enabled:
        # One tick at a time: the CronJob is `concurrencyPolicy: Forbid`.
        # Not under one DB transaction: a launch stages Vault material, which
        # a rollback would strand.
        schedule(now=now, report=report)
    return report


# ─── metrics (pushed by `vali_disk_probe`) ───────────────────────────

M_ENABLED = "hippius_disk_probe_enabled"
M_PUSH_TS = "hippius_disk_probe_push_timestamp_seconds"
M_INFLIGHT = "hippius_disk_probe_inflight"
M_RUNS_7D = "hippius_disk_probe_runs_7d"
M_RESULTS_7D = "hippius_disk_probe_results_7d"
M_RESULTS_TOTAL = "hippius_disk_probe_results_total"
M_DUE = "hippius_disk_probe_due"
M_SKIPPED = "hippius_disk_probe_skipped"
M_TICK = "hippius_disk_probe_tick"
M_NODE_LAST_VERIFIED = "hippius_disk_probe_node_last_verified_timestamp_seconds"
M_NODE_FAILURES = "hippius_disk_probe_node_consecutive_failures"
M_NODE_SUSPECT_CACHE = "hippius_disk_probe_node_suspect_cache"
M_NODE_SEVERE = "hippius_disk_probe_node_would_be_severe"
M_NODE_TIER = "hippius_disk_probe_node_would_be_tier"
M_NODE_UNFIT_UNSOLD = "hippius_disk_probe_node_would_be_unfit_unsold"

#: Failures that are vali's, not the miner's: not counted against a node.
VALI_SIDE_FAILURES = frozenset({"launch-timeout:queued"})

#: Every outcome of a routed result (`probe_results.route`).
RESULT_OUTCOMES = (
    "accepted",
    "repeat",
    "rejected_not_probe_vm",
    "rejected_unknown_run",
    "rejected_wrong_nonce",
    "rejected_wrong_node",
    "rejected_wrong_owner",
    "rejected_run_terminal",
    "rejected_not_launched",
)
_SKIP_REASONS = (
    "gated",
    "no-chip-id",
    "capacity",
    "boot-cap",
    "busy",
    "concurrency",
    "not-os-eligible",
    "pool-not-active",
    "needs-os-pool-order",
    "no-room",
    "os-pool-unavailable",
    "no-probe-owner",
    "image-not-ready",
)


def failure_class(reason: str) -> str:
    """A bounded label for a failure reason (`launch-failed:<why>` →
    `launch-failed`)."""
    return reason.split(":", 1)[0] if reason else ""


def _os_target(run: DiskProbeRun) -> dict[str, Any]:
    return next((t for t in run.targets if t.get("slot") == OS_SLOT), {})


def report_metrics(
    report: TickReport,
    *,
    now: datetime | None = None,
    nodes: Iterable[str] | None = None,
) -> metrics.MetricSet:
    """The gauges of one tick. Per-node series cover `nodes` (default: the
    dispatchable fleet), so a miner that left does not keep an alert alive."""
    from django.db.models import Q

    from .models import DiskIngestCounter

    now = now or timezone.now()
    ms = metrics.MetricSet()
    ms.gauge(
        M_ENABLED, 1 if report.enabled else 0, help_text="1 while the probe orchestrator runs."
    )
    ms.gauge(M_PUSH_TS, time.time(), help_text="When the orchestrator last pushed.")
    ms.gauge(M_DUE, report.due, help_text="Pools due for a probe at the last tick.")
    for reason in _SKIP_REASONS:
        ms.gauge(
            M_SKIPPED,
            report.skipped.get(reason, 0),
            help_text="Due pools / nodes skipped at the last tick, by reason.",
            reason=reason,
        )
    for what, n in (
        ("launched", report.launched),
        ("refused", report.refused),
        ("torn_down", report.torn_down),
        ("forced_teardown", report.forced),
    ):
        ms.gauge(M_TICK, n, help_text="What the last tick did.", action=what)
    open_by_state = Counter(
        "awaiting-teardown" if r.state in VERDICTS else r.state for r in _open_runs()
    )
    for state in ("scheduled", "launching", "running", "awaiting-teardown"):
        ms.gauge(
            M_INFLIGHT,
            open_by_state.get(state, 0),
            help_text="Probe runs not closed yet, by state.",
            state=state,
        )
    week = now - timedelta(days=7)
    recent = list(
        DiskProbeRun.objects.filter(
            Q(finished_at__gte=week) | Q(state=ProbeRunState.TORN_DOWN, torn_down_at__gte=week)
        )
    )
    by_state = Counter(r.state for r in recent)
    for state in (*VERDICTS, ProbeRunState.TORN_DOWN):
        ms.gauge(
            M_RUNS_7D,
            by_state.get(state, 0),
            help_text="Probe runs that ended in the last 7 days, by final state.",
            state=state,
        )
    verdicts: Counter[str] = Counter()
    for r in recent:
        if r.state == ProbeRunState.VERIFIED:
            verdicts[_os_target(r).get("classified_tier") or "unknown"] += 1
        elif r.state in VERDICTS:
            verdicts[failure_class(r.failure_reason) or r.state] += 1
    for verdict, n in sorted(verdicts.items()):
        ms.gauge(
            M_RESULTS_7D,
            n,
            help_text="Probe verdicts of the last 7 days: the OS tier, or why it failed.",
            verdict=verdict,
        )
    counters = dict(
        DiskIngestCounter.objects.filter(name__startswith="probe_").values_list("name", "value")
    )
    for outcome in RESULT_OUTCOMES:
        ms.gauge(
            M_RESULTS_TOTAL,
            counters.get(f"probe_{outcome}", 0),
            help_text="Routed disk_probe results by outcome (cumulative).",
            outcome=outcome,
        )
    if nodes is None:
        from apps.scheduler import service

        nodes = service.dispatchable_node_ids()
    _node_metrics(ms, {n.lower() for n in nodes})
    return ms


def _node_metrics(ms: metrics.MetricSet, nodes: set[str]) -> None:
    """Per pool of each node of `nodes` (every series carries `node` and
    `pool`: a pool's verdicts never mask, reset or raise another's): the
    newest verified probe, the run of failures since, and what C1 WOULD
    conclude (record only). The pools are the node's not-retired ones
    with a verdict, plus every not-retired pool taking OS disks, whatever
    the probe's skip reason (an old agent, inactive, no room); a node with
    none of those (no storage report, or only hdd pools) has `default`, so
    every node of `nodes` keeps a series. A pool never verified reports
    its watch start instead (its first attempt, else the latest of the
    fleet's first probe, the miner's registration and — not for `default`,
    the node's own data root — the pool's first report), so
    `DiskProbeStale` also covers a pool the probe keeps skipping. A
    retired pool's series drop out.

    `would_be_severe` (what C1 would cordon on) is emitted only for a
    SELLABLE pool (`_sellable`); a pool probed to explore or diagnose
    gets the non-severe `would_be_unfit_unsold` instead."""
    from django.db.models import Min

    from apps.miners.models import MinerIdentity

    node_ids = sorted(nodes)
    live: dict[str, list[MinerStoragePool]] = {}
    retired: set[tuple[str, str]] = set()
    for p in MinerStoragePool.objects.filter(miner_node_id__in=node_ids).order_by("pool_id"):
        if p.retired_at is None:
            live.setdefault(p.miner_node_id.lower(), []).append(p)
        else:
            retired.add((p.miner_node_id.lower(), p.pool_id))
    rows = (
        DiskProbeRun.objects.filter(state__in=VERDICTS, miner_node_id__in=node_ids)
        .order_by("miner_node_id", "-finished_at")
        .only("miner_node_id", "state", "failure_reason", "finished_at", "targets", "os_pool_id")
    )
    by_pool: dict[tuple[str, str], list[DiskProbeRun]] = {}
    for r in rows:
        key = (r.miner_node_id.lower(), r.os_pool_id)
        if key not in retired:
            by_pool.setdefault(key, []).append(r)
    first_attempt = {
        (n.lower(), pool): at
        for n, pool, at in DiskProbeRun.objects.filter(miner_node_id__in=node_ids)
        .order_by()
        .values_list("miner_node_id", "os_pool_id")
        .annotate(at=Min("scheduled_at"))
    }
    fleet_start = DiskProbeRun.objects.aggregate(at=Min("scheduled_at"))["at"]
    # A miner that joined after the probe started is watched from its
    # registration, not from the fleet's first probe.
    registered = {
        n.lower(): at
        for n, at in MinerIdentity.objects.filter(chain_node_id__in=node_ids)
        .order_by()
        .values_list("chain_node_id")
        .annotate(at=Min("registered_at"))
    }
    for nid in node_ids:
        pools = live.get(nid, [])
        watched = {pool for (n, pool) in by_pool if n == nid}
        watched |= {p.pool_id for p in pools if p.os_disks}
        # `default` keeps its node-level clock: a node that starts reporting
        # pools late does not restart its Stale watch.
        reported = {p.pool_id: p.created_at for p in pools if p.pool_id != DEFAULT_POOL_ID}
        rows_by_id = {p.pool_id: p for p in pools}
        supported: bool | None = None
        for pool_id in sorted(watched or {DEFAULT_POOL_ID}):
            if pool_id != DEFAULT_POOL_ID and supported is None:
                supported = routing.supported(nid)
            sellable = _sellable(pool_id, rows_by_id.get(pool_id), bool(supported))
            watch = first_attempt.get((nid, pool_id))
            if watch is None and fleet_start is not None:
                starts = (fleet_start, registered.get(nid), reported.get(pool_id))
                watch = max(t for t in starts if t is not None)
            _pool_metrics(
                ms, nid, pool_id, by_pool.get((nid, pool_id), []), watch, sellable=sellable
            )


def _sellable(pool_id: str, row: MinerStoragePool | None, supported: bool) -> bool:
    """The pool is one a VM's OS disk is sold on today, so C1 would act on
    its verdict. `default`: no row (the node's data root, no storage
    report), or an active one taking OS disks. Another pool: one A4b
    routes OS disks to (`routing.choose_os_pool`) — the node's agent takes
    `os_pool`, the pool takes OS disks, is reported active, not retired,
    and of the class sold as an OS disk (`routing.sold_class_as_os_disk`:
    declared or overridden nvme). Deliberately NOT the verdict-derived
    half of `sold_as_os_disk_tier` (tier, health): a probe demoting a pool
    must not turn it unsold, or its severe grade could never fire. And not
    the report's age: a late heartbeat must not flip the series (anti-flap).
    Anything else (draining, hdd/ssd, unroutable) is probed to explore or
    diagnose only. A declared-ssd pool a probe verified nvme (which A4b does
    route to) stays unsold here until the operator declares or overrides it
    nvme: the operator's side decides what is sold. No gap while verdicts
    are record-only (the effective tier is then the declared class).

    TODO(C1): once verdicts change the tier, follow what routing actually
    sells — a pool that holds or can receive OS disks — without letting an
    unfit verdict make its own pool unsold (its severe grade must still
    fire)."""
    if row is None:
        return pool_id == DEFAULT_POOL_ID
    if row.retired_at is not None or not row.os_disks:
        return False
    if pool_id == DEFAULT_POOL_ID:
        return row.reported_state in ("", "active")
    return supported and row.reported_state == "active" and routing.sold_class_as_os_disk(row)


def _pool_metrics(
    ms: metrics.MetricSet,
    nid: str,
    pool_id: str,
    runs: list[DiskProbeRun],
    watch: datetime | None,
    *,
    sellable: bool,
) -> None:
    """One pool's gauges (`_node_metrics`); `runs` are its verdicts,
    newest first. `would_be_severe` only for a `sellable` pool,
    `would_be_unfit_unsold` only for another."""
    labels = {"node": nid, "pool": pool_id}
    last_verified_help = (
        "When the newest verified probe of the node's pool finished, else when the "
        "probe started watching it (unix s)."
    )
    verified = next((r for r in runs if r.state == ProbeRunState.VERIFIED), None)
    if verified is None and watch is not None:
        ms.gauge(M_NODE_LAST_VERIFIED, watch.timestamp(), help_text=last_verified_help, **labels)
    if not runs:
        return
    failures = 0
    for r in runs:
        if r.state == ProbeRunState.VERIFIED:
            break
        if r.failure_reason in VALI_SIDE_FAILURES:
            continue  # vali's own backlog says nothing about the miner
        failures += 1
    ms.gauge(
        M_NODE_FAILURES,
        failures,
        help_text="Probe runs of the node's pool failed or timed out since its last verified one.",
        **labels,
    )
    if verified is not None and verified.finished_at is not None:
        ms.gauge(
            M_NODE_LAST_VERIFIED,
            verified.finished_at.timestamp(),
            help_text=last_verified_help,
            **labels,
        )
        ms.gauge(
            M_NODE_TIER,
            1,
            help_text="The OS tier the newest verified probe of the node's pool classifies "
            "(record only).",
            **labels,
            tier=_os_target(verified).get("classified_tier") or DiskTier.UNKNOWN.value,
        )
    last = runs[0]
    suspect_cache = last.state == ProbeRunState.FAILED and last.failure_reason == "suspect-cache"
    ms.gauge(
        M_NODE_SUSPECT_CACHE,
        1 if suspect_cache else 0,
        help_text="1 when the newest probe of the node's pool failed suspect-cache.",
        **labels,
    )
    unfit = (
        last.state == ProbeRunState.VERIFIED
        and _os_target(last).get("classified_tier") == DiskTier.UNFIT.value
    )
    if not sellable:
        ms.gauge(
            M_NODE_UNFIT_UNSOLD,
            1 if unfit else 0,
            help_text=(
                "1 when the newest probe of a pool no OS disk is sold on (inactive, "
                "draining, hdd-only or unroutable) classified it unfit. Info only: C1 "
                "acts on sellable pools."
            ),
            **labels,
        )
        return
    two_timeouts = len(runs) >= 2 and all(r.state == ProbeRunState.TIMEOUT for r in runs[:2])
    ms.gauge(
        M_NODE_SEVERE,
        1 if (unfit or suspect_cache or two_timeouts) else 0,
        help_text=(
            "1 when C1 would grade the node's sellable pool severe: an unfit verdict, "
            "suspect-cache, or 2 timeouts in a row (record only)."
        ),
        **labels,
    )
