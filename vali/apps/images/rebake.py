"""Scheduled golden re-bake (F6) — the logic behind
`vali_scheduled_golden_rebake`.

Why: a golden image is frozen at bake time. Bake 2 carried 107 pending
noble-security updates (openssh-server, openssl, sudo, libc6…) a month
after it was blessed, and every VM's unattended-upgrades then patched its
OWN overlay upper — so the running root diverges from the measured golden
and every VM pays the download. Re-baking on a schedule moves the patch
into the measured base.

What a run does, per golden image (ubuntu, debian, cs10, fedora):

1. Clones the CURRENTLY BLESSED bake's inputs (base image URL + sha,
   size, bucket) into a new golden `TenantBake` row whose
   `package_refresh` stamp makes the baker apply every pending distro
   update and miss the stage-1 cache (`tenant-image-bake.sh
   --package-refresh`). vm_id `golden-<image>-rebake-<stamp>`, S3 prefix
   `tenant/<vm_id>/` — a fresh prefix, so the golden's fixed artifact keys
   never overwrite the blessed bake's.
2. Queues it ONLY when no other bake is in flight, then waits for it to go
   terminal before the next image. Concurrent bakes race on loop devices
   in the baker pod (no udev) and fail. The hard guarantee is the serial
   gate in `vali_bake_spawn` (the only Job creator): a re-bake row never
   starts next to another live bake, whoever queued it and whenever —
   including in the window between the check here and the INSERT.
3. Optionally runs the synthetic full e2e against the new, UNBLESSED bake
   (launch by `bake_id`, which needs no catalog entry).

What a run NEVER does: bless. `GoldenImage` is untouched; the human runs
the real-boot checklist (docs/operator/golden-rebake-runbook.md) and then
`vali_bless_golden_image`.

`report_freshness` is the read-only half: the blessed bake's age and
whether a re-bake is waiting for a bless, pushed as gauges the
`hippius-golden-rebake` PrometheusRule alerts on.
"""

from __future__ import annotations

import logging
import re
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime

from django.utils import timezone

from apps.images.models import GoldenImage
from apps.synthetic import metrics
from apps.tenant_bake.models import (
    IN_FLIGHT_STATES,
    TenantBake,
    TenantBakeDiskMode,
    TenantBakeState,
    live_in_flight_q,
)

log = logging.getLogger("apps.images.rebake")

DEFAULT_IMAGES: tuple[str, ...] = ("ubuntu", "debian", "cs10", "fedora")
REQUESTER_NAME = "vali_scheduled_golden_rebake"
# The stamp is the vm_id suffix, so it takes the vm_id charset (a subset
# of what the baker's `--package-refresh` accepts): no case folding, no
# two stamps naming the same vm_id. 32 chars keeps
# `golden-<image>-rebake-<stamp>` inside the 64-char vm_id.
_STAMP_RE = re.compile(r"^[a-z0-9-]{1,32}$")
# vm_id charset of `apps.tenant_bake.views._VM_ID_RE`.
_VM_ID_RE = re.compile(r"^[a-z0-9-]{1,64}$")

M_BAKE_SUCCESS = "hippius_golden_rebake_bake_success"
M_E2E_SUCCESS = "hippius_golden_rebake_e2e_success"
M_RUN_TS = "hippius_golden_rebake_run_timestamp"
M_RUN_COMPLETED = "hippius_golden_rebake_run_completed"
M_BLESSED_AGE_DAYS = "hippius_golden_blessed_age_days"
M_BLESSED_BAKE_TS = "hippius_golden_blessed_bake_timestamp_seconds"
M_AWAITING_BLESS = "hippius_golden_rebake_awaiting_bless"
M_READY_TS = "hippius_golden_rebake_ready_timestamp_seconds"
M_REPORT_TS = "hippius_golden_freshness_report_timestamp"


# Result states that are not a TenantBake state.
NOT_BLESSED = "not-blessed"
NOT_RUN = "not-run"


class RebakeAbort(Exception):
    """Stop the whole run: continuing would queue a bake next to one that
    is still in flight."""


@dataclass
class ImageResult:
    image: str
    bake_id: str = ""
    vm_id: str = ""
    state: str = ""
    detail: str = ""
    e2e_success: bool | None = None

    @property
    def bake_ok(self) -> bool:
        return self.state == TenantBakeState.SUCCEEDED.value


@dataclass
class RebakeOutcome:
    stamp: str
    results: list[ImageResult] = field(default_factory=list)
    aborted: str = ""
    started_ts: float = field(default_factory=lambda: metrics.now())
    # False until every image was handled; a Job killed mid-run leaves its
    # last progress push at False (GoldenRebakeRunIncomplete).
    completed: bool = False

    @property
    def success(self) -> bool:
        return not self.aborted and all(
            r.bake_ok and r.e2e_success is not False for r in self.results
        )


@dataclass(frozen=True)
class Timing:
    """Injectable clock + sleep so tests drive the waits without waiting."""

    poll_interval_s: float
    idle_timeout_s: float
    bake_timeout_s: float
    # See `apps.tenant_bake.models.live_in_flight_q` — a Running row claimed
    # longer ago than this is an orphan and does not block.
    orphan_running_after_s: float
    monotonic: Callable[[], float] = lambda: time.monotonic()  # noqa: E731
    sleep: Callable[[float], None] = lambda s: time.sleep(s)  # noqa: E731


def rebake_vm_id(image: str, stamp: str) -> str:
    return f"golden-{image}-rebake-{stamp}"


def _rebake_prefix(image: str) -> str:
    return f"golden-{image}-rebake-"


def _bake_time(bake: TenantBake) -> datetime:
    return bake.finished_at or bake.requested_at


def run_rebake(
    *,
    images: tuple[str, ...],
    stamp: str,
    timing: Timing,
    e2e: Callable[[str, str], bool] | None = None,
    on_progress: Callable[[RebakeOutcome], None] | None = None,
) -> RebakeOutcome:
    """Re-bake each image in order, one bake in flight at a time.

    `e2e(image, bake_id) -> success` runs after a Succeeded bake when
    given. A failed or timed-out bake does not stop the run; a bake that is
    still in flight when its wait expires does (`RebakeAbort`), because the
    next image would then bake concurrently with it.

    `on_progress(outcome)` runs after each image (and once at the end with
    `completed=True`), so a run killed mid-way has already published what
    it did.
    """
    if not _STAMP_RE.match(stamp):
        raise ValueError(f"stamp {stamp!r} must match [a-z0-9-]{{1,32}}")
    outcome = RebakeOutcome(stamp=stamp)
    for image in images:
        result = ImageResult(image=image)
        outcome.results.append(result)
        if outcome.aborted:
            # Reported, not skipped silently: an image the run never reached
            # did not get its refresh either.
            result.state = NOT_RUN
            result.detail = f"run aborted before this image: {outcome.aborted}"
            continue
        try:
            bake = _bake_one(image, stamp, timing, result)
        except RebakeAbort as exc:
            result.detail = str(exc)
            outcome.aborted = str(exc)
            log.error("golden re-bake aborted at image=%s: %s", image, exc)
            continue
        if bake is None or not result.bake_ok:
            if on_progress is not None:
                on_progress(outcome)
            continue
        if e2e is not None:
            result.e2e_success = bool(e2e(image, bake.bake_id))
            TenantBake.objects.filter(pk=bake.pk).update(rebake_e2e_passed=result.e2e_success)
        if on_progress is not None:
            on_progress(outcome)
    outcome.completed = True
    if on_progress is not None:
        on_progress(outcome)
    return outcome


def _bake_one(
    image: str, stamp: str, timing: Timing, result: ImageResult
) -> TenantBake | None:
    try:
        blessed_id = GoldenImage.objects.get(image_name=image).bake_id
    except GoldenImage.DoesNotExist:
        result.state = NOT_BLESSED
        result.detail = f"no blessed golden image named {image!r}"
        log.error("golden re-bake: %s", result.detail)
        return None
    blessed = TenantBake.objects.filter(bake_id=blessed_id).first()
    if blessed is None or blessed.disk_mode != TenantBakeDiskMode.GOLDEN_VERITY_OVERLAY.value:
        result.state = NOT_BLESSED
        result.detail = f"blessed bake {blessed_id!r} is missing or not a golden bake"
        log.error("golden re-bake: %s", result.detail)
        return None

    vm_id = rebake_vm_id(image, stamp)
    if not _VM_ID_RE.match(vm_id):
        raise ValueError(f"re-bake vm_id {vm_id!r} is not a valid vm_id")
    result.vm_id = vm_id

    # Re-run of the same stamp (a retried CronJob): reuse a Succeeded or
    # still-running bake instead of baking twice; a Failed one is retried.
    bake = TenantBake.objects.filter(vm_id=vm_id).order_by("-requested_at").first()
    if bake is not None and bake.state == TenantBakeState.FAILED.value:
        bake = None
    if bake is None:
        bake = _queue_when_idle(blessed, vm_id, stamp, timing, image)
        log.info(
            "golden re-bake queued image=%s bake_id=%s vm_id=%s (clone of blessed %s)",
            image,
            bake.bake_id,
            vm_id,
            blessed.bake_id,
        )
    result.bake_id = bake.bake_id

    bake = _wait_terminal(bake, timing)
    result.state = bake.state
    if bake.state == TenantBakeState.FAILED.value:
        result.detail = bake.failure_reason or "<no reason>"
        log.error(
            "golden re-bake FAILED image=%s bake_id=%s: %s", image, bake.bake_id, result.detail
        )
    else:
        log.info("golden re-bake Succeeded image=%s bake_id=%s", image, bake.bake_id)
    return bake


def _queue_when_idle(
    blessed: TenantBake, vm_id: str, stamp: str, timing: Timing, image: str
) -> TenantBake:
    """INSERT the re-bake row once no live bake is in flight.

    The check and the INSERT run under `bake_queue_lock`, which every bake
    creator takes, so no other bake can be inserted between them. The wait
    itself sleeps OUTSIDE the lock. `vali_bake_spawn`'s serial gate is the
    second line: whatever is queued, a re-bake never starts next to
    another live bake."""
    from apps.tenant_bake.locks import bake_queue_lock

    deadline = timing.monotonic() + timing.idle_timeout_s
    live = live_in_flight_q(timing.orphan_running_after_s)
    _log_orphans(live)
    while True:
        with bake_queue_lock():
            busy = TenantBake.objects.filter(live).order_by("requested_at").first()
            if busy is None:
                return _queue(blessed, vm_id, stamp)
        if timing.monotonic() > deadline:
            raise RebakeAbort(
                f"bake {busy.bake_id} (vm_id={busy.vm_id}) still {busy.state} after "
                f"{timing.idle_timeout_s:.0f}s — refusing to queue {image} next to it. "
                "If it is dead, close it: vali_tenant_bake_close_orphan "
                f"{busy.bake_id} --reason '...'"
            )
        log.info("golden re-bake waiting for in-flight bake %s (%s)", busy.bake_id, busy.state)
        timing.sleep(timing.poll_interval_s)


def _log_orphans(live) -> None:
    for orphan in TenantBake.objects.filter(state__in=list(IN_FLIGHT_STATES)).exclude(live):
        log.warning(
            "golden re-bake ignores orphan bake %s (vm_id=%s, Running since %s) — close it "
            "with vali_tenant_bake_close_orphan",
            orphan.bake_id,
            orphan.vm_id,
            orphan.started_at.isoformat() if orphan.started_at else "?",
        )


def _queue(blessed: TenantBake, vm_id: str, stamp: str) -> TenantBake:
    from apps.identity.models import PrincipalScope, ServiceClient
    from apps.tenant_bake.views import _mint_bake_id

    # Same posture as `vali_tenant_bake_create`: a bake is a fleet
    # artifact, so the requester principal is an operator. No token.
    requester, _ = ServiceClient.objects.get_or_create(
        name=REQUESTER_NAME,
        defaults={"scope": PrincipalScope.OPERATOR.value},
    )
    return TenantBake.objects.create(
        bake_id=_mint_bake_id(),
        vm_id=vm_id,
        base_image_url=blessed.base_image_url,
        base_image_sha256=blessed.base_image_sha256,
        size_gb=blessed.size_gb,
        # A golden bake reads no KEK; the path keeps the per-vm_id shape
        # every golden row carries.
        kek_vault_path=f"secret/data/hippius-compute/kbs/tenants/{vm_id}/luks-kek",
        s3_output_bucket=blessed.s3_output_bucket,
        s3_output_prefix=f"tenant/{vm_id}/",
        disk_mode=TenantBakeDiskMode.GOLDEN_VERITY_OVERLAY.value,
        package_refresh=stamp,
        state=TenantBakeState.QUEUED.value,
        requested_by=requester,
    )


def _wait_terminal(bake: TenantBake, timing: Timing) -> TenantBake:
    deadline = timing.monotonic() + timing.bake_timeout_s
    while True:
        bake.refresh_from_db()
        if bake.state not in IN_FLIGHT_STATES:
            return bake
        if timing.monotonic() > deadline:
            raise RebakeAbort(
                f"bake {bake.bake_id} still {bake.state} after "
                f"{timing.bake_timeout_s:.0f}s — stopping before the next image"
            )
        timing.sleep(timing.poll_interval_s)


# ── Metrics ──────────────────────────────────────────────────────────


def rebake_metrics(outcome: RebakeOutcome) -> metrics.MetricSet:
    ms = metrics.MetricSet()
    for r in outcome.results:
        if r.state == NOT_BLESSED:
            # Nothing to re-bake from (logged as an error). Not a bake
            # failure: GoldenRebakeFailed would page for a config choice.
            continue
        ms.gauge(
            M_BAKE_SUCCESS,
            1 if r.bake_ok else 0,
            help_text="1 if this run's golden re-bake for the distro Succeeded.",
            distro=r.image,
        )
        if r.e2e_success is not None:
            ms.gauge(
                M_E2E_SUCCESS,
                1 if r.e2e_success else 0,
                help_text="1 if the synthetic e2e passed on the new, unblessed bake.",
                distro=r.image,
            )
    ms.gauge(M_RUN_TS, outcome.started_ts, help_text="Unix ts the last golden re-bake run started.")
    ms.gauge(
        M_RUN_COMPLETED,
        1 if outcome.completed else 0,
        help_text="1 once the run handled every image; 0 while running or if it was killed.",
    )
    return ms


@dataclass(frozen=True)
class Freshness:
    image: str
    blessed_bake_id: str
    blessed_bake_time: datetime
    ready_bake_id: str
    ready_time: datetime | None

    @property
    def awaiting_bless(self) -> bool:
        return self.ready_time is not None


def freshness(images: tuple[str, ...]) -> list[Freshness]:
    """Per image: when the blessed bake was produced, and the newest
    Succeeded re-bake produced after it (the one awaiting a bless)."""
    out: list[Freshness] = []
    for image in images:
        golden = GoldenImage.objects.filter(image_name=image).first()
        if golden is None:
            continue
        blessed = TenantBake.objects.filter(bake_id=golden.bake_id).first()
        if blessed is None:
            continue
        blessed_time = _bake_time(blessed)
        ready = (
            TenantBake.objects.filter(
                vm_id__startswith=_rebake_prefix(image),
                state=TenantBakeState.SUCCEEDED.value,
                finished_at__gt=blessed_time,
            )
            .exclude(bake_id=blessed.bake_id)
            # A re-bake the e2e failed on is not a bless candidate.
            .exclude(rebake_e2e_passed=False)
            .order_by("-finished_at")
            .first()
        )
        out.append(
            Freshness(
                image=image,
                blessed_bake_id=blessed.bake_id,
                blessed_bake_time=blessed_time,
                ready_bake_id=ready.bake_id if ready else "",
                ready_time=ready.finished_at if ready else None,
            )
        )
    return out


def freshness_metrics(rows: list[Freshness]) -> metrics.MetricSet:
    now = timezone.now()
    ms = metrics.MetricSet()
    for f in rows:
        ms.gauge(
            M_BLESSED_AGE_DAYS,
            round((now - f.blessed_bake_time).total_seconds() / 86400, 2),
            help_text="Days since the blessed golden bake for the distro was produced.",
            distro=f.image,
        )
        ms.gauge(
            M_BLESSED_BAKE_TS,
            f.blessed_bake_time.timestamp(),
            help_text="Unix ts the blessed golden bake for the distro was produced.",
            distro=f.image,
        )
        ms.gauge(
            M_AWAITING_BLESS,
            1 if f.awaiting_bless else 0,
            help_text="1 if a Succeeded re-bake newer than the blessed bake awaits a human bless.",
            distro=f.image,
        )
        ms.gauge(
            M_READY_TS,
            f.ready_time.timestamp() if f.ready_time else 0,
            help_text="Unix ts the re-bake awaiting a bless finished (0 = none).",
            distro=f.image,
        )
    ms.gauge(M_REPORT_TS, metrics.now(), help_text="Unix ts of the last golden freshness report.")
    return ms
