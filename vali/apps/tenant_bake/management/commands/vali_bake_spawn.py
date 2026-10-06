"""`vali_bake_spawn` — the ONLY component that creates tenant-bake k8s
Jobs (RA-N9 spawner isolation).

The `create jobs` k8s capability lets its holder create a **privileged**
bake Job (the baker needs `privileged:true` + hostPath `/dev/kvm` for
losetup/cryptsetup), which is a path to node root → the k3s datastore →
every secret. Previously the large vali web/Django pod held that token
and spawned the Job inline in `TenantBakeCreateView`, so a web-tier RCE
could create an arbitrary privileged Job and escalate.

This worker moves the spawn off the web pod: the view now only creates
the `Queued` row (the source of truth), and this tiny poll loop — the
only workload that mounts the `vali-tenant-bake-spawner` SA token —
finds Queued bakes and calls the idempotent `spawn_bake_job`. The web
pod mounts no SA token at all, so a web RCE can no longer spawn Jobs.

`spawn_bake_job` is idempotent on the deterministic Job name (a 409 =
already spawned), so re-checking a still-Queued bake each sweep is a
no-op; no new DB state is needed.

SERIAL GATE for the scheduled golden re-bake (F6). Concurrent bake pods
race on loop devices (no udev in the pod: "losetup: device node
/dev/loopN is lost") and fail. A re-bake row (`package_refresh` set) is
therefore spawned only when no OTHER live in-flight bake was requested
before it, and no bake requested after a live re-bake row is spawned
until that re-bake is terminal. This worker is the only component that
creates bake Jobs, so the gate holds whoever queued the other bake (the
HTTP API, `vali_tenant_bake_create`, a second re-bake) and closes the
window between the re-bake command's "nothing in flight" check and its
INSERT. Bakes without a re-bake row in flight are spawned exactly as
before (they may still run in parallel with each other).
"""

from __future__ import annotations

import logging
import time
from typing import Any

from django.conf import settings
from django.core.management.base import BaseCommand

from apps.tenant_bake.models import TenantBake, TenantBakeState, live_in_flight_q

log = logging.getLogger("apps.tenant_bake.spawn")


def serial_blocker(bake: TenantBake, live: list[TenantBake]) -> TenantBake | None:
    """The live in-flight bake that must finish before `bake` may spawn,
    or None. `live` is ordered by (requested_at, bake_id) — a total order,
    so two rows can never each wait for the other."""
    for other in live:
        if other.bake_id == bake.bake_id:
            return None  # everything after `bake` in the order is irrelevant
        if bake.package_refresh or other.package_refresh:
            return other
    return None


def spawn_queued_bakes() -> int:
    """One sweep: (re-)spawn every Queued bake's Job. Returns the count
    of bakes for which `spawn_bake_job` was attempted successfully
    (already-spawned re-checks included — the call is idempotent). A
    transient k8s failure for one bake is logged and skipped; it retries
    next sweep (the row stays Queued)."""
    # Imported inside the function so a test can
    # `monkeypatch.setattr(apps.tenant_bake.k8s_jobs, "spawn_bake_job", …)`
    # and have this rebinding observed at call time.
    from apps.tenant_bake import k8s_jobs

    # ONE snapshot feeds both the gate and the candidates. Reading the Queued
    # rows in a second query would let a re-bake row inserted between the
    # two be invisible to the gate while a bake queued after it spawns.
    live = list(
        TenantBake.objects.filter(
            live_in_flight_q(float(settings.VALI_TENANT_BAKE_ORPHAN_RUNNING_S))
        ).order_by("requested_at", "bake_id")
    )
    spawned = 0
    for bake in [b for b in live if b.state == TenantBakeState.QUEUED.value]:
        blocker = serial_blocker(bake, live)
        if blocker is not None:
            log.info(
                "bake spawn held: bake_id=%s waits for re-bake-serial bake_id=%s (%s)",
                bake.bake_id,
                blocker.bake_id,
                blocker.state,
            )
            continue
        try:
            k8s_jobs.spawn_bake_job(bake)
            spawned += 1
        except k8s_jobs.K8sUnavailable as exc:
            log.warning(
                "bake spawn deferred (k8s unavailable): bake_id=%s err=%s",
                bake.bake_id,
                exc,
            )
    return spawned


class Command(BaseCommand):
    help = (
        "Poll Queued tenant bakes and spawn their baker k8s Job "
        "(RA-N9: the sole holder of the create-jobs capability)."
    )

    def add_arguments(self, parser: Any) -> None:
        parser.add_argument(
            "--once",
            action="store_true",
            help="Run a single spawn sweep and exit (for tests / one-shot).",
        )

    def handle(self, *args: Any, **options: Any) -> None:
        interval = float(getattr(settings, "VALI_BAKE_SPAWN_INTERVAL_S", 15.0))
        once: bool = options["once"]
        log.info("vali_bake_spawn starting (interval=%.1fs, once=%s)", interval, once)
        while True:
            try:
                n = spawn_queued_bakes()
                if n:
                    log.info("vali_bake_spawn: (re-)spawned %d queued bake(s)", n)
            except Exception:  # noqa: BLE001 — a sweep error must not kill the loop
                log.exception("vali_bake_spawn sweep failed; retrying next cycle")
            if once:
                break
            time.sleep(interval)
