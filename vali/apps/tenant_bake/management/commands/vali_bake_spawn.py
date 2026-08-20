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
"""

from __future__ import annotations

import logging
import time
from typing import Any

from django.conf import settings
from django.core.management.base import BaseCommand

from apps.tenant_bake.models import TenantBake, TenantBakeState

log = logging.getLogger("apps.tenant_bake.spawn")


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

    spawned = 0
    for bake in TenantBake.objects.filter(state=TenantBakeState.QUEUED).order_by(
        "requested_at"
    ):
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
