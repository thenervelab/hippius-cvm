"""`vali_scheduled_golden_rebake` — monthly golden re-bake (F6).

    python manage.py vali_scheduled_golden_rebake            # re-bake (flag-gated)
    python manage.py vali_scheduled_golden_rebake --report-only

Re-bakes every golden image (`VALI_GOLDEN_REBAKE_IMAGES`, default
ubuntu/debian/cs10/fedora/cdn-node) from its currently blessed bake's inputs WITH a
package refresh, strictly one bake in flight at a time, optionally runs
the synthetic full e2e on each new bake (not cdn-node), and pushes the results plus the
freshness gauges to the Pushgateway. See `apps.images.rebake`.

It NEVER blesses. Blessing stays a human step after the real-boot checks
(docs/operator/golden-rebake-runbook.md), via `vali_bless_golden_image`.

With `VALI_GOLDEN_REBAKE_ENABLED` off the re-bake is a no-op (exit 0,
nothing queued). `--report-only` only reads the DB and pushes the
freshness gauges; it runs whatever the flag says.

Exit is 0 even when a bake fails — the failure is signalled through the
metrics, like `vali_synthetic_monitor`. `--strict` exits non-zero instead.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone

from apps.images import rebake
from apps.synthetic import metrics

log = logging.getLogger("apps.images.rebake.command")


class Command(BaseCommand):
    help = (
        "Re-bake every golden image with a package refresh, one bake at a "
        "time, and report golden freshness. Never blesses."
    )

    def add_arguments(self, parser: Any) -> None:
        parser.add_argument(
            "--report-only",
            action="store_true",
            help="Push the freshness gauges only (read-only; ignores the flag).",
        )
        parser.add_argument(
            "--stamp",
            default="",
            help="Package-refresh stamp (default: today's UTC date, YYYYMMDD).",
        )
        parser.add_argument("--json", action="store_true", help="Emit the result as JSON.")
        parser.add_argument("--no-push", action="store_true", help="Skip the Pushgateway push.")
        parser.add_argument(
            "--strict",
            action="store_true",
            help="Exit non-zero when a bake or e2e failed (default: alert via metrics).",
        )

    def handle(self, *args: Any, **opts: Any) -> None:
        images = tuple(settings.VALI_GOLDEN_REBAKE_IMAGES)
        if opts["report_only"]:
            self._report(opts, images)
            return

        if not settings.VALI_GOLDEN_REBAKE_ENABLED:
            self.stdout.write(
                "golden re-bake disabled (VALI_GOLDEN_REBAKE_ENABLED is off) — nothing queued"
            )
            return

        stamp = opts["stamp"] or timezone.now().strftime("%Y%m%d")
        timing = rebake.Timing(
            poll_interval_s=float(settings.VALI_GOLDEN_REBAKE_POLL_INTERVAL_S),
            idle_timeout_s=float(settings.VALI_GOLDEN_REBAKE_IDLE_TIMEOUT_S),
            bake_timeout_s=float(settings.VALI_GOLDEN_REBAKE_BAKE_TIMEOUT_S),
            orphan_running_after_s=float(settings.VALI_TENANT_BAKE_ORPHAN_RUNNING_S),
        )
        if settings.VALI_GOLDEN_REBAKE_E2E:
            _reap_leaked_e2e_vms()
        try:
            outcome = rebake.run_rebake(
                images=images,
                stamp=stamp,
                timing=timing,
                e2e=_synthetic_e2e if settings.VALI_GOLDEN_REBAKE_E2E else None,
                # Pushed after every image, not once at the end: a run the
                # activeDeadline kills mid-way has still published its
                # results (and `run_completed=0`).
                on_progress=lambda o: self._push(
                    opts, rebake.rebake_metrics(o), {"kind": "rebake"}
                ),
            )
        except ValueError as exc:
            raise CommandError(str(exc)) from exc

        self._report(opts, images)

        payload = {
            "stamp": outcome.stamp,
            "success": outcome.success,
            "aborted": outcome.aborted,
            "results": [
                {
                    "image": r.image,
                    "bake_id": r.bake_id,
                    "vm_id": r.vm_id,
                    "state": r.state,
                    "e2e_success": r.e2e_success,
                    "detail": r.detail,
                }
                for r in outcome.results
            ],
            "blessed": "unchanged — bless by hand after the real-boot checks",
        }
        if opts["json"]:
            self.stdout.write(json.dumps(payload))
        else:
            self.stdout.write(
                f"golden re-bake {stamp}: {'OK' if outcome.success else 'FAIL'} — {payload}"
            )
        if not outcome.success and opts["strict"]:
            raise CommandError(f"golden re-bake {stamp} FAILED")

    def _report(self, opts: dict, images: tuple[str, ...]) -> None:
        rows = rebake.freshness(images)
        for f in rows:
            log.info(
                "golden freshness image=%s blessed=%s produced=%s awaiting_bless=%s%s",
                f.image,
                f.blessed_bake_id,
                f.blessed_bake_time.isoformat(),
                f.awaiting_bless,
                f" ({f.ready_bake_id})" if f.awaiting_bless else "",
            )
        self._push(opts, rebake.freshness_metrics(rows), {"kind": "freshness"})

    def _push(self, opts: dict, ms: metrics.MetricSet, grouping_key: dict) -> None:
        if opts["no_push"]:
            self.stdout.write(ms.render())
            return
        # PUT: each run replaces its group whole, so a distro dropped from
        # the image list does not linger at its last value.
        metrics.push(
            ms,
            gateway_url=settings.VALI_SYNTHETIC_PUSHGATEWAY_URL,
            job=settings.VALI_GOLDEN_REBAKE_PUSH_JOB,
            grouping_key=grouping_key,
            replace=True,
            timeout_s=float(settings.VALI_SYNTHETIC_HTTP_TIMEOUT_S),
        )


def _reap_leaked_e2e_vms() -> None:
    """§24 any synthetic-tenant VM a killed run left behind.

    The e2e's `finally` teardown cannot run when the Job is SIGKILLed (its
    activeDeadline, an eviction, OOM). The re-bake's test VMs are ordinary
    synthetic-tenant VMs, so the synthetic reaper owns them: the light
    tier runs it every 15 min, and this run runs it again before it
    launches anything. Age-bounded (`VALI_SYNTHETIC_REAP_AGE_S`), so a
    healthy in-flight synthetic run is never touched."""
    from apps.synthetic import e2e

    try:
        result = e2e.run_reaper()
    except Exception:  # a reaper crash must not block the re-bake
        log.exception("golden re-bake: synthetic reaper crashed")
        return
    if result.reaped_total:
        log.warning("golden re-bake: reaped leaked synthetic resources: %s", result.detail)


def _synthetic_e2e(image: str, bake_id: str) -> bool:
    """The synthetic full e2e, launched on `bake_id` instead of the blessed
    bake. Same self-cleaning teardown as the periodic monitor."""
    from apps.synthetic import e2e

    try:
        api = e2e.ApiClient(
            base=settings.VALI_SYNTHETIC_API_BASE,
            token=settings.VALI_SYNTHETIC_ROOT_TOKEN,
            timeout_s=float(settings.VALI_SYNTHETIC_HTTP_TIMEOUT_S),
        )
    except e2e.ConfigError as exc:
        log.error("golden re-bake e2e mis-configured: %s", exc)
        return False
    outcome = e2e.run_e2e(
        api=api,
        distro=image,
        budget_s=float(settings.VALI_SYNTHETIC_E2E_BUDGET_S),
        bake_id=bake_id,
    )
    log.info(
        "golden re-bake e2e image=%s bake_id=%s vm=%s success=%s stages=%s",
        image,
        bake_id,
        outcome.vm_id,
        outcome.success,
        [(s.name, s.ok) for s in outcome.stages],
    )
    return outcome.success
