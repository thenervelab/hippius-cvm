"""`vali_telemetry_gc` — reap terminal §9 telemetry envelopes.

Spec of record: ARCHITECTURE.md §9 (bounded queues).

Runs `service.gc()` on a fixed interval: `Done` / `Failed` /
`Quarantined` envelopes older than `VALI_TELEMETRY_GC_AGE_DAYS` are
deleted. `Pending` envelopes are never GC'd — they leave the table
only by being pulled (→ `Done`) or reclassified `Quarantined`.

`--once` runs a single sweep and exits — for a cron-driven
deployment and for tests.
"""

from __future__ import annotations

import logging
import signal
import time
from typing import Any

from django.conf import settings
from django.core.management.base import BaseCommand

from apps.telemetry import service

log = logging.getLogger("apps.telemetry.gc")


class Command(BaseCommand):
    help = "Garbage-collect terminal §9 telemetry envelopes."

    def add_arguments(self, parser: Any) -> None:
        parser.add_argument(
            "--once",
            action="store_true",
            help="Run a single GC sweep and exit.",
        )

    def handle(self, *args: Any, **options: Any) -> None:
        once: bool = options["once"]
        interval = float(
            getattr(settings, "VALI_TELEMETRY_GC_INTERVAL_S", 3600.0)
        )

        self._running = True

        def _stop(signum: int, _frame: Any) -> None:
            self._running = False
            log.info(
                "vali_telemetry_gc received signal %s — stopping after "
                "this sweep",
                signum,
            )

        signal.signal(signal.SIGTERM, _stop)
        signal.signal(signal.SIGINT, _stop)

        log.info(
            "vali_telemetry_gc started (interval=%.1fs once=%s)",
            interval,
            once,
        )
        while self._running:
            try:
                deleted = service.gc()
                log.info("telemetry gc sweep: deleted=%d", deleted)
            except Exception:  # noqa: BLE001 — daemon loop must survive.
                log.exception("telemetry gc sweep raised — continuing")

            if once:
                break
            self._sleep(interval)

        log.info("vali_telemetry_gc stopped")

    def _sleep(self, interval: float) -> None:
        """Interruptible sleep — a SIGTERM ends the loop within ~0.5s."""
        slept = 0.0
        while self._running and slept < interval:
            step = min(0.5, interval - slept)
            time.sleep(step)
            slept += step
