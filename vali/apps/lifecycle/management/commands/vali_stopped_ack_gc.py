"""`vali_stopped_ack_gc` — reap consumed / stale guest StoppedAck rows.

The `/v1/lifecycle/stopped` ingress (AllowAny) stores one opaque
`SignedStoppedAck` per `(vm_id, generation)` awaiting orchestration
consumption (§24 decommission / §25 cold migration). A migration /
decommission consumes its ack within minutes (well inside the phase
deadline); the row is then dead weight. Nothing deletes it, so the table
grows one row per lifecycle event forever (audit M-StoppedAck).

This reaps rows whose `received_at` is older than
`VALI_STOPPED_ACK_GC_AGE_HOURS` (default 24h — orders of magnitude above
the consume window, so a still-in-flight ack is never reaped). `--once`
runs a single sweep and exits — for the cron-driven deployment and for
tests.
"""

from __future__ import annotations

import logging
import signal
import time
from datetime import timedelta
from typing import Any

from django.conf import settings
from django.core.management.base import BaseCommand
from django.utils import timezone

from apps.lifecycle.models import StoppedAckIngest

log = logging.getLogger("apps.lifecycle.stopped_ack_gc")


def gc_stopped_acks(age_hours: float) -> int:
    """Delete `StoppedAckIngest` rows older than `age_hours`. Returns the
    number deleted. Kept a module function so tests can drive one sweep
    without the daemon loop."""
    cutoff = timezone.now() - timedelta(hours=age_hours)
    deleted, _ = StoppedAckIngest.objects.filter(received_at__lt=cutoff).delete()
    return deleted


class Command(BaseCommand):
    help = "Garbage-collect stale guest StoppedAck ingest rows (audit M-StoppedAck)."

    def add_arguments(self, parser: Any) -> None:
        parser.add_argument(
            "--once",
            action="store_true",
            help="Run a single GC sweep and exit.",
        )

    def handle(self, *args: Any, **options: Any) -> None:
        once: bool = options["once"]
        interval = float(getattr(settings, "VALI_STOPPED_ACK_GC_INTERVAL_S", 3600.0))
        age_hours = float(getattr(settings, "VALI_STOPPED_ACK_GC_AGE_HOURS", 24.0))

        self._running = True

        def _stop(signum: int, _frame: Any) -> None:
            self._running = False
            log.info(
                "vali_stopped_ack_gc received signal %s — stopping after this sweep",
                signum,
            )

        signal.signal(signal.SIGTERM, _stop)
        signal.signal(signal.SIGINT, _stop)

        log.info(
            "vali_stopped_ack_gc started (interval=%.1fs age_hours=%.1f once=%s)",
            interval,
            age_hours,
            once,
        )
        while self._running:
            try:
                deleted = gc_stopped_acks(age_hours)
                log.info("stopped-ack gc sweep: deleted=%d", deleted)
            except Exception:  # noqa: BLE001 — daemon loop must survive.
                log.exception("stopped-ack gc sweep raised — continuing")

            if once:
                break
            self._sleep(interval)

        log.info("vali_stopped_ack_gc stopped")

    def _sleep(self, interval: float) -> None:
        """Interruptible sleep — a SIGTERM ends the loop within ~0.5s."""
        slept = 0.0
        while self._running and slept < interval:
            step = min(0.5, interval - slept)
            time.sleep(step)
            slept += step
