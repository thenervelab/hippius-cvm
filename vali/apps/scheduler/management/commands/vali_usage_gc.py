"""`vali_usage_gc` — reap historical UsageAccrual rows (audit M-GC).

The `(epoch, miner, vm)` UsageAccrual ledger grows one row per VM per
epoch forever — but `scoring.py` only ever reads the LATEST epoch
(`latest_usage_epoch()`) for the uptime-integrated epoch weights + the
`owed` readout. Once an epoch has closed, its accruals are historical:
never re-read, only state bloat.

This reaps rows for epochs older than the last `VALI_USAGE_GC_KEEP_EPOCHS`
(default 8 — a generous audit window kept for the admin readout / dispute
window), always retaining the latest epoch. `--once` runs a single sweep
and exits — for the cron-driven deployment and for tests.
"""

from __future__ import annotations

import logging
import signal
import time
from typing import Any

from django.conf import settings
from django.core.management.base import BaseCommand

from apps.scheduler.models import UsageAccrual
from apps.scheduler.scoring import latest_usage_epoch

log = logging.getLogger("apps.scheduler.usage_gc")


def gc_usage_accruals(keep_epochs: int) -> int:
    """Delete UsageAccrual rows for epochs older than the last
    `keep_epochs` (the latest epoch is always retained). Returns the
    number deleted. A module function so tests can drive one sweep."""
    latest = latest_usage_epoch()
    if latest is None:
        return 0
    # Keep epochs in [cutoff, latest]; delete epoch < cutoff. `keep_epochs`
    # is clamped to ≥ 1 so the latest epoch is never reaped.
    cutoff = latest - max(1, keep_epochs) + 1
    deleted, _ = UsageAccrual.objects.filter(epoch__lt=cutoff).delete()
    return deleted


class Command(BaseCommand):
    help = "Garbage-collect historical UsageAccrual rows (audit M-GC)."

    def add_arguments(self, parser: Any) -> None:
        parser.add_argument(
            "--once",
            action="store_true",
            help="Run a single GC sweep and exit.",
        )

    def handle(self, *args: Any, **options: Any) -> None:
        once: bool = options["once"]
        interval = float(getattr(settings, "VALI_USAGE_GC_INTERVAL_S", 3600.0))
        keep_epochs = int(getattr(settings, "VALI_USAGE_GC_KEEP_EPOCHS", 8))

        self._running = True

        def _stop(signum: int, _frame: Any) -> None:
            self._running = False
            log.info(
                "vali_usage_gc received signal %s — stopping after this sweep",
                signum,
            )

        signal.signal(signal.SIGTERM, _stop)
        signal.signal(signal.SIGINT, _stop)

        log.info(
            "vali_usage_gc started (interval=%.1fs keep_epochs=%d once=%s)",
            interval,
            keep_epochs,
            once,
        )
        while self._running:
            try:
                deleted = gc_usage_accruals(keep_epochs)
                log.info("usage gc sweep: deleted=%d", deleted)
            except Exception:  # noqa: BLE001 — daemon loop must survive.
                log.exception("usage gc sweep raised — continuing")

            if once:
                break
            self._sleep(interval)

        log.info("vali_usage_gc stopped")

    def _sleep(self, interval: float) -> None:
        """Interruptible sleep — a SIGTERM ends the loop within ~0.5s."""
        slept = 0.0
        while self._running and slept < interval:
            step = min(0.5, interval - slept)
            time.sleep(step)
            slept += step
