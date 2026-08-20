"""`vali_usage_meter` — continuous uptime-usage accrual loop.

Runs [`usage.accrue_usage_once`] on a fixed interval. Each cycle drains a
batch of verified `served_receipt` telemetry envelopes (the tenant guest's
attested "VM X served during [t0,t1]" proofs) and accrues billable
resource-seconds into the `(epoch, miner, vm)` `UsageAccrual` ledger — the
input to uptime-integrated `compute_epoch_weights()` and to
`owed = unit_seconds × MinerPrice`.

A down VM emits no receipts ⇒ accrues nothing ⇒ isn't paid. Fail-closed: a
cycle that raises is logged and skipped; the daemon never crashes. `--once`
runs a single cycle (cron / tests).
"""

from __future__ import annotations

import logging
import signal
import time
from typing import Any

from django.conf import settings
from django.core.management.base import BaseCommand

from apps.scheduler import usage

log = logging.getLogger("apps.scheduler.usage")


class Command(BaseCommand):
    help = (
        "Continuously accrue attested VM uptime from served-delivery "
        "receipts into the per-(epoch,miner,vm) usage ledger."
    )

    def add_arguments(self, parser: Any) -> None:
        parser.add_argument(
            "--once",
            action="store_true",
            help="Run a single accrual cycle and exit.",
        )

    def handle(self, *args: Any, **options: Any) -> None:
        once: bool = options["once"]
        interval = float(getattr(settings, "VALI_USAGE_METER_INTERVAL_S", 30.0))

        self._running = True

        def _stop(signum: int, _frame: Any) -> None:
            self._running = False
            log.info(
                "vali_usage_meter received signal %s — stopping after this cycle",
                signum,
            )

        signal.signal(signal.SIGTERM, _stop)
        signal.signal(signal.SIGINT, _stop)

        log.info("vali_usage_meter started (interval=%.1fs once=%s)", interval, once)
        while self._running:
            try:
                report = usage.accrue_usage_once()
                if report.drained:
                    log.info(
                        "usage-meter cycle: drained=%d accrued=%d skipped=%d "
                        "requeued=%d",
                        report.drained,
                        report.accrued,
                        report.skipped,
                        report.requeued,
                    )
            except Exception:  # noqa: BLE001 — daemon loop must survive.
                log.exception("usage-meter cycle raised — continuing")

            if once:
                break
            self._sleep(interval)

        log.info("vali_usage_meter stopped")

    def _sleep(self, interval: float) -> None:
        slept = 0.0
        while self._running and slept < interval:
            step = min(0.5, interval - slept)
            time.sleep(step)
            slept += step
