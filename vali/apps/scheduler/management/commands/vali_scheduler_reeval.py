"""`vali_scheduler_reeval` — continuous §23/§13 re-evaluation loop.

Spec of record: ARCHITECTURE.md §23 ("continuous re-evaluation") /
§13 (drain + quarantine).

Runs [`service.reeval_once`] on a fixed interval. Each cycle reads a
fresh on-chain snapshot, refreshes the `MinerCapacity` mirror, and
§13-drains any `Bound` placement whose miner has left `Active` state
(quarantined / decommissioned / gone) or whose score has gone stale.

Fail-closed: a cycle whose chain read fails is **skipped** with an
error log — the loop never drains on a failed read (that would be a
self-inflicted mass-quarantine on a transient RPC blip) and never
crashes the daemon.

`--once` runs a single cycle and exits — useful for a cron-driven
deployment and for tests.
"""

from __future__ import annotations

import logging
import signal
import time
from typing import Any

from django.conf import settings
from django.core.management.base import BaseCommand

from apps.scheduler import service
from apps.scheduler.chain import ChainReadUnavailable

log = logging.getLogger("apps.scheduler.reeval")


class Command(BaseCommand):
    help = (
        "Continuously re-evaluate Bound placements; §13-drain miners "
        "that leave Active state (ARCHITECTURE.md §23/§13)."
    )

    def add_arguments(self, parser: Any) -> None:
        parser.add_argument(
            "--once",
            action="store_true",
            help="Run a single re-evaluation cycle and exit.",
        )

    def handle(self, *args: Any, **options: Any) -> None:
        once: bool = options["once"]
        interval = float(getattr(settings, "VALI_SCHEDULER_REEVAL_INTERVAL_S", 30.0))

        self._running = True

        def _stop(signum: int, _frame: Any) -> None:
            # Finish the in-flight cycle, then exit cleanly — never
            # abandon a cycle mid-drain.
            self._running = False
            log.info(
                "vali_scheduler_reeval received signal %s — stopping after "
                "this cycle",
                signum,
            )

        signal.signal(signal.SIGTERM, _stop)
        signal.signal(signal.SIGINT, _stop)

        log.info(
            "vali_scheduler_reeval started (interval=%.1fs once=%s)",
            interval,
            once,
        )
        while self._running:
            try:
                report = service.reeval_once()
                log.info(
                    "reeval cycle: epoch=%d miners=%d bound_checked=%d drained=%d",
                    report.current_epoch,
                    report.miners_seen,
                    report.bound_checked,
                    report.drained,
                )
            except ChainReadUnavailable as exc:
                # Fail-closed: skip the cycle, do NOT drain.
                log.error("reeval cycle skipped — chain read failed: %s", exc)
            except Exception:  # noqa: BLE001 — daemon loop must survive.
                log.exception("reeval cycle raised — continuing")

            if once:
                break
            self._sleep(interval)

        log.info("vali_scheduler_reeval stopped")

    def _sleep(self, interval: float) -> None:
        """Interruptible sleep — a SIGTERM ends the loop within ~0.5s
        instead of waiting out the full interval.
        """
        slept = 0.0
        while self._running and slept < interval:
            step = min(0.5, interval - slept)
            time.sleep(step)
            slept += step
