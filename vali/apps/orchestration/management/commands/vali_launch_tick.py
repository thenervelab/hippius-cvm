"""`vali_launch_tick` — the admin→API launch worker loop (PR-A2).

Drains `LaunchJob(queued)` rows: each cycle CAS-claims at most one job
to `running`, reads its secrets back from Vault, and drives
`launch_jobs.run_job` → `launch.launch_vm` (scheduler place → dispatch →
re-place). Because the miner preflight inside `launch_vm` can take up to
30 min, a launch is async — the `POST /v1/vm/launch` request just
enqueues; this worker does the slow work.

Deploy as a **single** instance (mirrors `vali_orchestration_tick`).
A crashed-then-restarted tick is safe: the claim + the terminal write
are optimistic CAS on `(id, version, state)`, so a job cannot be
double-claimed or double-finished.

`--once` runs a single cycle and exits — for cron / tests.
`--drain` keeps running cycles until the queue is empty (then exits if
`--once`-style behaviour is wanted for a batch).
"""

from __future__ import annotations

import logging
import signal
import time
from typing import Any

from django.conf import settings
from django.core.management.base import BaseCommand

from apps.orchestration import launch_jobs

log = logging.getLogger("apps.orchestration.launch_tick")


class Command(BaseCommand):
    help = "Drive admin-requested VM launch jobs (PR-A2)."

    def add_arguments(self, parser: Any) -> None:
        parser.add_argument(
            "--once",
            action="store_true",
            help="Run a single cycle (drain the queue once) and exit.",
        )

    def handle(self, *args: Any, **options: Any) -> None:
        once: bool = options["once"]
        interval = float(getattr(settings, "VALI_LAUNCH_TICK_INTERVAL_S", 5.0))

        self._running = True

        def _stop(signum: int, _frame: Any) -> None:
            self._running = False
            log.info(
                "vali_launch_tick received signal %s — stopping after this cycle",
                signum,
            )

        signal.signal(signal.SIGTERM, _stop)
        signal.signal(signal.SIGINT, _stop)

        log.info("vali_launch_tick started (interval=%.1fs once=%s)", interval, once)
        while self._running:
            ran = 0
            try:
                # Drain every queued job this cycle (one at a time so a
                # SIGTERM lands between jobs, not mid-launch).
                while self._running and launch_jobs.tick_once():
                    ran += 1
                if ran:
                    log.info("launch tick: ran %d job(s)", ran)
            except Exception:  # noqa: BLE001 — daemon loop must survive.
                log.exception("launch tick raised — continuing")

            if once:
                break
            self._sleep(interval)

        log.info("vali_launch_tick stopped")

    def _sleep(self, interval: float) -> None:
        """Interruptible sleep — a SIGTERM ends the loop within ~0.5s."""
        slept = 0.0
        while self._running and slept < interval:
            step = min(0.5, interval - slept)
            time.sleep(step)
            slept += step
