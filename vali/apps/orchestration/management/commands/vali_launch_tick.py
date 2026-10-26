"""`vali_launch_tick` — the admin→API launch worker loop (PR-A2).

Drains `LaunchJob(queued)` rows: each cycle CAS-claims a job to
`running`, reads its secrets back from Vault, and drives
`launch_jobs.run_job` → `launch.launch_vm` (scheduler place → dispatch →
re-place). Because the miner preflight inside `launch_vm` can take up to
30 min, a launch is async — the `POST /v1/vm/launch` request just
enqueues; this worker does the slow work.

Deploy as a **single** instance (mirrors `vali_orchestration_tick`).
A crashed-then-restarted tick is safe: the claim + the terminal write
are optimistic CAS on `(id, version, state)`, so a job cannot be
double-claimed or double-finished.

`VALI_LAUNCH_TICK_CONCURRENCY` (default `1`) is how many jobs run at
once. At `1` the loop is the serial one: one job, then the next. Above
it, the main thread stays the ONLY claimer and hands each claimed job to
a bounded thread pool; a job's placement decision (count the fleet →
write its `Pending` placement) is serialized fleet-wide by
`apps.scheduler.decision_lock`, so overlapping jobs never spend the same
boot slot or capacity twice. The one-active-launch-per-vm constraint
keeps two jobs for one `vm_id` from ever being in flight together.

SIGTERM/SIGINT stop the claiming; the jobs already in flight run to
their terminal state before the process exits (the pod's termination
grace period bounds how long that may take). In the concurrent loop a
job still waiting for a boot slot — nothing placed yet — ends at once
as `miners-booting` rather than holding the drain for up to
`VALI_SCHEDULER_BOOT_WAIT_S`.

`--once` drains the queue (every queued job, and the ones in flight) and
exits — for cron / tests.
"""

from __future__ import annotations

import logging
import signal
import time
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from typing import Any

from django.conf import settings
from django.core.management.base import BaseCommand
from django.db import close_old_connections

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
        concurrency = launch_jobs.launch_tick_concurrency()

        self._running = True

        def _stop(signum: int, _frame: Any) -> None:
            self._running = False
            log.info(
                "vali_launch_tick received signal %s — stopping after this cycle",
                signum,
            )

        signal.signal(signal.SIGTERM, _stop)
        signal.signal(signal.SIGINT, _stop)

        if concurrency > 1:
            self._run_concurrent(concurrency, interval, once)
            return

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

    def _run_concurrent(self, concurrency: int, interval: float, once: bool) -> None:
        """Up to `concurrency` jobs in flight. The main thread claims (so a
        claim is never lost to a sibling's CAS and mistaken for an empty
        queue); pool threads only run claimed jobs."""
        log.info(
            "vali_launch_tick started (interval=%.1fs once=%s concurrency=%d)",
            interval,
            once,
            concurrency,
        )
        inflight: set[Future[None]] = set()
        with ThreadPoolExecutor(max_workers=concurrency, thread_name_prefix="launch-job") as pool:
            while self._running:
                queue_empty = False
                claimed = 0
                try:
                    # The claiming connection lives as long as the process:
                    # recycle it if it broke (a Postgres restart) or aged out.
                    close_old_connections()
                    while self._running and len(inflight) < concurrency:
                        job = launch_jobs.claim_one()
                        if job is None:
                            queue_empty = True
                            break
                        inflight.add(pool.submit(launch_jobs.run_claimed_job, job, self._stopping))
                        claimed += 1
                    if claimed:
                        log.info(
                            "launch tick: started %d job(s), %d in flight",
                            claimed,
                            len(inflight),
                        )
                except Exception:  # noqa: BLE001 — daemon loop must survive.
                    log.exception("launch tick raised — continuing")
                    # `--once` must still end when the claim keeps failing.
                    queue_empty = True

                if not inflight:
                    if once and queue_empty:
                        break
                    self._sleep(interval)
                    continue
                # A finished job frees a slot at once; otherwise re-poll the
                # queue every `interval` (a slot may be free, the queue was not).
                _done, inflight = wait(inflight, timeout=interval, return_when=FIRST_COMPLETED)

            if inflight:
                log.info("vali_launch_tick stopping — draining %d in-flight job(s)", len(inflight))
            # Leaving the `with` waits for every in-flight job.
        log.info("vali_launch_tick stopped")

    def _stopping(self) -> bool:
        """The shutdown probe handed to each job (`launch_vm(stopping=)`)."""
        return not self._running

    def _sleep(self, interval: float) -> None:
        """Interruptible sleep — a SIGTERM ends the loop within ~0.5s."""
        slept = 0.0
        while self._running and slept < interval:
            step = min(0.5, interval - slept)
            time.sleep(step)
            slept += step
