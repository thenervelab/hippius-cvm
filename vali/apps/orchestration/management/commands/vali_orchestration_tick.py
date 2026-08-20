"""`vali_orchestration_tick` — the §24/§25 orchestration driver loop.

Spec of record: ARCHITECTURE.md §24 / §25.

Runs `service.tick_once()` on a fixed interval. Each cycle advances
every in-flight `MigrationJob` / `DecommissionJob` by one bounded
step (snapshot polling, ack waits + timeouts, the generation fence,
crypto-erase, …).

Deploy as a **single** instance. A crashed-then-restarted tick is
safe: every job transition is an optimistic CAS on
`(id, version, state)`, so it cannot double-advance, and the §14
idempotency store + idempotent peer effects (§24) absorb a re-run of
the in-flight step. Two concurrently-racing tick processes are not a
supported topology — the CAS still prevents a double-advance, but
side-effect dedup then degrades to "peer idempotency only" (same
posture as `vali_scheduler_reeval`).

`--once` runs a single cycle and exits — for a cron-driven
deployment and for tests.
"""

from __future__ import annotations

import logging
import signal
import time
from typing import Any

from django.conf import settings
from django.core.management.base import BaseCommand

from apps.orchestration import service

log = logging.getLogger("apps.orchestration.tick")


class Command(BaseCommand):
    help = (
        "Continuously advance §24/§25 migration + decommission jobs "
        "(ARCHITECTURE.md §24/§25)."
    )

    def add_arguments(self, parser: Any) -> None:
        parser.add_argument(
            "--once",
            action="store_true",
            help="Run a single tick cycle and exit.",
        )

    def handle(self, *args: Any, **options: Any) -> None:
        once: bool = options["once"]
        interval = float(
            getattr(settings, "VALI_ORCHESTRATION_TICK_INTERVAL_S", 10.0)
        )

        self._running = True

        def _stop(signum: int, _frame: Any) -> None:
            self._running = False
            log.info(
                "vali_orchestration_tick received signal %s — stopping after "
                "this cycle",
                signum,
            )

        signal.signal(signal.SIGTERM, _stop)
        signal.signal(signal.SIGINT, _stop)

        log.info(
            "vali_orchestration_tick started (interval=%.1fs once=%s)",
            interval,
            once,
        )
        while self._running:
            try:
                report = service.tick_once()
                log.info(
                    "orchestration tick: migrations=%d decommissions=%d "
                    "netbird_checks=%d wedged_guests=%d source_reclaims=%d "
                    "unbound_launches=%d stranded_migrations=%d "
                    "abandoned_launches=%d",
                    report.migration_jobs,
                    report.decommission_jobs,
                    report.netbird_checks,
                    # Active VMs whose libvirt domain is up but whose GUEST
                    # has gone silent — the silent-green case. The detail
                    # line is the WARNING from `sweep_guest_liveness`.
                    report.wedged_guests,
                    report.source_reclaims,
                    # vm_ids vali launched but has no `Vm` row for — see
                    # `sweep_unbound_launches`. Should be a FLAT historical
                    # number; a rising one means the hole reopened.
                    report.unbound_launches,
                    # VMs fenced in `migrating` behind a TERMINAL job: DOWN,
                    # on neither host, and invisible to reboot-recovery
                    # (which scans `active` only). ANY non-zero value is an
                    # outage — the detail line is the ERROR from
                    # `sweep_stranded_migrations`.
                    report.stranded_migrations,
                    # `Vm` rows a failed launch left `active` with NO host
                    # and a LIVE per-VM KEK — phantoms that every other
                    # sweep counts as running tenants. The detail line is
                    # the WARNING from `sweep_abandoned_launches`.
                    report.abandoned_launches,
                )
            except Exception:  # noqa: BLE001 — daemon loop must survive.
                log.exception("orchestration tick raised — continuing")

            if once:
                break
            self._sleep(interval)

        log.info("vali_orchestration_tick stopped")

    def _sleep(self, interval: float) -> None:
        """Interruptible sleep — a SIGTERM ends the loop within ~0.5s."""
        slept = 0.0
        while self._running and slept < interval:
            step = min(0.5, interval - slept)
            time.sleep(step)
            slept += step
