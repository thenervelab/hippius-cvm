"""`vali_epoch_close` — the §23 reward-weight PRODUCER loop.

Each cycle computes every miner's reward weight from what it ACTUALLY
hosts (`scoring.compute_epoch_weights` — the reserved cpu/ram/disk of the
tenant VMs bound to it, NOT advertised capacity) and posts it on-chain via
`chain.submit_epoch_close` → the pallet's root-only
`vali_submit_epoch_close`.

This is the producer the chain was missing: without it `EpochWeights` stays
empty and every miner scores `quality = 0`, so the scheduler cannot rank by
merit. vali is the trustless source — it placed the VMs, so it knows the
exact flavor on each miner from its own `Placement` records.

Fail-closed + best-effort: a cycle whose submit fails is logged + retried
next cycle; it never crashes the daemon and never blocks placement.
`--once` runs a single cycle (cron / tests).
"""

from __future__ import annotations

import logging
import signal
import time
from typing import Any

from django.conf import settings
from django.core.management.base import BaseCommand

from apps.scheduler import chain, scoring

log = logging.getLogger("apps.scheduler.epoch_close")


class Command(BaseCommand):
    help = (
        "Compute per-miner reward weights from bound placements (real "
        "hosting) and submit them on-chain (vali_submit_epoch_close)."
    )

    def add_arguments(self, parser: Any) -> None:
        parser.add_argument(
            "--once",
            action="store_true",
            help="Run a single epoch-close cycle and exit.",
        )
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Compute + log the weights but do NOT submit on-chain.",
        )

    def handle(self, *args: Any, **options: Any) -> None:
        once: bool = options["once"]
        dry_run: bool = options["dry_run"]
        interval = float(getattr(settings, "VALI_EPOCH_CLOSE_INTERVAL_S", 300.0))

        self._running = True

        def _stop(signum: int, _frame: Any) -> None:
            self._running = False
            log.info(
                "vali_epoch_close received signal %s — stopping after this cycle",
                signum,
            )

        signal.signal(signal.SIGTERM, _stop)
        signal.signal(signal.SIGINT, _stop)

        log.info(
            "vali_epoch_close started (interval=%.1fs once=%s dry_run=%s)",
            interval,
            once,
            dry_run,
        )
        while self._running:
            try:
                weights = scoring.compute_epoch_weights()
                total = sum(weights.values())
                log.info(
                    "epoch-close: %d miner(s), total weight %d%s",
                    len(weights),
                    total,
                    " (dry-run)" if dry_run else "",
                )
                if not dry_run:
                    chain.submit_epoch_close(weights)
            except chain.ChainWriteUnavailable as exc:
                # Best-effort: a failed submit is retried next cycle.
                log.error("epoch-close submit failed — retrying next cycle: %s", exc)
            except Exception:  # noqa: BLE001 — daemon loop must survive.
                log.exception("epoch-close cycle raised — continuing")

            if once:
                break
            self._sleep(interval)

        log.info("vali_epoch_close stopped")

    def _sleep(self, interval: float) -> None:
        slept = 0.0
        while self._running and slept < interval:
            step = min(0.5, interval - slept)
            time.sleep(step)
            slept += step
