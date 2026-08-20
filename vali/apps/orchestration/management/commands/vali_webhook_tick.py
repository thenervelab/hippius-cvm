"""`vali_webhook_tick` — the outbound job-event webhook delivery loop
(#587 Phase 3).

Each cycle, delivers due `WebhookDelivery(pending)` rows: POSTs the
canonical JSON body signed `X-Hippius-Signature: sha256=<hmac>` to
`VALI_WEBHOOK_URL`, CASing each row `delivered` on a 2xx or scheduling a
backoff retry until `max_attempts`. A no-op when webhooks are unconfigured
(`VALI_WEBHOOK_URL` / `VALI_WEBHOOK_SECRET` unset).

Deploy as a **single** instance (mirrors `vali_launch_tick`). Safe across
restarts: each delivery is an optimistic CAS on `(id, version)`, so a row
cannot be double-delivered.

`--once` runs a single cycle and exits — for cron / tests.
"""

from __future__ import annotations

import logging
import signal
import time
from typing import Any

from django.conf import settings
from django.core.management.base import BaseCommand

from apps.orchestration import webhook

log = logging.getLogger("apps.orchestration.webhook_tick")


class Command(BaseCommand):
    help = "Deliver outbound job-event webhooks (#587 Phase 3)."

    def add_arguments(self, parser: Any) -> None:
        parser.add_argument(
            "--once",
            action="store_true",
            help="Run a single delivery cycle and exit.",
        )

    def handle(self, *args: Any, **options: Any) -> None:
        once: bool = options["once"]
        interval = float(getattr(settings, "VALI_WEBHOOK_TICK_INTERVAL_S", 5.0))
        batch = int(getattr(settings, "VALI_WEBHOOK_BATCH", 20))

        self._running = True

        def _stop(signum: int, _frame: Any) -> None:
            self._running = False
            log.info(
                "vali_webhook_tick received signal %s — stopping after this cycle",
                signum,
            )

        signal.signal(signal.SIGTERM, _stop)
        signal.signal(signal.SIGINT, _stop)

        if not webhook.is_enabled():
            log.warning(
                "vali_webhook_tick: webhooks unconfigured "
                "(VALI_WEBHOOK_URL / VALI_WEBHOOK_SECRET) — idle"
            )

        log.info("vali_webhook_tick started (interval=%.1fs once=%s)", interval, once)
        while self._running:
            try:
                n = webhook.deliver_pending(limit=batch)
                if n:
                    log.info("webhook tick: delivered %d", n)
            except Exception:  # noqa: BLE001 — daemon loop must survive.
                log.exception("webhook tick raised — continuing")

            if once:
                break
            self._sleep(interval)

        log.info("vali_webhook_tick stopped")

    def _sleep(self, interval: float) -> None:
        """Interruptible sleep — a SIGTERM ends the loop within ~0.5s."""
        slept = 0.0
        while self._running and slept < interval:
            step = min(0.5, interval - slept)
            time.sleep(step)
            slept += step
