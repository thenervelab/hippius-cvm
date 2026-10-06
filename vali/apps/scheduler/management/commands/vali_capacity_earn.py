"""`vali_capacity_earn` — one earned-capacity pass (capacity v2 §3).

Run by the `capacity-earn` CronJob every few minutes. For every `earned`
miner: record the proven concurrency, promote a concurrency held for the
whole hold window to `proven_peak_*`, and grow the earned ceiling from it
when it has filled `earn_util_trigger` of the current one. An observed
SNP-incapable host is reset to the floor. Every change is audited
(`actor = tick:earn`); `operator` miners are never touched.

With `VALI_CAPACITY_EARN_PROOF=off` (the default) no proof is trusted and
nothing grows — see `apps.scheduler.capacity_earn`.

    python manage.py vali_capacity_earn
"""

from __future__ import annotations

import json
from dataclasses import asdict
from typing import Any

from django.core.management.base import BaseCommand

from apps.scheduler import capacity_earn


class Command(BaseCommand):
    help = "One earned-capacity pass over every `earned` miner."

    def handle(self, *args: Any, **opts: Any) -> None:
        report = capacity_earn.tick()
        line = {
            "event": "capacity_earn_tick",
            "proof": capacity_earn.proof_source(),
            **asdict(report),
        }
        self.stdout.write(json.dumps(line, sort_keys=True))
