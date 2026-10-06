"""`vali_capacity_report` — v1 slot capacity next to capacity v2, per miner.

Read-only. This is how the capacity-v2 shadow run is judged before
`VALI_SCHEDULER_RESOURCE_ADMISSION` is switched on: for every miner, the
v1 slot bound and the v2 budget (vCPU with overcommit, RAM + per-VM
overhead, VM count), which term binds each, the resource-true units, and
the per-flavor headroom under both models.

    python manage.py vali_capacity_report
    python manage.py vali_capacity_report --dispatchable-only --json
    python manage.py vali_capacity_report --preflight

`--preflight` is the gate before switching resource admission on: it
exits non-zero when any DISPATCHABLE miner would be refused outright or
shrink under v2 (`capacity_report.preflight_issues`).
"""

from __future__ import annotations

import json
from typing import Any

from django.core.management.base import BaseCommand, CommandError

from apps.scheduler import capacity_report


class Command(BaseCommand):
    help = "Print v1 vs capacity-v2 capacity per miner (read-only)."

    def add_arguments(self, parser: Any) -> None:
        parser.add_argument(
            "--dispatchable-only",
            action="store_true",
            help="Only miners vali can currently dispatch to.",
        )
        parser.add_argument("--json", action="store_true", help="One JSON document.")
        parser.add_argument(
            "--preflight",
            action="store_true",
            help="Fail when a dispatchable miner would be refused or shrink under v2.",
        )

    def handle(self, *args: Any, **opts: Any) -> None:
        reports = capacity_report.fleet_report()
        if opts["dispatchable_only"]:
            reports = [r for r in reports if r.dispatchable]
        if opts["json"]:
            self.stdout.write(json.dumps([r.as_dict() for r in reports], sort_keys=True))
            return
        for r in reports:
            for line in capacity_report.render(r):
                self.stdout.write(line)
        if opts["preflight"]:
            blocked = {
                r.node_id: issues
                for r in reports
                if (issues := capacity_report.preflight_issues(r))
            }
            if blocked:
                raise CommandError(
                    "resource admission preflight FAILED: "
                    + "; ".join(f"{nid[:12]} {','.join(i)}" for nid, i in sorted(blocked.items()))
                )
            self.stdout.write("resource admission preflight: OK")
