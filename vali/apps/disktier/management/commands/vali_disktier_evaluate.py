"""`vali_disktier_evaluate` — grade the passive disk signal of the last
closed hours into `MinerDiskHealthHourly` and push the gauges
(`apps.disktier.evaluate`). RECORD ONLY. DB-only. Run by the
`disktier-evaluate` CronJob (suspended until the passive ingest is on).

    manage.py vali_disktier_evaluate [--hours N] [--no-push]
"""

from __future__ import annotations

from typing import Any

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError

from apps.disktier import evaluate
from apps.synthetic import metrics


class Command(BaseCommand):
    help = "Grade passive disk I/O per pool / dedicated disk (record only) and push the gauges."

    def add_arguments(self, parser: Any) -> None:
        parser.add_argument("--hours", type=int, default=None, help="Closed hours to (re)grade.")
        parser.add_argument("--no-push", action="store_true", help="Print the metrics instead.")

    def handle(self, *args: Any, **opts: Any) -> None:
        report = evaluate.evaluate(hours=opts["hours"])
        self.stdout.write(
            f"disktier evaluate: hours={len(report.hours)} rows={report.rows} "
            f"verdicts={dict(report.verdicts)} would_reprobe={report.would_reprobe} "
            f"rate_limited={report.rate_limited} griefer_capped={report.griefer_capped}"
        )
        ms = evaluate.report_metrics()
        if opts["no_push"]:
            self.stdout.write(ms.render())
            return
        # PUT: the group is replaced whole, so a target that left does not
        # linger at its last value.
        pushed = metrics.push(
            ms,
            gateway_url=settings.VALI_SYNTHETIC_PUSHGATEWAY_URL,
            job=settings.VALI_DISK_EVALUATE_PUSH_JOB,
            grouping_key={"report": "disk-tier"},
            replace=True,
            timeout_s=float(settings.VALI_SYNTHETIC_HTTP_TIMEOUT_S),
        )
        if not pushed:
            raise CommandError("disktier evaluate: the Pushgateway refused or did not answer")
