"""`vali_guest_report` — push the guest upgrade gauges the
`hippius-guest-upgrade` alerts read (`apps.orchestration.guest_report`).
DB-only. Run by the `guest-report` CronJob.

    manage.py vali_guest_report [--no-push]   # --no-push prints the text format
"""

from __future__ import annotations

from typing import Any

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError

from apps.orchestration import guest_report
from apps.synthetic import metrics


class Command(BaseCommand):
    help = "Push the guest upgrade report gauges to the Pushgateway."

    def add_arguments(self, parser: Any) -> None:
        parser.add_argument("--no-push", action="store_true")

    def handle(self, *args: Any, **opts: Any) -> None:
        ms = guest_report.report_metrics()
        if opts["no_push"]:
            self.stdout.write(ms.render())
            return
        # PUT: each run replaces its group whole, so a VM that caught up or
        # a rollout that ended does not linger at its last value.
        pushed = metrics.push(
            ms,
            gateway_url=settings.VALI_SYNTHETIC_PUSHGATEWAY_URL,
            job=settings.VALI_GUEST_REPORT_PUSH_JOB,
            grouping_key={"report": "guest"},
            replace=True,
            timeout_s=float(settings.VALI_SYNTHETIC_HTTP_TIMEOUT_S),
        )
        if not pushed:
            # Fail the Job: Kubernetes retries it, and GuestReportStale fires
            # if it keeps failing.
            raise CommandError("guest report: the Pushgateway refused or did not answer")
        self.stdout.write(f"guest report: pushed {len(ms.samples)} sample(s)")
