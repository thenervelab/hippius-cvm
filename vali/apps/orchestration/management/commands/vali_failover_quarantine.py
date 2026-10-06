"""`vali_failover_quarantine` — list, or clear, the miners a manual failover
declared dead.

A failed-over miner is not dispatchable until an operator clears it: it may
have been partitioned rather than dead, and its reappearance is reconciled
(stale domains force-stopped, disks reclaimed once each moved VM is proven)
before anyone should place a VM there again.

    manage.py vali_failover_quarantine                 # list open ones
    manage.py vali_failover_quarantine --clear MINER   # clear MINER
"""

from __future__ import annotations

from typing import Any

from django.core.management.base import BaseCommand

from apps.orchestration import restore
from apps.orchestration.models import FailoverQuarantine


class Command(BaseCommand):
    help = "List or clear failover quarantines."

    def add_arguments(self, parser: Any) -> None:
        parser.add_argument("--clear", metavar="MINER_ID", help="clear this miner's quarantine")
        parser.add_argument("--by", default="operator", help="who clears it (recorded)")

    def handle(self, *args: Any, **options: Any) -> None:
        miner = options.get("clear")
        if miner:
            cleared = restore.clear_quarantine(miner, by=str(options.get("by") or "operator"))
            self.stdout.write(f"{miner}: {cleared} quarantine(s) cleared")
            return
        rows = FailoverQuarantine.objects.filter(cleared_at__isnull=True).select_related("job")
        for q in rows:
            self.stdout.write(
                f"{q.miner_id}\tjob={q.job.job_id}\tvm={q.job.vm_id}\tsince={q.created_at:%Y-%m-%dT%H:%M:%SZ}"
            )
        if not rows:
            self.stdout.write("no open failover quarantine")
