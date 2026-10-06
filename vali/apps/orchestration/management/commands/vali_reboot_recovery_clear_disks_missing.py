"""`vali_reboot_recovery_clear_disks_missing` — re-arm reboot-recovery for a
VM it stopped relaunching because its bound host lacked the VM's disks.

When a relaunch is refused with `relaunch-disks-missing`, vali latches
`RebootRecovery.last_outcome = "disks-missing"` and never relaunches that VM
again (see `service.DISKS_MISSING_OUTCOME`). Once an operator has put the
disks back on the bound host (or otherwise fixed the placement), this
command lifts the latch so the next tick may relaunch it.

It clears ONLY that latch, and only on a row that still carries it: the
attempt budget, backoff and `seen_running` are left alone.

    manage.py vali_reboot_recovery_clear_disks_missing --vm-id VM [--vm-id VM ...]
                                                       [--commit]

Dry-run is the DEFAULT: nothing is written without `--commit`. Exit 0 when
every named VM carried the latch (and, with `--commit`, had it cleared);
1 otherwise.
"""

from __future__ import annotations

import sys
from typing import Any

from django.core.management.base import BaseCommand, CommandParser

from apps.orchestration import service
from apps.orchestration.models import RebootRecovery


class Command(BaseCommand):
    help = "Clear reboot-recovery's sticky disks-missing latch for VMs (dry-run by default)."

    def add_arguments(self, parser: CommandParser) -> None:
        parser.add_argument("--vm-id", action="append", required=True, dest="vm_ids")
        parser.add_argument(
            "--commit", action="store_true", help="Write the change (default: dry-run)."
        )

    def handle(self, *args: Any, **opts: Any) -> None:
        commit: bool = opts["commit"]
        ok = True
        for vm_id in opts["vm_ids"]:
            rows = RebootRecovery.objects.filter(
                vm__vm_id=vm_id, last_outcome=service.DISKS_MISSING_OUTCOME
            )
            if not rows.exists():
                self.stdout.write(f"{vm_id}: no disks-missing latch — nothing to clear")
                ok = False
                continue
            if not commit:
                self.stdout.write(f"{vm_id}: WOULD clear the disks-missing latch (dry-run)")
                continue
            # Filtered on the latch itself, so a concurrent re-scope or
            # healthy observation that already cleared it is not overwritten.
            cleared = rows.update(last_outcome="")
            self.stdout.write(
                f"{vm_id}: disks-missing latch cleared"
                if cleared
                else f"{vm_id}: latch changed concurrently — nothing written"
            )
            ok = ok and bool(cleared)
        if not ok:
            sys.exit(1)
