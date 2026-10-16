"""`vali_failover_auto` — operator controls of the automatic failover worker
(docs/design/backup-failover.md §9.4).

    manage.py vali_failover_auto reset --vm-id <vm> --operator <name> [--reason ...]

`reset`: after `MAX_FAILED_ATTEMPTS` failed automatic failovers off a miner
the worker stops trying that VM until an operator looks; this records that
they did, so only failures from now on count.
"""

from __future__ import annotations

from typing import Any

from django.core.management.base import BaseCommand, CommandError

from apps.lifecycle.models import Vm
from apps.orchestration.models import AutoFailoverReset


class Command(BaseCommand):
    help = "Operator controls of the automatic failover worker."

    def add_arguments(self, parser: Any) -> None:
        sub = parser.add_subparsers(dest="action", required=True)
        reset = sub.add_parser("reset", help="forget a VM's failed automatic failovers")
        reset.add_argument("--vm-id", required=True)
        reset.add_argument("--operator", required=True)
        reset.add_argument("--reason", default="")

    def handle(self, *args: Any, **opts: Any) -> None:
        vm = Vm.objects.filter(vm_id=opts["vm_id"]).first()
        if vm is None:
            raise CommandError(f"no vm {opts['vm_id']!r}")
        operator = opts["operator"].strip()
        if not operator:
            raise CommandError("--operator must name who looked")
        AutoFailoverReset.objects.create(
            vm=vm, reset_by=operator[:128], reason=opts["reason"][:256]
        )
        self.stdout.write(
            f"vm {vm.vm_id}: failed automatic failovers reset by {operator}; "
            "the worker may try it again"
        )
