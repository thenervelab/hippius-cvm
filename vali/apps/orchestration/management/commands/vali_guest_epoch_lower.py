"""`vali_guest_epoch_lower` — the audited break-glass for a VM's guest
components floor (docs/design/guest-component-rollout.md, G3).

Once an upgrade onto a release with a higher security epoch is decided,
vali never launches the VM on a lower-epoch set again. When that leaves a
VM stuck (`upgrade_blocked`: its miner will not boot the new set and a
replacement is not an option), an operator may lower the floor — the one
way back to the previous set, recorded in the VM's floor history:

    manage.py vali_guest_epoch_lower --vm-id <vm> --to <epoch> \\
        --operator <who> --reason <why>          # dry-run; add --apply

Refused while a guest upgrade holds the VM.
"""

from __future__ import annotations

from typing import Any

from django.core.management.base import BaseCommand, CommandError

from apps.lifecycle.models import Vm
from apps.orchestration.services import guest_components


class Command(BaseCommand):
    help = "Lower a VM's guest components required epoch (audited break-glass)."

    def add_arguments(self, parser: Any) -> None:
        parser.add_argument("--vm-id", required=True)
        parser.add_argument("--to", type=int, required=True)
        parser.add_argument("--operator", required=True)
        parser.add_argument("--reason", required=True)
        parser.add_argument("--apply", action="store_true")

    def handle(self, *args: Any, **opts: Any) -> None:
        vm = Vm.objects.filter(vm_id=opts["vm_id"]).first()
        if vm is None:
            raise CommandError(f"no vm {opts['vm_id']!r}")
        current = guest_components.required_epoch(vm.vm_id)
        if not opts["apply"]:
            self.stdout.write(
                f"dry-run: vm={vm.vm_id} required_epoch={current} → {opts['to']} "
                "(add --apply to write)"
            )
            return
        try:
            before = guest_components.lower_required_epoch(
                vm, opts["to"], operator=opts["operator"], reason=opts["reason"]
            )
        except ValueError as exc:
            raise CommandError(str(exc)) from exc
        self.stdout.write(f"lowered: vm={vm.vm_id} required_epoch={before} → {opts['to']}")
