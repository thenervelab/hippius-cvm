"""`vali_storage_move` — live-move a running VM's OS disk to another pool of
its host (`apps.disktier.storage_move`).

## Usage

    python manage.py vali_storage_move start --vm-id <vm_id> --to nvme0 \\
        [--bandwidth 200] --by ops@hippius
    python manage.py vali_storage_move status [--vm-id <vm_id>]
    python manage.py vali_storage_move cancel --vm-id <vm_id>
    python manage.py vali_storage_move release --vm-id <vm_id> --by ops@hippius
    python manage.py vali_storage_move abandon --vm-id <vm_id> --by ops@hippius
    python manage.py vali_storage_move resolve --vm-id <vm_id> --on source|target \\
        --by ops@hippius

`start` only admits the move: the orchestration tick sends it, follows it,
verifies the guest on the target and releases the source. `cancel` aborts
the copy before the pivot (refused by the agent after it). `release` hands
a `failed:verify-timeout|release-refused|agent-unanswered` move back to the
tick, once an operator checked the guest runs on the target. `abandon`
ends a move vali cannot finish without sending anything (the agent's
journal is then the operator's to settle on the host). `resolve` records
how an operator settled a `move-pivot-unknown` on the host
(docs/operator/storage-move-runbook.md).
"""

from __future__ import annotations

import json
from typing import Any

from django.core.management.base import BaseCommand, CommandError, CommandParser

from apps.disktier import storage_move
from apps.disktier.models import TERMINAL_MOVE_STATES, VmStorageMove


def _row(move: VmStorageMove) -> dict[str, Any]:
    return {
        "move_id": move.move_id,
        "vm_id": move.vm.vm_id,
        "node_id": move.miner_node_id,
        "source_pool": move.source_pool,
        "target_pool": move.target_pool,
        "state": move.state,
        "agent_phase": move.agent_phase,
        "code": move.code,
        "bytes_done": move.bytes_done,
        "bytes_total": move.bytes_total,
        "last_error": move.last_error,
        "requested_by": move.requested_by_principal,
        "created_at": move.created_at.isoformat(),
        "redefined_at": move.redefined_at.isoformat() if move.redefined_at else None,
        "finished_at": move.finished_at.isoformat() if move.finished_at else None,
    }


class Command(BaseCommand):
    help = "Live-move a running VM's OS disk to another pool of its host."

    def add_arguments(self, parser: CommandParser) -> None:
        parser.add_argument(
            "action", choices=["start", "status", "cancel", "release", "abandon", "resolve"]
        )
        parser.add_argument("--vm-id", default="")
        parser.add_argument("--to", default="", help="The target pool (start).")
        parser.add_argument("--bandwidth", type=int, default=None, help="MiB/s, 10..1000.")
        parser.add_argument("--by", default="", help="Who asks (every write).")
        parser.add_argument(
            "--on",
            default="",
            choices=["", "source", "target"],
            help="resolve: the copy the VM boots from now.",
        )

    def handle(self, *args: Any, **opts: Any) -> None:
        action: str = opts["action"]
        vm_id: str = opts["vm_id"].strip()
        if action == "status":
            moves = VmStorageMove.objects.select_related("vm")
            if vm_id:
                moves = moves.filter(vm__vm_id=vm_id)
            else:
                moves = moves.exclude(state__in=TERMINAL_MOVE_STATES)
            for move in moves[:50]:
                self.stdout.write(json.dumps(_row(move), sort_keys=True))
            return
        if not vm_id:
            raise CommandError("--vm-id is required")
        by: str = opts["by"].strip()
        try:
            if action == "start":
                if not opts["to"] or not by:
                    raise CommandError("start needs --to and --by")
                move = storage_move.request_move(
                    vm_id=vm_id,
                    target_pool=opts["to"].strip(),
                    bandwidth_mib_s=opts["bandwidth"],
                    requester=storage_move.Requester(principal=f"op:{by}"[:128]),
                )
            elif action == "cancel":
                move = self._live(vm_id)
                move = storage_move.cancel(move)
            elif action == "resolve":
                if not by or not opts["on"]:
                    raise CommandError("resolve needs --on and --by")
                move = VmStorageMove.objects.filter(
                    vm__vm_id=vm_id, state="failed", code=storage_move.PIVOT_UNKNOWN
                ).first()
                if move is None:
                    raise CommandError(f"no move-pivot-unknown storage move of {vm_id!r}")
                move = storage_move.resolve_pivot_unknown(move, on=opts["on"], by=f"op:{by}"[:128])
            elif action == "abandon":
                if not by:
                    raise CommandError("abandon needs --by")
                move = storage_move.abandon(self._live(vm_id), by=f"op:{by}"[:128])
            else:
                if not by:
                    raise CommandError("release needs --by")
                move = VmStorageMove.objects.filter(
                    vm__vm_id=vm_id,
                    state="failed",
                    code__in=storage_move.RELEASABLE_BY_HAND,
                ).first()
                if move is None:
                    raise CommandError(f"no releasable storage move of {vm_id!r}")
                move = storage_move.force_release(move, by=f"op:{by}"[:128])
        except storage_move.MoveRefused as exc:
            raise CommandError(f"{exc.code}: {exc}") from exc
        self.stdout.write(json.dumps(_row(move), sort_keys=True))

    @staticmethod
    def _live(vm_id: str) -> VmStorageMove:
        move = (
            VmStorageMove.objects.filter(vm__vm_id=vm_id)
            .exclude(state__in=TERMINAL_MOVE_STATES)
            .first()
        )
        if move is None:
            raise CommandError(f"no storage move of {vm_id!r} in flight")
        return move
