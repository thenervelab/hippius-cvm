"""`vali_dedicated_reprobe` — send a dedicated disk back to the R3 probe.

A `free` (or `unfit`) disk goes to `pending_probe`: off sale until the
next d1 verdict, which sets its verified tier to min(classification,
declared class). The way an operator re-grades a disk probed before the
ssd/nvme thresholds existed (every such disk was graded `hdd`), or one
re-cabled or re-seated. Never a disk a VM or a probe holds, nor one whose
release wipe is not yet reported.

## Usage

    python manage.py vali_dedicated_reprobe --node-id <64-hex> --disk wwn-0x5000c500a1b2c3d4 \\
        --by ops@hippius --reason "re-grade after the ssd/nvme d1 thresholds"

    python manage.py vali_dedicated_reprobe --node-id <64-hex> --disk <id> --dry-run

## Refusals (CommandError, nothing written)

- `--node-id` is not 64 hex; the node has no such disk;
- the disk is not `free` or `unfit` (assigned, probing, pending, released,
  failed, replaced), or it moved meanwhile;
- `--by` or `--reason` is missing on a real write.

## Audit

One `MinerCapacityAudit` row (`field = dedicated_disk_state`, `actor =
op:<--by>`, reason `operator-reprobe: <--reason>`) in the same transaction,
via `apps.disktier.dedicated.request_reprobe`; the same JSON is logged on
`apps.disktier.dedicated` and echoed as the last line of stdout.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any

from django.core.management.base import BaseCommand, CommandError

from apps.disktier import dedicated
from apps.disktier.models import DedicatedDisk

log = logging.getLogger("apps.disktier.dedicated")

_NODE_ID_RE = re.compile(r"^[0-9a-f]{64}$")


class Command(BaseCommand):
    help = "Send a free or unfit dedicated disk back to the d1 probe (audited)."

    def add_arguments(self, parser: Any) -> None:
        parser.add_argument("--node-id", required=True, help="On-chain node id (64 hex).")
        parser.add_argument("--disk", required=True, help="The disk's /dev/disk/by-id basename.")
        parser.add_argument(
            "--dry-run", action="store_true", help="Print the change without writing it."
        )
        parser.add_argument("--by", default="", help="Operator identity (required to write).")
        parser.add_argument("--reason", default="", help="Why (required to write).")

    def handle(self, *args: Any, **opts: Any) -> None:
        node_id = opts["node_id"].strip().lower()
        if not _NODE_ID_RE.match(node_id):
            raise CommandError(f"--node-id {opts['node_id']!r} is not 64 lowercase hex")
        disk_id = opts["disk"].strip()
        by: str = opts["by"].strip()
        reason: str = opts["reason"].strip()
        dry_run: bool = opts["dry_run"]
        if not dry_run and not by:
            raise CommandError("--by <operator identity> is required for a real write")
        if not dry_run and not reason:
            raise CommandError("--reason <why> is required for a real write")
        disk = DedicatedDisk.objects.filter(miner_node_id=node_id, disk_id=disk_id).first()
        if disk is None:
            raise CommandError(f"no dedicated disk {disk_id!r} on node {node_id}")
        if disk.state not in dedicated.REPROBE_STATES or disk.assigned_vm_id is not None:
            raise CommandError(
                f"disk {disk_id} is {disk.state}: only a free or unfit disk is re-probed"
            )
        self.stdout.write(f"node   {node_id}")
        self.stdout.write(f"disk   {disk_id}")
        self.stdout.write(
            f"state: {disk.state} -> pending_probe (verified_tier {disk.verified_tier}, "
            f"declared_class {disk.declared_class or '-'})"
        )
        if not dry_run and not dedicated.request_reprobe(
            disk,
            reason=f"operator-reprobe: {reason}",
            actor=f"op:{by}",
        ):
            raise CommandError(f"disk {disk_id} moved meanwhile: nothing written")
        audit = json.dumps(
            {
                "event": "dedicated_disk_reprobe",
                "by": by,
                "node_id": node_id,
                "disk_id": disk_id,
                "dry_run": dry_run,
                "reason": reason,
                "before": disk.state,
                "after": "pending_probe",
            },
            sort_keys=True,
        )
        log.info("dedicated disk re-probe %s: %s", "dry-run" if dry_run else "requested", audit)
        if dry_run:
            self.stdout.write("dry run — nothing written")
        else:
            self.stdout.write(self.style.SUCCESS("re-probe requested"))
        self.stdout.write(audit)
