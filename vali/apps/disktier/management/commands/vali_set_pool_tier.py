"""`vali_set_pool_tier` — the operator override of a storage pool's tier.

An override wins over the probe-verified tier while it is set: an
emergency `unfit` to stop new disks landing on a pool, or a tier pinned
while the probe cannot yet establish one. `--clear` hands the pool back to
its probes. `--show` prints the pool and writes nothing.

## Usage

    python manage.py vali_set_pool_tier --node-id <64-hex> --pool default \\
        --override unfit --by ops@hippius --reason "controller errors in dmesg"

    python manage.py vali_set_pool_tier --miner-id <miner_id> --pool nvme0 --clear \\
        --by ops@hippius --reason "disk replaced; let the probe decide"

    python manage.py vali_set_pool_tier --node-id <64-hex> --pool default --show

## Refusals (CommandError, nothing written)

- the pool row does not exist. Pools are created from the miner's report;
  the one exception is the implicit `default` pool (every node has one —
  its data root), created on first override when the node has a
  `MinerCapacity` row;
- `--miner-id` is unknown or has no `chain_node_id`; `--node-id` is not 64
  hex; `--pool` is not a pool id;
- `--by` or `--reason` is missing on a real (non-dry-run) write;
- neither `--override` nor `--clear` (nor `--show`) was given.

## Audit

Every applied change lands one `MinerCapacityAudit` row
(`field = disk_tier_override:<pool>`, `actor = op:<--by>`) in the same
transaction, via `apps.disktier.override`, and the same JSON is logged on
`apps.disktier.override` and echoed as the last line of stdout.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any

from django.core.management.base import BaseCommand, CommandError
from django.db import transaction

from apps.disktier import override as override_mod
from apps.disktier.models import POOL_ID_MAX_LEN, MinerStoragePool
from apps.scheduler.models import MinerCapacity

log = logging.getLogger("apps.disktier.override")

_NODE_ID_RE = re.compile(r"^[0-9a-f]{64}$")
_POOL_ID_RE = re.compile(rf"^[a-z0-9-]{{1,{POOL_ID_MAX_LEN}}}$")
#: The implicit pool every node has: its data root.
DEFAULT_POOL_ID = "default"

_SHOW_FIELDS: tuple[str, ...] = (
    "declared_class",
    "os_disks",
    "total_gb",
    "available_gb",
    "budget_gb",
    "reported_at",
    "tier",
    "tier_since",
    "operator_override",
    "override_reason",
    "health",
    "health_since",
    "next_probe_due_at",
    "retired_at",
)


def implicit_default_pool_fields(capacity: MinerCapacity) -> dict[str, Any]:
    """The implicit `default` pool of a node that reports no pools: its data
    root, as today's single-pool `MinerCapacity` disk columns describe it
    (untrusted reports, the declared budget, vali's earned ceiling). A
    snapshot taken when the row is created."""
    return {
        "total_gb": capacity.reported_data_disk_total_gb,
        "available_gb": capacity.reported_data_disk_available_gb,
        "budget_gb": capacity.declared_disk_gb_budget,
        "earned_gb": capacity.earned_disk_gb,
        "reported_at": capacity.disk_reported_at,
    }


class Command(BaseCommand):
    help = "Set or clear the operator tier override of a miner's storage pool (audited)."

    def add_arguments(self, parser: Any) -> None:
        who = parser.add_mutually_exclusive_group(required=True)
        who.add_argument("--node-id", default=None, help="On-chain node id (64 hex).")
        who.add_argument("--miner-id", default=None, help="MinerIdentity.miner_id.")
        parser.add_argument("--pool", required=True, help="Pool id (e.g. `default`).")
        action = parser.add_mutually_exclusive_group()
        action.add_argument(
            "--override",
            choices=sorted(override_mod.OVERRIDE_TIERS),
            default=None,
            help="Pin the pool's tier; wins over probes until cleared.",
        )
        action.add_argument("--clear", action="store_true", help="Remove the override.")
        action.add_argument("--show", action="store_true", help="Print the pool; write nothing.")
        parser.add_argument(
            "--dry-run", action="store_true", help="Print the change without writing it."
        )
        parser.add_argument("--by", default="", help="Operator identity (required to write).")
        parser.add_argument("--reason", default="", help="Why (required to write).")

    def handle(self, *args: Any, **opts: Any) -> None:
        pool_id: str = opts["pool"].strip()
        if not _POOL_ID_RE.match(pool_id):
            raise CommandError(f"--pool {opts['pool']!r} is not a pool id ([a-z0-9-]{{1,32}})")
        node_id = self._resolve_node_id(opts)
        if opts["show"]:
            self._show(node_id, pool_id)
            return
        if opts["override"] is None and not opts["clear"]:
            raise CommandError("nothing to do — pass --override <tier>, --clear, or --show")

        target: str = "" if opts["clear"] else opts["override"]
        dry_run: bool = opts["dry_run"]
        by: str = opts["by"].strip()
        reason: str = opts["reason"].strip()
        if not dry_run and not by:
            raise CommandError("--by <operator identity> is required for a real write")
        if not dry_run and not reason:
            raise CommandError("--reason <why> is required for a real write")

        with transaction.atomic():
            # A clear never creates the implicit pool: there is nothing on
            # it to clear.
            pool = self._locked_pool(node_id, pool_id, create=not dry_run and bool(target))
            before = pool.operator_override if pool is not None else ""
            self.stdout.write(f"node   {node_id}")
            self.stdout.write(f"pool   {pool_id}")
            self.stdout.write(f"operator_override: {before!r} -> {target!r}")
            if not dry_run:
                change = None
                if pool is not None:
                    try:
                        change = override_mod.set_pool_override(
                            pool, target, actor=f"op:{by}", reason=reason
                        )
                    except ValueError as exc:
                        raise CommandError(str(exc)) from exc
                if change is None:
                    self.stdout.write("no change (already set to this override and reason)")
                    return

        audit = json.dumps(
            {
                "event": "disk_pool_tier_override",
                "by": by,
                "node_id": node_id,
                "pool_id": pool_id,
                "dry_run": dry_run,
                "reason": reason,
                "before": before,
                "after": target,
            },
            sort_keys=True,
        )
        log.info("pool tier override %s: %s", "dry-run" if dry_run else "set", audit)
        if dry_run:
            self.stdout.write("dry run — nothing written")
        else:
            self.stdout.write(self.style.SUCCESS("pool tier override updated"))
        self.stdout.write(audit)

    def _locked_pool(self, node_id: str, pool_id: str, *, create: bool) -> MinerStoragePool | None:
        """The pool under a row lock. Only the implicit `default` pool of a
        node vali knows may be created here (and only on a real write); any
        other pool comes from the miner's report."""
        pool = (
            MinerStoragePool.objects.select_for_update()
            .filter(miner_node_id=node_id, pool_id=pool_id)
            .first()
        )
        if pool is not None:
            return pool
        if pool_id != DEFAULT_POOL_ID:
            raise CommandError(
                f"no pool {pool_id!r} on node {node_id} — pools are created from the "
                "miner's report; only the implicit `default` pool can be created here"
            )
        capacity = MinerCapacity.objects.filter(miner_node_id=node_id).first()
        if capacity is None:
            raise CommandError(
                f"no MinerCapacity row for node {node_id} — vali does not know this node"
            )
        if not create:
            return None
        pool, _created = MinerStoragePool.objects.get_or_create(
            miner_node_id=node_id,
            pool_id=DEFAULT_POOL_ID,
            defaults=implicit_default_pool_fields(capacity),
        )
        return MinerStoragePool.objects.select_for_update().get(pk=pool.pk)

    def _resolve_node_id(self, opts: dict[str, Any]) -> str:
        if opts["node_id"] is not None:
            node_id = opts["node_id"].strip().lower()
            if not _NODE_ID_RE.match(node_id):
                raise CommandError(f"--node-id {opts['node_id']!r} is not 64 lowercase hex")
            return node_id

        from apps.miners.models import MinerIdentity

        miner_id: str = opts["miner_id"]
        identity = MinerIdentity.objects.filter(miner_id=miner_id).first()
        if identity is None:
            raise CommandError(f"no MinerIdentity {miner_id!r}")
        if not identity.chain_node_id:
            raise CommandError(
                f"MinerIdentity {miner_id!r} has no chain_node_id — bridge it first "
                "(POST /v1/admin/miner/register) or pass --node-id"
            )
        return identity.chain_node_id

    def _show(self, node_id: str, pool_id: str) -> None:
        pool = MinerStoragePool.objects.filter(miner_node_id=node_id, pool_id=pool_id).first()
        if pool is None:
            raise CommandError(f"no pool {pool_id!r} on node {node_id}")
        self.stdout.write(f"node   {node_id}")
        self.stdout.write(f"pool   {pool_id}")
        for field in _SHOW_FIELDS:
            self.stdout.write(f"{field}: {getattr(pool, field)!r}")
        self.stdout.write(f"effective_tier: {pool.effective_tier!r}")
