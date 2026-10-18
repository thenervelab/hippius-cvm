"""`vali_approve_miner` — approve a pending external miner and anchor it.

While `VALI_MINER_APPROVAL_REQUIRED` is on, a miner first seen on chain is
PENDING: it heartbeats and reports as usual but takes no new placement
(`apps.scheduler.approval`). This command approves it and sets its
host-size anchor to min(what you declare, what its heartbeat measures).

## Usage

    python manage.py vali_approve_miner --list-pending

    python manage.py vali_approve_miner --miner-id <id> --show

    python manage.py vali_approve_miner --node-id <64-hex> \\
        --cpus 64 --memory-mb 257000 --disk-gb 3500 \\
        --by ops@hippius --reason "operator sheet + onboarding call" [--dry-run]

    python manage.py vali_approve_miner --node-id <64-hex> --revoke \\
        --by ops@hippius --reason "host swapped without notice"

`--trust operator` additionally sizes the miner from the anchor alone;
without it the trust class is left as is (`earned` for a new miner), and
the anchor is one more clamp on what the miner has proven.

Refusals (nothing written): no `MinerCapacity` row yet, already approved
(re-anchor with `vali_set_miner_capacity`), a value out of range, no fresh
heartbeat cpu / memory figure, or an anchor below what vali already placed
there. Every applied change lands a `MinerCapacityAudit` row per field
(`actor = op:<--by>`); the result is echoed as JSON on the last line.

`--revoke` puts an approved (or pending) miner back to pending and marks it
revoked: the automatic approval (`VALI_MINER_AUTO_APPROVE`) never takes a
revoked miner again — only an approval from this command or the API does.
`--list-pending` shows each pending miner's revocation and the first
automatic-approval condition it fails.

`--auto-evaluate [--json]` is read-only: for EVERY miner, approved ones
included, what the automatic approval would decide — every condition
passed or failed, `would_approve` (the next pass, as configured) and
`would_approve_if_pending` (the miner alone, as a new pending miner with the
switch on), and the anchor per term (declared side vs heartbeat vs result),
both as the real pass would set it and as a new miner would get it
(`approval.evaluate_auto_approval`). It writes nothing; it is how to check
the rule against the live fleet before turning `VALI_MINER_AUTO_APPROVE` on.
"""

from __future__ import annotations

import json
import re
from typing import Any

from django.core.management.base import BaseCommand, CommandError

from apps.scheduler import approval
from apps.scheduler.models import CapacityTrustClass, MinerCapacity

_NODE_ID_RE = re.compile(r"^[0-9a-f]{64}$")


class Command(BaseCommand):
    help = (
        "Approve a pending miner and set its host-size anchor to "
        "min(declared, heartbeat-measured); or --list-pending / --show."
    )

    def add_arguments(self, parser: Any) -> None:
        target = parser.add_mutually_exclusive_group(required=True)
        target.add_argument("--node-id", help="The miner's 64-hex chain node id.")
        target.add_argument("--miner-id", help="The miner's vali miner_id.")
        target.add_argument(
            "--list-pending",
            action="store_true",
            help="List every miner without an approval and exit.",
        )
        target.add_argument(
            "--auto-evaluate",
            action="store_true",
            help="Read-only: what the automatic approval would decide for every miner.",
        )
        parser.add_argument(
            "--json", action="store_true", help="With --auto-evaluate: one JSON object per miner."
        )
        parser.add_argument("--show", action="store_true", help="Print the approval readout.")
        parser.add_argument(
            "--revoke",
            action="store_true",
            help="Revoke the approval: back to pending, never auto-approved again.",
        )
        parser.add_argument("--cpus", type=int, help="Declared host threads.")
        parser.add_argument("--memory-mb", type=int, help="Declared host RAM, MiB.")
        parser.add_argument("--disk-gb", type=int, help="Declared tenant data-disk size, GiB.")
        parser.add_argument(
            "--trust",
            choices=sorted(c.value for c in CapacityTrustClass),
            help="Also set the trust class (default: leave it).",
        )
        parser.add_argument("--by", default="", help="Approver identity (audit actor).")
        parser.add_argument("--reason", default="", help="Why (audit reason).")
        parser.add_argument("--dry-run", action="store_true", help="Compute, write nothing.")

    def handle(self, *args: Any, **options: Any) -> None:
        if options["list_pending"]:
            self._list_pending()
            return
        if options["auto_evaluate"]:
            self._auto_evaluate(as_json=options["json"])
            return
        if options["json"]:
            raise CommandError("--json goes with --auto-evaluate")
        node_id = self._resolve(options["node_id"], options["miner_id"])
        if options["show"]:
            status = approval.approval_status(node_id)
            if status is None:
                raise CommandError(f"no MinerCapacity row for node {node_id}")
            self.stdout.write(json.dumps(status, sort_keys=True))
            return
        if options["revoke"]:
            if options["dry_run"]:
                raise CommandError("--revoke has no --dry-run")
            if any(options[k] is not None for k in ("cpus", "memory_mb", "disk_gb", "trust")):
                raise CommandError("--revoke takes no --cpus / --memory-mb / --disk-gb / --trust")
            try:
                revoked = approval.revoke_approval(
                    node_id, revoker=options["by"], reason=options["reason"]
                )
            except approval.ApprovalRefused as exc:
                raise CommandError(f"[{exc.code}] {exc.message}") from exc
            self.stdout.write(json.dumps(revoked, sort_keys=True))
            return
        if options["cpus"] is None or options["memory_mb"] is None:
            raise CommandError("--cpus and --memory-mb are required to approve")
        try:
            result = approval.approve_miner(
                node_id,
                cpus=options["cpus"],
                memory_mb=options["memory_mb"],
                disk_gb=options["disk_gb"],
                approver=options["by"] or ("dry-run" if options["dry_run"] else ""),
                reason=options["reason"] or ("dry-run" if options["dry_run"] else ""),
                trust_class=options["trust"],
                dry_run=options["dry_run"],
            )
        except approval.ApprovalRefused as exc:
            raise CommandError(f"[{exc.code}] {exc.message}") from exc
        self.stdout.write(json.dumps(result.as_dict(), sort_keys=True))

    def _auto_evaluate(self, *, as_json: bool) -> None:
        verdicts = approval.evaluate_auto_approval()
        for v in verdicts:
            if as_json:
                self.stdout.write(json.dumps(v, sort_keys=True))
                continue
            if v["state"] == "error":
                self.stdout.write(f"{v['node_id']} state=error {v['error']}")
                continue
            reasons = [
                f"{c['name']}[{c['blocker']}]" for c in v["conditions"] if c["passed"] is False
            ] + [
                f"{name}[{v[name]['refusal']}]"
                for name in ("anchor", "anchor_as_new")
                if not v[name]["ok"]
            ]
            failed = ",".join(reasons) or "-"
            self.stdout.write(
                f"{v['node_id']} state={v['state']} would_approve={v['would_approve']} "
                f"if_pending={v['would_approve_if_pending']} failed={failed}\n"
                f"    anchor:        {self._terms(v['anchor'])}\n"
                f"    anchor_as_new: {self._terms(v['anchor_as_new'])}\n"
                f"    current:       {v['current_anchor']}"
            )
        if not as_json:
            self.stdout.write(
                f"{len(verdicts)} miner(s) evaluated; auto-approve on="
                f"{approval.auto_approve_enabled()}; nothing written"
            )

    @staticmethod
    def _terms(anchor: dict[str, Any]) -> str:
        if not anchor["ok"]:
            return f"refused [{anchor['refusal']}] {anchor['detail']}"
        return " ".join(
            f"{dim}={t['result']}("
            + " ".join(f"{k}={val}" for k, val in t.items() if k != "result")
            + ")"
            for dim, t in anchor["terms"].items()
        )

    def _list_pending(self) -> None:
        from django.utils import timezone

        now = timezone.now()
        rows = MinerCapacity.objects.filter(approved_at__isnull=True).order_by("miner_node_id")
        for row in rows:
            revoked = f" revoked={row.revoked_at.isoformat()}" if row.revoked_at else ""
            self.stdout.write(
                f"{row.miner_node_id} status={row.status} created={row.created_at.isoformat()}"
                f"{revoked} auto={approval.auto_approval_blocker(row, now=now) or 'eligible'}"
            )
        self.stdout.write(
            f"{rows.count()} pending; approval required={approval.approval_required()}"
        )

    @staticmethod
    def _resolve(node_id: str | None, miner_id: str | None) -> str:
        if node_id is not None:
            node_id = node_id.strip().lower()
            if not _NODE_ID_RE.match(node_id):
                raise CommandError("--node-id must be 64 lower-case hex chars")
            return node_id
        from apps.miners.models import MinerIdentity

        identity = MinerIdentity.objects.filter(miner_id=miner_id).first()
        if identity is None:
            raise CommandError(f"unknown miner_id {miner_id!r}")
        if not identity.chain_node_id:
            raise CommandError(f"miner {miner_id!r} has no chain_node_id")
        return identity.chain_node_id.lower()
