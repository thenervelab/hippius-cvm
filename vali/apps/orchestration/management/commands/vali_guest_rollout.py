"""`vali_guest_rollout` — move a set of VMs onto a guest components release
in waves (`apps.orchestration.guest_rollout`,
docs/design/guest-component-rollout.md). Mirrors `/v1/guest-rollouts`.

    manage.py vali_guest_rollout create --release N --canary <vm> [--canary <vm> ...]
        [--vm-id <vm> ...] [--tenant <id> ...] [--node <id> ...] [--bake <id> ...]
        [--waves 5,25,50,100] [--max-concurrent 2] [--wave-pause-s 1800]
        [--max-failure-ratio 0.1] [--not-before 2026-10-06T02:00:00Z]
        [--decided-by <client>] [--apply]          # dry-run (scope) without --apply
    manage.py vali_guest_rollout status <rollout_id>
    manage.py vali_guest_rollout pause|resume|abort <rollout_id> [--reason ...]

The rollout runs in the orchestration tick (`VALI_GUEST_UPGRADE_ENABLED`).
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any

from django.core.management.base import BaseCommand, CommandError

from apps.orchestration import guest_rollout, guest_upgrade
from apps.orchestration.models import GuestRollout
from apps.orchestration.services import launch


class Command(BaseCommand):
    help = "Guest components rollouts (dry-run by default)."

    def add_arguments(self, parser: Any) -> None:
        parser.add_argument("action", choices=["create", "status", "pause", "resume", "abort"])
        parser.add_argument("rollout_id", nargs="?", default="")
        parser.add_argument("--release", type=int)
        parser.add_argument("--canary", action="append", default=[])
        parser.add_argument("--vm-id", action="append", default=[])
        parser.add_argument("--tenant", action="append", default=[])
        parser.add_argument("--node", action="append", default=[])
        parser.add_argument("--bake", action="append", default=[])
        parser.add_argument("--waves", default="")
        parser.add_argument("--max-concurrent", type=int, default=2)
        parser.add_argument("--wave-pause-s", type=int, default=1800)
        parser.add_argument("--max-failure-ratio", type=float, default=0.1)
        parser.add_argument("--not-before", default="")
        parser.add_argument("--decided-by", default="")
        parser.add_argument("--reason", default="")
        parser.add_argument("--apply", action="store_true")

    def handle(self, *args: Any, **opts: Any) -> None:
        if opts["action"] == "create":
            self._create(opts)
            return
        rollout = GuestRollout.objects.filter(rollout_id=opts["rollout_id"]).first()
        if rollout is None:
            raise CommandError(f"no rollout {opts['rollout_id']!r}")
        try:
            if opts["action"] == "pause":
                guest_rollout.pause(rollout, opts["reason"] or "paused by an operator")
            elif opts["action"] == "resume":
                guest_rollout.resume(rollout)
            elif opts["action"] == "abort":
                guest_rollout.abort(rollout, by=opts["reason"] or "operator")
        except guest_rollout.RolloutRefused as exc:
            raise CommandError(f"refused: {exc.category}: {exc.message}") from exc
        rollout.refresh_from_db()
        self.stdout.write(json.dumps(guest_rollout.serialize_rollout(rollout), indent=2))

    def _create(self, opts: dict[str, Any]) -> None:
        if opts["release"] is None or not opts["canary"]:
            raise CommandError("create needs --release and at least one --canary")
        scope = {
            "vm_ids": opts["vm_id"],
            "tenant_ids": opts["tenant"],
            "node_ids": opts["node"],
            "bake_ids": opts["bake"],
        }
        scope = {k: v for k, v in scope.items() if v}
        waves = [int(w) for w in opts["waves"].split(",") if w.strip()] or None
        not_before = None
        if opts["not_before"]:
            try:
                not_before = datetime.fromisoformat(opts["not_before"].replace("Z", "+00:00"))
            except ValueError as exc:
                raise CommandError(f"--not-before: {exc}") from exc
        if not opts["apply"]:
            vms = guest_rollout.scope_vms(scope)
            missing = [
                vm.vm_id for vm in vms if guest_upgrade.build_for_vm(vm, opts["release"]) is None
            ]
            self.stdout.write(
                f"dry-run: release {opts['release']}, canaries {opts['canary']}, "
                f"{len(vms)} VM(s) in scope, {len(missing)} without a build"
                + (f": {', '.join(missing)}" if missing else "")
                + " — add --apply"
            )
            return
        try:
            rollout = guest_rollout.create_rollout(
                release=opts["release"],
                canary_vm_ids=opts["canary"],
                scope=scope,
                decided_by=launch.resolve_forced_launch_principal(opts["decided_by"]),
                waves=waves,
                max_concurrent=opts["max_concurrent"],
                wave_pause_s=opts["wave_pause_s"],
                max_failure_ratio=opts["max_failure_ratio"],
                not_before=not_before,
            )
        except guest_rollout.RolloutRefused as exc:
            extra = f" ({', '.join(exc.missing)})" if exc.missing else ""
            raise CommandError(f"refused: {exc.category}: {exc.message}{extra}") from exc
        self.stdout.write(json.dumps(guest_rollout.serialize_rollout(rollout), indent=2))
