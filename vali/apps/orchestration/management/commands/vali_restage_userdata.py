"""`vali_restage_userdata` — give an M0 VM a new cloud-init userdata at its NEXT boot.

The operator's file-reading front end to `apps.orchestration.userdata_restage`.
The module docstring there covers what a restage writes, why it is M0 only,
and how it serializes. The root-only API `POST /v1/vm/<id>/userdata/restage`
is the other front end.

## What it is for

Repairing a running tenant VM whose guest needs a one-off fix that cloud-init
can apply at boot (a `bootcmd` that rewrites a file before
`multi-user.target`), without touching its disks.

The file is stored and delivered BYTE FOR BYTE. No `{{NETBIRD_SETUP_KEY}}`
or other token is required or substituted, and the relaunch mints no NetBird
key for it. The file REPLACES the old userdata, so it must be COMPLETE:
everything the guest's userdata carried, its real values included, plus the
fix. A `bootcmd` runs on EVERY boot the userdata stays staged: make it
idempotent, or wrap it in `cloud-init-per once <name> ...`. Restage the
original afterwards. See `docs/operator/userdata-restage-runbook.md`.

Until the VM is relaunched, nothing it boots changes. `--relaunch` admits
the write as a tracked restage job, exactly as the API does: the job holds
the VM against every other operation (launch intake included) until
`vali_orchestration_tick` has stopped and started it. Poll it with
`GET /v1/vm/<id>/userdata/restage/<job_id>`. Without `--relaunch` only the
record moves; the next power stop/start takes it.

## Invocation

    manage.py vali_restage_userdata --vm-id <vm> --userdata-file <path> \\
        --by <who> --reason <why> [--dry-run] [--relaunch]

Rollback, without new bytes:

    manage.py vali_restage_userdata --vm-id <vm> --to-version <N> ...
    manage.py vali_restage_userdata --vm-id <vm> --revert-last ...

`--to-version` points the record at version N of
`{prefix}/{vm_id}/userdata-intake` (Vault KV keeps the previous versions).
`--revert-last` puts back the pointer the latest restage replaced, from the
audit trail, legacy paths included. A rolled-back-to version keeps how it
was staged: a launch template is substituted again at relaunch, a restaged
one is delivered verbatim.

It is behind the same locks as the API: `VALI_USERDATA_RESTAGE_ENABLED`
and the VM allow-list `VALI_USERDATA_RESTAGE_VM_ALLOWLIST` (both off/empty
by default). It also needs a shell in a vali pod.

## Refusals (nothing written)

- the VM is not `active` and powered `running`, or a §25/restore,
  decommission, resize, guest upgrade, power op, reboot-recovery relaunch,
  launch job or restage job is in flight;
- it has no SUCCEEDED launch record;
- it is not provably M0;
- the userdata is empty, not UTF-8, `vault:`-prefixed, or larger than the
  launch API admits;
- a rollback names a version a relaunch could not read back, or the current
  one.

## Custody

The command never prints, logs or stores the userdata: only its size and
sha256. It decrypts nothing.
"""

from __future__ import annotations

import secrets
from pathlib import Path
from typing import Any

from django.core.management.base import BaseCommand, CommandError

from apps.lifecycle.models import Vm
from apps.orchestration import userdata_restage as restage
from apps.orchestration.services import vault_kv


class Command(BaseCommand):
    help = __doc__

    def add_arguments(self, parser: Any) -> None:
        parser.add_argument("--vm-id", required=True, help="The VM to restage.")
        source = parser.add_mutually_exclusive_group(required=True)
        source.add_argument(
            "--userdata-file",
            default="",
            help="LOCAL path to the COMPLETE new cloud-init userdata (stored and "
            "delivered byte for byte; it replaces the old one). Never printed.",
        )
        source.add_argument(
            "--to-version",
            type=int,
            default=None,
            help="Roll back: point the record at this existing version of "
            "{prefix}/{vm_id}/userdata-intake. No bytes are written.",
        )
        source.add_argument(
            "--revert-last",
            action="store_true",
            help="Roll back: put back the pointer the latest restage replaced "
            "(from the audit trail, legacy paths included).",
        )
        parser.add_argument("--by", required=True, help="Who is doing this (audited).")
        parser.add_argument("--reason", required=True, help="Why (audited).")
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Show what would be staged and pointed at; write nothing.",
        )
        parser.add_argument(
            "--relaunch",
            action="store_true",
            help="Admit the write as a tracked restage job: the orchestration tick "
            "stops and starts the VM so its next boot takes the new userdata.",
        )

    def handle(self, *args: Any, **opts: Any) -> None:
        by = str(opts["by"]).strip()
        reason = str(opts["reason"]).strip()
        if not by or not reason:
            raise CommandError("--by and --reason must not be empty")
        if opts["dry_run"] and opts["relaunch"]:
            raise CommandError("--dry-run and --relaunch are mutually exclusive")
        if opts["to_version"] is not None and opts["to_version"] <= 0:
            raise CommandError("--to-version must be a positive version")
        vm_id = str(opts["vm_id"]).strip()
        try:
            restage.check_api_gates(vm_id)
        except restage.RestageRefused as exc:
            raise CommandError(f"vm={vm_id} refused: {exc.category}: {exc.message}") from exc
        vm = Vm.objects.filter(vm_id=vm_id).first()
        if vm is None:
            raise CommandError(f"vm {vm_id!r}: no such VM")
        userdata = b""
        if opts["userdata_file"]:
            try:
                userdata = Path(opts["userdata_file"]).read_bytes()
            except OSError as exc:
                raise CommandError(f"--userdata-file: {exc}") from exc
        try:
            self._run(vm, userdata, opts, by=by, reason=reason)
        except restage.RestageRefused as exc:
            raise CommandError(f"vm={vm_id} refused: {exc.category}: {exc.message}") from exc
        finally:
            userdata = b"\x00" * len(userdata)

    def _run(self, vm: Vm, userdata: bytes, opts: dict[str, Any], *, by: str, reason: str) -> None:
        if opts["userdata_file"]:
            plan = restage.plan_restage(vm, userdata)
            what = (
                f"stage {plan.size} B (sha256 {plan.digest_hex}) at "
                f"{plan.to_path}@{plan.to_version} wrapped under "
                f"{vault_kv.userdata_transit_key_name(vm.vm_id)}, delivered verbatim, "
                "then point the record at it"
            )
        else:
            plan = restage.plan_rollback(
                vm, to_version=opts["to_version"], revert_last=bool(opts["revert_last"])
            )
            what = f"point the record at {plan.to_path}@{plan.to_version} (nothing staged)"
        self.stdout.write(
            f"vm={vm.vm_id} record={plan.job_id} key_mode=M0 "
            f"current={plan.from_path}@{plan.from_version}"
        )
        self.stdout.write(f"plan: {what}")
        if opts["dry_run"]:
            self.stdout.write("vali-restage-userdata: mode=dry-run — nothing written")
            return
        if opts["relaunch"]:
            self._start_job(vm, userdata, opts, by=by, reason=reason)
            return
        written = restage.apply_plan(plan, userdata, operator=by, reason=reason)
        if written.staged_version:
            self.stdout.write(f"staged: {written.to_path}@{written.staged_version}")
        self.stdout.write(
            f"vali-restage-userdata: mode=apply vm={vm.vm_id} "
            f"{plan.from_path}@{plan.from_version} → {written.to_path}@{written.to_version}"
        )
        self.stdout.write(
            f"rollback: --to-version {plan.from_version}"
            if plan.from_path == restage.intake_path(vm.vm_id)
            else "rollback: --revert-last (the previous pointer is a legacy path)"
        )
        self.stdout.write(
            "next: relaunch the VM (power stop + start) — nothing boots the new userdata until then"
        )

    def _start_job(
        self, vm: Vm, userdata: bytes, opts: dict[str, Any], *, by: str, reason: str
    ) -> None:
        from django.conf import settings

        from apps.identity.models import ServiceClient

        # The job is recorded as decided by the root principal (the API's
        # caller); `--by` is the operator in its audit entry.
        root = str(getattr(settings, "VALI_ORCHESTRATION_ROOT_PRINCIPAL", "") or "")
        decided_by = ServiceClient.objects.filter(name=root).first() if root else None
        if decided_by is None:
            raise CommandError(
                "--relaunch needs the orchestration root principal "
                "(VALI_ORCHESTRATION_ROOT_PRINCIPAL) to exist as a ServiceClient"
            )
        if opts["userdata_file"]:
            kind = restage.KIND_RESTAGE
        elif opts["revert_last"]:
            kind = restage.KIND_REVERT
        else:
            kind = restage.KIND_ROLLBACK
        job = restage.start_job(
            vm,
            kind=kind,
            userdata=userdata,
            rollback_to_version=opts["to_version"],
            request_id=f"cli-{secrets.token_hex(8)}",
            decided_by=decided_by,
            operator=by,
            reason=reason,
        )
        self.stdout.write(
            f"vali-restage-userdata: mode=apply vm={vm.vm_id} job={job.job_id} "
            f"{job.from_path}@{job.from_version} → {job.to_path}@{job.to_version} "
            f"phase={job.phase}"
        )
        self.stdout.write(
            "next: vali_orchestration_tick stops and starts the VM; poll "
            f"GET /v1/vm/{vm.vm_id}/userdata/restage/{job.job_id}"
        )
