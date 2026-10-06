"""`vali_backfill_ticket_intake` — record the ticket a never-migrated VM was
last granted against, when vali minted it before it recorded its tickets.

## Why

A §25 that fails before the fence restores the source only if the KBS's
latest grant for the VM is a ticket vali knows as the source's own
(`service._kbs_grant_veto`). Launches and reboot-recovery relaunches record
their ticket (`persist_intake`) only since #1187; a VM last relaunched
before that — e.g. the 2026-09-21 reboot-recovery wave — is granted against
a ticket vali has no record of, so a failed migration would leave it down.

## What is recorded, and why it is safe

The ticket_id comes from the KBS's own evidence bundle (read off the KBS
admin listener — the miner is not on that path). A row is written only for
a VM that is `active` at generation 1 on a bound host, whose ticket carries
vali's `tk-<vm_id>-` id, and that no migration ever reached: the KBS then
holds it as `Active{1, host}` (its host is fixed at the first register), so
every grant it ever made was at generation 1 on that host — exactly the
`(vm, 1, host)` the row records.

The row has no COSE blob (vali never kept it). Its only blob reader, the
§25 re-mint's reuse path, matches the migration's `new_gen` (>= 2), never
a generation-1 row.

Dry-run is the default; `--commit` writes.
"""

from __future__ import annotations

from typing import Any

from django.core.management.base import BaseCommand
from django.db import IntegrityError

from apps.lifecycle.models import Vm, VmState
from apps.miners.models import MinerIdentity
from apps.orchestration import service
from apps.orchestration.models import LaunchJob, LaunchJobState, MigrationJob
from apps.orchestration.services import kbs_evidence
from apps.orders.models import OrderTicketIntake

RECEIVED_FROM = "system:backfill-kbs-evidence"


def backfill_verdict(vm: Vm) -> tuple[str, str]:
    """`("record", ticket_id)` when `vm`'s latest grant may be recorded,
    else `("skip", reason)`."""
    if vm.state != VmState.ACTIVE:
        return "skip", f"not-active:{vm.state}"
    if vm.generation != 1:
        return "skip", f"generation:{vm.generation}"
    if not vm.host:
        return "skip", "no-bound-host"
    if MigrationJob.objects.filter(vm=vm).exists():
        return "skip", "has-a-migration-history"
    bundle = kbs_evidence.fetch_evidence(vm.vm_id)
    if bundle is None:
        return "skip", "no-kbs-evidence-bundle"
    ticket_id = str(bundle.get("ticket_id") or "")
    if not ticket_id.startswith(f"tk-{vm.vm_id}-"):
        return "skip", f"not-a-vali-launch-ticket:{ticket_id or '(none)'}"
    if OrderTicketIntake.objects.filter(ticket_id=ticket_id).exists():
        return "skip", "already-recorded"
    if service._launch_ticket_grant(ticket_id) is not None:
        return "skip", "known-from-its-launch-job"
    return "record", ticket_id


class Command(BaseCommand):
    help = __doc__

    def add_arguments(self, parser: Any) -> None:
        parser.add_argument("--commit", action="store_true", help="Write the rows.")

    def handle(self, *args: Any, **opts: Any) -> None:
        commit = bool(opts["commit"])
        recorded = 0
        for vm in Vm.objects.filter(state=VmState.ACTIVE).order_by("vm_id"):
            action, detail = backfill_verdict(vm)
            if action != "record":
                self.stdout.write(f"  {vm.vm_id}: skip ({detail})")
                continue
            if not commit:
                self.stdout.write(f"  {vm.vm_id}: would record {detail} at (1, {vm.host})")
                continue
            _record(vm, detail)
            recorded += 1
            self.stdout.write(f"  {vm.vm_id}: recorded {detail} at (1, {vm.host})")
        mode = "COMMIT" if commit else "DRY-RUN (nothing written)"
        self.stdout.write(f"{mode}: {recorded} recorded")


def _record(vm: Vm, ticket_id: str) -> None:
    launch = (
        LaunchJob.objects.filter(vm_id=vm.vm_id, state=LaunchJobState.SUCCEEDED.value)
        .order_by("-finished_at")
        .first()
    )
    spec = (launch.spec_json if launch else None) or {}
    platform_id = (
        MinerIdentity.objects.filter(miner_id=vm.host)
        .values_list("platform_id", flat=True)
        .first()
    )
    try:
        OrderTicketIntake.objects.create(
            ticket_id=ticket_id,
            vm_id=vm.vm_id,
            tenant_id=vm.tenant_id or str(spec.get("tenant_id") or ""),
            user_id=str(spec.get("user_id") or ""),
            lease_id=vm.lease_id,
            vm_generation=1,
            issue_time=0,
            expiry=0,
            node_id=vm.host,
            platform_id=platform_id or "",
            resource_class=str(spec.get("flavor") or ""),
            kid_hex="",
            cose_blob=b"",
            received_from=RECEIVED_FROM,
        )
    except IntegrityError:
        pass  # recorded concurrently — the row names the same ticket
