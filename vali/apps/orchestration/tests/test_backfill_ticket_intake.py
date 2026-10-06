"""`vali_backfill_ticket_intake`: record the pre-#1187 relaunch ticket of a
never-migrated VM, so a failed §25 restores it instead of leaving it down."""

from __future__ import annotations

from io import StringIO
from typing import Any

import pytest
from django.core.management import call_command

from apps.lifecycle.models import Vm, VmState
from apps.orchestration.management.commands import vali_backfill_ticket_intake as cmd
from apps.orders.models import OrderTicketIntake

from .factories import make_migration_job, make_vm

pytestmark = pytest.mark.django_db


def _evidence(monkeypatch: pytest.MonkeyPatch, bundles: dict[str, Any]) -> None:
    from apps.orchestration.services import kbs_evidence

    monkeypatch.setattr(kbs_evidence, "fetch_evidence", lambda vm_id: bundles.get(vm_id))


def _run(*args: str) -> str:
    out = StringIO()
    call_command("vali_backfill_ticket_intake", *args, stdout=out)
    return out.getvalue()


def test_a_never_migrated_vms_relaunch_ticket_is_recorded(monkeypatch) -> None:
    vm = make_vm("vm-r", generation=1, host="node-src")
    _evidence(monkeypatch, {"vm-r": {"ticket_id": "tk-vm-r-0dcdb670"}})

    assert "would record tk-vm-r-0dcdb670" in _run()
    assert OrderTicketIntake.objects.count() == 0, "dry-run writes nothing"

    _run("--commit")
    row = OrderTicketIntake.objects.get(ticket_id="tk-vm-r-0dcdb670")
    assert (row.vm_id, row.vm_generation, row.node_id) == ("vm-r", 1, "node-src")
    assert row.received_from == cmd.RECEIVED_FROM
    assert cmd.backfill_verdict(vm) == ("skip", "already-recorded")


@pytest.mark.parametrize(
    ("setup", "reason"),
    [
        (lambda vm: Vm.objects.filter(pk=vm.pk).update(generation=2), "generation:2"),
        (lambda vm: Vm.objects.filter(pk=vm.pk).update(host=""), "no-bound-host"),
        (lambda vm: make_migration_job(vm), "has-a-migration-history"),
    ],
)
def test_only_a_vm_the_kbs_holds_at_1_on_its_host_qualifies(monkeypatch, setup, reason) -> None:
    vm = make_vm("vm-r", generation=1, host="node-src")
    _evidence(monkeypatch, {"vm-r": {"ticket_id": "tk-vm-r-0dcdb670"}})
    setup(vm)
    vm.refresh_from_db()
    assert cmd.backfill_verdict(vm) == ("skip", reason)


@pytest.mark.parametrize(
    ("bundle", "reason"),
    [
        (None, "no-kbs-evidence-bundle"),
        ({"ticket_id": "tk-mig-vm-r-2-abc"}, "not-a-vali-launch-ticket:tk-mig-vm-r-2-abc"),
        ({"ticket_id": "tk-vm-other-1"}, "not-a-vali-launch-ticket:tk-vm-other-1"),
    ],
)
def test_only_the_vms_own_launch_ticket_is_recorded(monkeypatch, bundle, reason) -> None:
    vm = make_vm("vm-r", generation=1, host="node-src")
    _evidence(monkeypatch, {"vm-r": bundle})
    assert cmd.backfill_verdict(vm) == ("skip", reason)


def test_a_non_active_vm_is_skipped(monkeypatch) -> None:
    vm = make_vm("vm-r", generation=1, host="node-src")
    Vm.objects.filter(pk=vm.pk).update(state=VmState.DECOMMISSIONING)
    vm.refresh_from_db()
    _evidence(monkeypatch, {"vm-r": {"ticket_id": "tk-vm-r-0dcdb670"}})
    assert cmd.backfill_verdict(vm) == ("skip", "not-active:decommissioning")
