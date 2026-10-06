"""The Vm-row gate in front of every KBS `register-vm` (`register_gate`).

Reboot-recovery's `launch_on_miner` and the operator `vali_dispatch_launch`
used to bind a VM at the KBS on the strength of a valid ticket alone. The
row is now re-read under lock, across the KBS call: a VM that started a
§24 decommission or a §25 migration, left the generation the ticket was
minted for, or is bound to another host is never registered.
"""

from __future__ import annotations

import json

import pytest
from django.core.management import call_command
from django.db import connection

from apps.lifecycle.models import Vm, VmState
from apps.orchestration.services import launch, register_gate
from apps.orchestration.tests.test_launch_service import (
    _fake_the_launch_choreography,
    _register_miner,
    _spec,
)

pytestmark = pytest.mark.django_db

UD = b"#cloud-config\n# {{NETBIRD_SETUP_KEY}}\n"


def _vm(**fields) -> Vm:
    Vm.objects.filter(vm_id="vm-launch-1").delete()
    base = dict(
        vm_id="vm-launch-1",
        tenant_id="t-launch",
        lease_id="lease-1",
        state=VmState.ACTIVE,
        host="",
        generation=1,
    )
    base.update(fields)
    return Vm.objects.create(**base)


def _count_register(monkeypatch) -> list[bool]:
    """Record every KBS register call, and whether it ran inside the
    transaction holding the row lock."""
    calls: list[bool] = []

    class _Admin:
        vm_id = "vm-launch-1"
        vm_generation = 1
        cached = False

    def _register(*a, **k):
        calls.append(connection.in_atomic_block)
        return _Admin()

    monkeypatch.setattr(launch.kbs_admin, "register_vm_active_with_vm_id", _register)
    return calls


def _change_row_during_mint(monkeypatch, **fields) -> None:
    """The launch runs for minutes between its entry check and the
    register. Simulate a §24/§25 transition landing in that window."""
    from apps.orchestration.services import ticket_mint

    def _mint(*a, **k):
        Vm.objects.filter(vm_id="vm-launch-1").update(**fields)
        return b"cose"

    monkeypatch.setattr(ticket_mint, "mint", _mint)
    monkeypatch.setattr(
        "apps.orchestration.services.migration_ticket.persist_intake",
        lambda *a, **k: None,
    )


# ── launch_on_miner: the paths that must still register ─────────────


# `transaction=True`: without pytest-django's per-test wrapping
# transaction, `in_atomic_block` is True only inside the gate's own
# `atomic()` — which is what proves the lock is held across the KBS call.
@pytest.mark.django_db(transaction=True)
def test_a_fresh_launch_registers_inside_the_row_lock(monkeypatch) -> None:
    miner = _register_miner(1)
    _fake_the_launch_choreography(monkeypatch, dispatch_ok=True)
    calls = _count_register(monkeypatch)
    _vm(host="")
    out = launch.launch_on_miner(_spec(userdata=UD), miner)
    assert out.disposition == launch.ACCEPTED, out.emit
    assert calls == [True], "registered once, inside the lock's transaction"


def test_reboot_recovery_on_the_bound_host_registers(monkeypatch) -> None:
    miner = _register_miner(1)
    _fake_the_launch_choreography(monkeypatch, dispatch_ok=True)
    calls = _count_register(monkeypatch)
    _vm(host="miner-a")
    out = launch.launch_on_miner(_spec(userdata=UD), miner)
    assert out.disposition == launch.ACCEPTED, out.emit
    assert calls == [True]


# ── launch_on_miner: transitions that land mid-launch ───────────────


@pytest.mark.parametrize(
    ("fields", "needle"),
    [
        ({"state": VmState.DECOMMISSIONING}, "decommissioning"),
        ({"state": VmState.DESTROYED}, "destroyed"),
        (
            {"state": VmState.MIGRATING, "migration_dest": "miner-b", "new_generation": 2},
            "migrating",
        ),
        ({"generation": 2}, "generation 2"),
        ({"host": "miner-i"}, "bound to host 'miner-i'"),
    ],
)
def test_a_transition_during_the_launch_is_never_registered(monkeypatch, fields, needle) -> None:
    miner = _register_miner(1)
    _fake_the_launch_choreography(monkeypatch, dispatch_ok=True)
    calls = _count_register(monkeypatch)
    dispatched: list[object] = []
    from apps.orchestration import order_dispatch

    monkeypatch.setattr(order_dispatch, "dispatch_order", lambda *a, **k: dispatched.append(1))
    _vm(host="")
    _change_row_during_mint(monkeypatch, **fields)

    out = launch.launch_on_miner(_spec(userdata=UD), miner)

    assert out.disposition == launch.TERMINAL
    assert out.emit["outcome"] == "kbs-admin-vm-state-refused"
    assert needle in out.emit["error"]
    assert calls == [], "the KBS must not be called"
    assert dispatched == [], "nothing is dispatched"
    assert out.registered is False, "a pre-register refusal"


def test_a_migrating_vm_is_refused_at_entry(monkeypatch) -> None:
    from apps.orchestration.services import vault_kv

    miner = _register_miner(1)
    _fake_the_launch_choreography(monkeypatch, dispatch_ok=True)
    puts: list[str] = []
    monkeypatch.setattr(vault_kv, "put_kv", lambda mount, path, value, **kw: puts.append(path))
    _vm(state=VmState.MIGRATING, host="miner-a", migration_dest="miner-b", new_generation=2)
    with pytest.raises(launch.LaunchConfigError, match="migrating"):
        launch.launch_on_miner(_spec(userdata=UD), miner)
    assert puts == [], "nothing staged for a migrating VM"


# ── register_gate itself ────────────────────────────────────────────


def test_an_absent_row_is_refused_without_calling_the_kbs() -> None:
    called: list[int] = []
    with pytest.raises(register_gate.RegisterRefused, match="no Vm row"):
        register_gate.register_under_vm_lock(
            "vm-nope", generation=1, miner_id="m", register=lambda: called.append(1)
        )
    assert called == []


@pytest.mark.parametrize(
    ("fields", "generation", "miner", "ok"),
    [
        ({}, 1, "m1", True),
        ({"host": "m1"}, 1, "m1", True),
        ({"host": "m2"}, 1, "m1", False),
        ({"generation": 3}, 3, "m1", True),
        ({"generation": 3}, 1, "m1", False),
        ({"state": VmState.MIGRATING, "migration_dest": "m2", "new_generation": 2}, 1, "m1", False),
        ({"state": VmState.DECOMMISSIONING}, 1, "m1", False),
        ({"state": VmState.DESTROYED}, 1, "m1", False),
    ],
)
def test_register_refusal_table(fields, generation, miner, ok) -> None:
    vm = _vm(**fields)
    assert (register_gate.register_refusal(vm, generation=generation, miner_id=miner) is None) is ok


# ── vali_dispatch_launch ────────────────────────────────────────────


def _dispatch_env(monkeypatch, tmp_path, *, ticket_vm="vm-launch-1", platform=None, gen=1):
    from apps.orchestration import order_dispatch
    from apps.orders import validator

    miner = _register_miner(1)
    calls = _count_register(monkeypatch)
    parsed = validator.ParsedTicket(
        ticket_id="tk",
        vm_id=ticket_vm,
        tenant_id="t",
        user_id="u",
        lease_id="lease-1",
        vm_generation=gen,
        issue_time=1,
        expiry=2,
        node_id="miner-a",
        platform_id=platform if platform is not None else miner.platform_id,
        resource_class="small",
        kid_hex="00",
    )
    monkeypatch.setattr(validator, "validate_ticket", lambda b: parsed)
    monkeypatch.setattr(order_dispatch, "build_launch_payload", lambda *a, **k: {})
    monkeypatch.setattr(
        order_dispatch,
        "dispatch_order",
        lambda *a, **k: order_dispatch.DispatchResult(ok=True, status=200, classifier="launched"),
    )
    ticket = tmp_path / "t.cose"
    ticket.write_bytes(b"cose")
    argv = {
        "miner_id": "miner-a",
        "vm_id": "vm-launch-1",
        "order_id": "o-1",
        "cpu_count": 1,
        "memory_mb": 2048,
        "cose_ticket_path": str(ticket),
    }
    return argv, calls


def _run_dispatch(argv, capsys) -> tuple[int, dict]:
    code = 0
    try:
        call_command("vali_dispatch_launch", **argv)
    except SystemExit as exc:
        code = int(exc.code or 0)
    lines = [line for line in capsys.readouterr().out.splitlines() if line.startswith("{")]
    return code, json.loads(lines[-1]) if lines else {}


@pytest.mark.django_db(transaction=True)
def test_dispatch_registers_an_active_vm_matching_its_ticket(monkeypatch, tmp_path, capsys) -> None:
    argv, calls = _dispatch_env(monkeypatch, tmp_path)
    _vm()
    _code, emit = _run_dispatch(argv, capsys)
    assert calls == [True], emit


def test_dispatch_refuses_a_ticket_with_no_vm_row(monkeypatch, tmp_path, capsys) -> None:
    argv, calls = _dispatch_env(monkeypatch, tmp_path)
    Vm.objects.filter(vm_id="vm-launch-1").delete()
    code, emit = _run_dispatch(argv, capsys)
    assert code != 0 and emit["outcome"] == "kbs-admin-vm-state-refused"
    assert calls == []


@pytest.mark.parametrize("state", [VmState.DECOMMISSIONING, VmState.DESTROYED, VmState.MIGRATING])
def test_dispatch_refuses_a_vm_that_is_not_active(monkeypatch, tmp_path, capsys, state) -> None:
    argv, calls = _dispatch_env(monkeypatch, tmp_path)
    extra = {"migration_dest": "miner-b", "new_generation": 2} if state == VmState.MIGRATING else {}
    _vm(state=state, **extra)
    code, emit = _run_dispatch(argv, capsys)
    assert code != 0 and emit["outcome"] == "kbs-admin-vm-state-refused"
    assert calls == []


def test_dispatch_refuses_a_ticket_for_another_generation(monkeypatch, tmp_path, capsys) -> None:
    argv, calls = _dispatch_env(monkeypatch, tmp_path, gen=2)
    _vm(generation=1)
    code, emit = _run_dispatch(argv, capsys)
    assert code != 0 and emit["outcome"] == "kbs-admin-vm-state-refused"
    assert calls == []


def test_dispatch_refuses_a_ticket_naming_another_vm(monkeypatch, tmp_path, capsys) -> None:
    argv, calls = _dispatch_env(monkeypatch, tmp_path, ticket_vm="vm-other")
    _vm()
    code, emit = _run_dispatch(argv, capsys)
    assert code != 0 and emit["outcome"] == "ticket-mismatch"
    assert calls == []


def test_dispatch_refuses_a_ticket_for_another_chip(monkeypatch, tmp_path, capsys) -> None:
    argv, calls = _dispatch_env(monkeypatch, tmp_path, platform="ff" * 8)
    _vm()
    code, emit = _run_dispatch(argv, capsys)
    assert code != 0 and emit["outcome"] == "ticket-mismatch"
    assert calls == []


def test_dispatch_refuses_a_vm_bound_to_another_host(monkeypatch, tmp_path, capsys) -> None:
    argv, calls = _dispatch_env(monkeypatch, tmp_path)
    _vm(host="miner-i")
    code, emit = _run_dispatch(argv, capsys)
    assert code != 0 and emit["outcome"] == "kbs-admin-vm-state-refused"
    assert calls == []


# ── follow-up: bound-miner resolution, early refusal, rollback, stamps ──


def _succeeded_launch_job(vm_id: str, miner_id: str) -> None:
    import secrets

    from django.utils import timezone

    from apps.identity.models import PrincipalScope, ServiceClient
    from apps.orchestration.models import LaunchJob

    LaunchJob.objects.create(
        job_id=secrets.token_hex(8),
        vm_id=vm_id,
        tenant_id="t-launch",
        flavor="small",
        spec_json={"vm_id": vm_id},
        userdata_vault_path="x",
        userdata_vault_version=1,
        kek_vault_path="x",
        state="succeeded",
        miner_id=miner_id,
        phase_started_at=timezone.now(),
        finished_at=timezone.now(),
        decided_by=ServiceClient.objects.create(scope=PrincipalScope.OPERATOR.value, name="t"),
    )


def test_a_legacy_row_bound_only_through_its_launch_job_is_bound() -> None:
    # host "" but a SUCCEEDED LaunchJob placed it on miner X: that IS its
    # binding (`effects._bound_miner_id`), not "unbound".
    vm = _vm(host="")
    _succeeded_launch_job("vm-launch-1", "miner-x")
    assert "bound to host 'miner-x'" in register_gate.register_refusal(
        vm, generation=1, miner_id="miner-y"
    )
    assert register_gate.register_refusal(vm, generation=1, miner_id="miner-x") is None


def test_a_launch_onto_another_miner_than_the_legacy_binding_is_refused_before_vault(
    monkeypatch,
) -> None:
    from apps.orchestration.services import vault_kv

    miner = _register_miner(1)
    _fake_the_launch_choreography(monkeypatch, dispatch_ok=True)
    calls = _count_register(monkeypatch)
    puts: list[str] = []
    monkeypatch.setattr(vault_kv, "put_kv", lambda mount, path, value, **kw: puts.append(path))
    _vm(host="")
    _succeeded_launch_job("vm-launch-1", "miner-x")
    out = launch.launch_on_miner(_spec(userdata=UD), miner)
    assert out.emit["outcome"] == "kbs-admin-vm-state-refused"
    assert calls == [] and puts == []


def test_reboot_recovery_of_a_migrated_vm_is_refused_before_any_vault_or_bake_work(
    monkeypatch,
) -> None:
    from apps.orchestration.services import preflight as preflight_svc
    from apps.orchestration.services import vault_kv

    miner = _register_miner(1)
    _fake_the_launch_choreography(monkeypatch, dispatch_ok=True)
    calls = _count_register(monkeypatch)
    touched: list[str] = []
    monkeypatch.setattr(vault_kv, "put_kv", lambda *a, **k: touched.append("vault"))
    monkeypatch.setattr(vault_kv, "ensure_transit_key", lambda *a, **k: touched.append("transit"))
    monkeypatch.setattr(
        preflight_svc, "dispatch_preflight", lambda *a, **k: touched.append("preflight")
    )
    # §25-migrated: generation 2, bound to this very miner.
    _vm(host="miner-a", generation=2)
    out = launch.launch_on_miner(_spec(userdata=UD), miner)
    assert out.disposition == launch.TERMINAL
    assert out.emit["outcome"] == "kbs-admin-vm-state-refused"
    assert "generation 2" in out.emit["error"]
    assert touched == [] and calls == []
    assert out.registered is False


@pytest.mark.django_db(transaction=True)
def test_a_register_that_times_out_inside_the_gate_rolls_back_and_is_not_registered(
    monkeypatch,
) -> None:
    from apps.orchestration.effects import EffectUnavailable

    miner = _register_miner(1)
    _fake_the_launch_choreography(monkeypatch, dispatch_ok=True)

    def _timeout(*a, **k):
        # A write made in the gate's transaction before the failure…
        Vm.objects.filter(vm_id="vm-launch-1").update(lease_id="written-in-the-gate")
        raise EffectUnavailable("kbs admin: timed out")

    monkeypatch.setattr(launch.kbs_admin, "register_vm_active_with_vm_id", _timeout)
    _vm(host="")
    out = launch.launch_on_miner(_spec(userdata=UD), miner)
    assert out.disposition == launch.TERMINAL
    assert out.emit["outcome"] == "kbs-admin-unavailable"
    assert out.registered is False
    row = Vm.objects.get(vm_id="vm-launch-1")
    # …is rolled back with it, and the row is left unbound.
    assert row.lease_id == "lease-1" and row.host == ""


def test_a_named_miner_launch_onto_a_vm_bound_elsewhere_is_refused(monkeypatch) -> None:
    miner = _register_miner(1)
    _fake_the_launch_choreography(monkeypatch, dispatch_ok=True)
    calls = _count_register(monkeypatch)
    _vm(host="miner-i")
    out = launch.launch_on_named_miner(
        _spec(userdata=UD), miner, decided_by=launch.resolve_forced_launch_principal()
    )
    assert out.emit["outcome"] == "kbs-admin-vm-state-refused"
    assert "miner-i" in out.emit["error"]
    assert calls == []


def test_the_host_stamp_never_lands_on_a_row_that_left_active(monkeypatch) -> None:
    # The `apps` logger does not propagate (settings), so capture directly.
    warnings: list[str] = []
    monkeypatch.setattr(launch.log, "warning", lambda msg, *a: warnings.append(msg % a))
    _vm(host="", state=VmState.DECOMMISSIONING)
    launch._bind_vm_host("vm-launch-1", "miner-a")
    assert Vm.objects.get(vm_id="vm-launch-1").host == ""
    assert any("not stamping host=miner-a" in w for w in warnings)


def test_the_host_stamp_still_lands_on_an_active_unbound_row() -> None:
    _vm(host="")
    launch._bind_vm_host("vm-launch-1", "miner-a")
    assert Vm.objects.get(vm_id="vm-launch-1").host == "miner-a"


def test_dispatch_reports_an_unavailable_validator_as_its_own_outcome(
    monkeypatch, tmp_path, capsys
) -> None:
    from apps.orders import validator

    argv, calls = _dispatch_env(monkeypatch, tmp_path)

    def _down(_b):
        raise validator.ValidatorUnavailable("binary not found")

    monkeypatch.setattr(validator, "validate_ticket", _down)
    _vm()
    code, emit = _run_dispatch(argv, capsys)
    assert code != 0 and emit["outcome"] == "ticket-validator-unavailable"
    assert calls == []


def test_dispatch_reports_a_rejected_ticket_as_invalid(monkeypatch, tmp_path, capsys) -> None:
    from apps.orders import validator

    argv, calls = _dispatch_env(monkeypatch, tmp_path)

    def _bad(_b):
        raise validator.ValidatorFailed("bad signature", "signature")

    monkeypatch.setattr(validator, "validate_ticket", _bad)
    _vm()
    code, emit = _run_dispatch(argv, capsys)
    assert code != 0 and emit["outcome"] == "ticket-invalid"
    assert calls == []
