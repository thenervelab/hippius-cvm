"""The KBS fence client (`effects.kbs_fence_decommission` / `kbs_tombstone`)
and `vali_kbs_recover --reinstall-tombstones`.

Client claims: the exact route + body; a 404 is `KbsRouteMissing` (and an
invalid vm_id never reaches the network, so a 404 cannot mean "bad path"); a
tombstone 409 is the non-retried `KbsTombstoneConflict`; a 200 that does not
report the fenced state is NOT a fence.

Command claims: dry-run is the default and writes nothing; a commit needs
`--yes`; decommissioning ⇒ fence, destroyed ⇒ tombstone at the VM's
generation; a live VM is refused; a KBS without the routes aborts the run;
a generation conflict is a warning, not a failure.
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from django.core.management import CommandError, call_command

from apps.lifecycle.models import VmState
from apps.orchestration import effects, service

from .conftest import FakeEffects
from .factories import make_vm

pytestmark = pytest.mark.django_db


@pytest.fixture(autouse=True)
def _fresh_kbs_call_budget() -> None:
    service._reset_kbs_fence_budget()

COMMAND = "vali_kbs_recover"


# ─── the client ──────────────────────────────────────────────────────


@pytest.fixture
def http(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    state: dict[str, Any] = {"status": 200, "body": b"", "calls": []}

    def fake_http(method: str, url: str, *, label: str, json_body: Any = None, **_: Any):
        state["calls"].append({"method": method, "url": url, "json": json_body})
        return state["status"], state["body"]

    monkeypatch.setattr(effects, "_http", fake_http)
    return state


def _body(state: str, previous: str = "active", cached: bool = False) -> bytes:
    return json.dumps(
        {"v": 1, "vm_id": "vm-a", "previous": previous, "state": state, "cached": cached}
    ).encode()


def test_decommission_posts_v1_to_the_admin_route(http: dict[str, Any], fx: FakeEffects) -> None:
    http["body"] = _body("decommissioning")
    res = fx.real["kbs_fence_decommission"]("vm-a")
    assert res == effects.KbsFenceOk(previous="active", state="decommissioning", cached=False)
    assert http["calls"] == [
        {"method": "POST", "url": "http://kbs.test/v1/admin/vm/vm-a/decommission", "json": {"v": 1}}
    ]


def test_decommission_of_an_already_destroyed_row_is_a_fence(
    http: dict[str, Any], fx: FakeEffects
) -> None:
    http["body"] = _body("destroyed", previous="destroyed", cached=True)
    assert fx.real["kbs_fence_decommission"]("vm-a").cached is True


def test_tombstone_posts_the_generation(http: dict[str, Any], fx: FakeEffects) -> None:
    http["body"] = _body("destroyed", previous="decommissioning")
    fx.real["kbs_tombstone"]("vm-a", generation=9)
    assert http["calls"][0]["url"] == "http://kbs.test/v1/admin/vm/vm-a/tombstone"
    assert http["calls"][0]["json"] == {"v": 1, "gen": 9}


def test_a_200_that_does_not_report_the_fenced_state_is_not_a_fence(
    http: dict[str, Any], fx: FakeEffects
) -> None:
    http["body"] = _body("active")
    with pytest.raises(effects.EffectError):
        fx.real["kbs_fence_decommission"]("vm-a")
    http["body"] = _body("decommissioning")
    with pytest.raises(effects.EffectError):
        fx.real["kbs_tombstone"]("vm-a", generation=1)


def test_a_404_is_route_missing(http: dict[str, Any], fx: FakeEffects) -> None:
    http["status"] = 404
    with pytest.raises(effects.KbsRouteMissing):
        fx.real["kbs_fence_decommission"]("vm-a")
    with pytest.raises(effects.KbsRouteMissing):
        fx.real["kbs_tombstone"]("vm-a", generation=1)


def test_a_tombstone_409_is_the_non_retried_conflict(http: dict[str, Any], fx: FakeEffects) -> None:
    http["status"] = 409
    http["body"] = b"\xa1\x66reason\x78\x1dtombstone-generation-conflict"
    with pytest.raises(effects.KbsTombstoneConflict):
        fx.real["kbs_tombstone"]("vm-a", generation=1)


def test_a_decommission_409_is_an_ordinary_retryable_error(
    http: dict[str, Any], fx: FakeEffects
) -> None:
    http["status"] = 409
    with pytest.raises(effects.EffectError) as info:
        fx.real["kbs_fence_decommission"]("vm-a")
    assert not isinstance(info.value, effects.KbsTombstoneConflict)


@pytest.mark.parametrize("bad", ["", "VM-A", "vm/a", "a" * 65])
def test_an_invalid_vm_id_never_reaches_the_network(
    http: dict[str, Any], fx: FakeEffects, bad: str
) -> None:
    with pytest.raises(effects.EffectError):
        fx.real["kbs_fence_decommission"](bad)
    assert http["calls"] == []


@pytest.mark.parametrize("gen", [0, -1, True])
def test_an_invalid_generation_never_reaches_the_network(
    http: dict[str, Any], fx: FakeEffects, gen: Any
) -> None:
    with pytest.raises(effects.EffectError):
        fx.real["kbs_tombstone"]("vm-a", generation=gen)
    assert http["calls"] == []


# ─── vali_kbs_recover --reinstall-tombstones ─────────────────────────


def _dead_fleet() -> None:
    make_vm("vm-live", state=VmState.ACTIVE, generation=2)
    make_vm("vm-dec", state=VmState.DECOMMISSIONING, generation=3)
    make_vm("vm-dead", state=VmState.DESTROYED, generation=4)


def _kbs_calls(fx: FakeEffects) -> list[tuple]:
    return [c for c in fx.calls if c[0].startswith("kbs_")]


def test_reinstall_dry_run_is_the_default_and_writes_nothing(fx: FakeEffects, capsys: Any) -> None:
    _dead_fleet()
    call_command(COMMAND, "--reinstall-tombstones")
    assert _kbs_calls(fx) == []
    out = capsys.readouterr().out
    assert "vm=vm-dec op=decommission" in out
    assert "vm=vm-dead op=tombstone gen=4" in out
    assert "vm-live" not in out


def test_reinstall_commit_needs_yes(fx: FakeEffects) -> None:
    _dead_fleet()
    with pytest.raises(CommandError, match="--yes"):
        call_command(COMMAND, "--reinstall-tombstones", "--commit")
    assert _kbs_calls(fx) == []


def test_reinstall_commit_fences_and_tombstones_the_dead_only(fx: FakeEffects) -> None:
    _dead_fleet()
    call_command(COMMAND, "--reinstall-tombstones", "--commit", "--yes")
    assert sorted(_kbs_calls(fx)) == [
        ("kbs_fence_decommission", "vm-dec"),
        ("kbs_tombstone", "vm-dead", 4),
    ]


def test_reinstall_refuses_a_live_vm_by_id(fx: FakeEffects) -> None:
    _dead_fleet()
    with pytest.raises(CommandError, match="vm-live"):
        call_command(
            COMMAND, "--reinstall-tombstones", "--vm-id", "vm-live", "--commit", "--yes"
        )
    assert _kbs_calls(fx) == []


def test_reinstall_by_id_touches_only_that_vm(fx: FakeEffects) -> None:
    _dead_fleet()
    call_command(COMMAND, "--reinstall-tombstones", "--vm-id", "vm-dead", "--commit", "--yes")
    assert _kbs_calls(fx) == [("kbs_tombstone", "vm-dead", 4)]


def test_reinstall_aborts_when_the_kbs_lacks_the_routes(
    fx: FakeEffects, monkeypatch: pytest.MonkeyPatch
) -> None:
    _dead_fleet()

    def missing(vm_id: str) -> Any:
        raise effects.KbsRouteMissing("404")

    monkeypatch.setattr(effects, "kbs_fence_decommission", missing)
    with pytest.raises(CommandError, match="ABORTING"):
        call_command(COMMAND, "--reinstall-tombstones", "--commit", "--yes")


def test_reinstall_conflict_is_a_warning_not_a_failure(fx: FakeEffects, capsys: Any) -> None:
    _dead_fleet()
    fx.tombstone_conflict = True
    call_command(COMMAND, "--reinstall-tombstones", "--commit", "--yes")  # no SystemExit
    out = capsys.readouterr().out
    assert "outcome=tombstone-conflict" in out
    assert "ok=1 warned=1 failed=0" in out


def test_reinstall_other_failure_exits_non_zero(fx: FakeEffects) -> None:
    _dead_fleet()
    fx.fail.add("kbs_tombstone")
    with pytest.raises(SystemExit) as info:
        call_command(COMMAND, "--reinstall-tombstones", "--commit", "--yes")
    assert info.value.code == 1
    # One VM's failure does not stop the next.
    assert ("kbs_fence_decommission", "vm-dec") in _kbs_calls(fx)


@pytest.mark.parametrize(
    "extra", [["--all-active"], ["--boot-counter", "3"], ["--counter-source", "m1"]]
)
def test_reinstall_refuses_the_recovery_only_flags(fx: FakeEffects, extra: list[str]) -> None:
    _dead_fleet()
    with pytest.raises(CommandError):
        call_command(COMMAND, "--reinstall-tombstones", *extra)
    assert _kbs_calls(fx) == []


def test_reinstall_works_with_the_fence_flag_off(
    fx: FakeEffects, monkeypatch: pytest.MonkeyPatch
) -> None:
    from django.conf import settings

    monkeypatch.setattr(settings, "VALI_KBS_FENCE_ENABLED", False)
    _dead_fleet()
    call_command(COMMAND, "--reinstall-tombstones", "--commit", "--yes")
    assert len(_kbs_calls(fx)) == 2


def test_reinstall_rereads_a_vm_that_was_destroyed_after_the_plan(
    fx: FakeEffects, monkeypatch: pytest.MonkeyPatch
) -> None:
    from apps.lifecycle.models import Vm
    from apps.orchestration.management.commands import vali_kbs_recover

    _dead_fleet()
    original = vali_kbs_recover.Command._select_dead_vms

    def select_then_destroy(self: Any, vm_ids: list[str]) -> list[Any]:
        vms = original(self, vm_ids)
        # The teardown of vm-dec finishes while the plan is being printed.
        Vm.objects.filter(vm_id="vm-dec").update(state=VmState.DESTROYED)
        return vms

    monkeypatch.setattr(vali_kbs_recover.Command, "_select_dead_vms", select_then_destroy)
    call_command(COMMAND, "--reinstall-tombstones", "--commit", "--yes")
    assert ("kbs_tombstone", "vm-dec", 3) in _kbs_calls(fx)
    assert ("kbs_fence_decommission", "vm-dec") not in _kbs_calls(fx)


def test_reinstall_follows_a_fence_with_the_tombstone_if_destroyed_meanwhile(
    fx: FakeEffects, monkeypatch: pytest.MonkeyPatch
) -> None:
    from apps.lifecycle.models import Vm

    _dead_fleet()

    def fence_then_destroyed(vm_id: str) -> Any:
        fx.calls.append(("kbs_fence_decommission", vm_id))
        Vm.objects.filter(vm_id=vm_id).update(state=VmState.DESTROYED)
        return effects.KbsFenceOk(previous="active", state="decommissioning", cached=False)

    monkeypatch.setattr(effects, "kbs_fence_decommission", fence_then_destroyed)
    call_command(COMMAND, "--reinstall-tombstones", "--vm-id", "vm-dec", "--commit", "--yes")
    assert _kbs_calls(fx) == [("kbs_fence_decommission", "vm-dec"), ("kbs_tombstone", "vm-dec", 3)]


def test_reinstall_rides_out_the_kbs_admin_rate_limit(
    fx: FakeEffects, monkeypatch: pytest.MonkeyPatch
) -> None:
    # 2026-09-25: 400 of 440 tombstones came back 429 in one run. The run
    # itself must retry them, not report them failed.
    import time

    make_vm("vm-dead", state=VmState.DESTROYED, generation=4)
    answers: list[Any] = [effects.EffectError("kbs-admin:tombstone: KBS returned HTTP 429")]
    real = fx.kbs_tombstone

    def flaky(vm_id: str, *, generation: int) -> Any:
        if answers:
            raise answers.pop(0)
        return real(vm_id, generation=generation)

    monkeypatch.setattr(effects, "kbs_tombstone", flaky)
    monkeypatch.setattr(time, "sleep", lambda _s: None)
    call_command(COMMAND, "--reinstall-tombstones", "--commit", "--yes")
    assert _kbs_calls(fx) == [("kbs_tombstone", "vm-dead", 4)]
