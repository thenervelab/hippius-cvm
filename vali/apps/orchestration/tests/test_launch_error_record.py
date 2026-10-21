"""The launch path records the miner's answer in its launch-error ledger
(`apps.miners.launch_errors`) — and changes nothing else.

Drives the REAL `launch_on_miner` (collaborator stubs from
`test_launch_service`), because a unit test of the ledger cannot catch it
never being written."""

from __future__ import annotations

import pytest

from apps.miners.models import MinerLaunchErrors
from apps.orchestration import order_dispatch
from apps.orchestration.services import launch
from apps.orchestration.services import preflight as preflight_svc

from .test_launch_service import (  # isort: skip
    _fake_the_launch_choreography,
    _register_miner,
    _spec,
)

pytestmark = pytest.mark.django_db

_USERDATA = b"#cloud-config\n# {{NETBIRD_SETUP_KEY}}\n"


def _answer(monkeypatch, result: order_dispatch.DispatchResult) -> None:
    monkeypatch.setattr(order_dispatch, "dispatch_order", lambda *a, **k: result)


def test_a_rejected_launch_records_the_reason_and_carries_it_in_the_emit(
    monkeypatch, caplog
) -> None:
    miner = _register_miner(1)
    _fake_the_launch_choreography(monkeypatch, dispatch_ok=False)
    _answer(
        monkeypatch,
        order_dispatch.DispatchResult(
            ok=False, status=500, classifier="dispatch-failed", reason="libvirt-driver/define"
        ),
    )

    # `apps` does not propagate to the root logger caplog listens on.
    monkeypatch.setattr(launch.log, "handlers", [caplog.handler])
    out = launch.launch_on_miner(_spec(userdata=_USERDATA), miner)

    assert out.disposition == launch.RETRIABLE
    err = out.emit["miner_error"]
    assert err["code"] == "libvirt-driver/define"
    assert err["class"] == "dispatch-failed"
    assert (err["stage"], err["http_status"]) == ("launch", 500)
    assert err["order_id"] == out.emit["order_id"]
    row = MinerLaunchErrors.objects.get(miner=miner)
    assert row.fail_streak == 1
    assert row.errors[0]["code"] == "libvirt-driver/define"
    assert "code=libvirt-driver/define" in caplog.text


def test_an_accepted_launch_resets_the_streak(monkeypatch) -> None:
    miner = _register_miner(1)
    _fake_the_launch_choreography(monkeypatch, dispatch_ok=False)
    launch.launch_on_miner(_spec(userdata=_USERDATA), miner)
    _fake_the_launch_choreography(monkeypatch, dispatch_ok=True)

    out = launch.launch_on_miner(_spec(userdata=_USERDATA), miner)

    assert out.disposition == launch.ACCEPTED
    assert "miner_error" not in out.emit
    row = MinerLaunchErrors.objects.get(miner=miner)
    assert row.fail_streak == 0
    assert len(row.errors) == 1


def test_an_order_in_flight_is_not_a_refusal(monkeypatch) -> None:
    miner = _register_miner(1)
    _fake_the_launch_choreography(monkeypatch, dispatch_ok=False)
    _answer(
        monkeypatch,
        order_dispatch.DispatchResult(ok=False, status=409, classifier="order-in-flight"),
    )

    out = launch.launch_on_miner(_spec(userdata=_USERDATA), miner)

    assert "miner_error" not in out.emit
    assert not MinerLaunchErrors.objects.filter(miner=miner).exists()


def test_miner_bytes_are_sanitized_and_bounded(monkeypatch) -> None:
    miner = _register_miner(1)
    _fake_the_launch_choreography(monkeypatch, dispatch_ok=False)
    junk = "Error: /var/lib/hippius-miner/secret.key " + "A" * 5000
    _answer(
        monkeypatch,
        order_dispatch.DispatchResult(ok=False, status=500, classifier=junk, reason=junk),
    )

    out = launch.launch_on_miner(_spec(userdata=_USERDATA), miner)

    assert out.emit["miner_error"]["code"] == "invalid"
    assert out.emit["miner_error"]["class"] == "invalid"
    assert len(out.emit["classifier"]) <= 128
    assert out.emit["classifier"].isprintable()
    stored = MinerLaunchErrors.objects.get(miner=miner).errors[0]
    assert "secret" not in repr(stored)


def test_a_preflight_rejection_is_recorded_with_its_own_order(monkeypatch) -> None:
    miner = _register_miner(1)
    _fake_the_launch_choreography(monkeypatch, dispatch_ok=True)

    def _refuse(*a, **k):
        raise preflight_svc.PreflightRejected(
            "preflight-dispatch: miner-rejected",
            classifier="dispatch-failed",
            status=500,
            reason="tenant-preflight/ovmf-missing",
        )

    monkeypatch.setattr(preflight_svc, "dispatch_preflight", _refuse)

    out = launch.launch_on_miner(_spec(userdata=_USERDATA), miner)

    assert out.disposition == launch.RETRIABLE
    err = out.emit["miner_error"]
    assert (err["stage"], err["code"]) == ("preflight", "tenant-preflight/ovmf-missing")
    assert err["order_id"].startswith("ord-preflight-")
    assert MinerLaunchErrors.objects.get(miner=miner).fail_streak == 1


def test_a_vali_side_preflight_fault_is_not_recorded(monkeypatch) -> None:
    from apps.orchestration.effects import EffectUnavailable

    miner = _register_miner(1)
    _fake_the_launch_choreography(monkeypatch, dispatch_ok=True)

    def _down(*a, **k):
        raise EffectUnavailable("edge-order: peer unreachable")

    monkeypatch.setattr(preflight_svc, "dispatch_preflight", _down)

    out = launch.launch_on_miner(_spec(userdata=_USERDATA), miner)

    assert "miner_error" not in out.emit
    assert not MinerLaunchErrors.objects.filter(miner=miner).exists()


def test_the_ledger_changes_no_launch_outcome(monkeypatch) -> None:
    """The same rejection with the ledger write broken: same disposition,
    same exit code."""
    miner = _register_miner(1)
    _fake_the_launch_choreography(monkeypatch, dispatch_ok=False)
    baseline = launch.launch_on_miner(_spec(userdata=_USERDATA), miner)

    def _boom(*a, **k):
        raise RuntimeError("db down")

    monkeypatch.setattr(MinerLaunchErrors.objects, "select_for_update", _boom)
    _fake_the_launch_choreography(monkeypatch, dispatch_ok=False)
    out = launch.launch_on_miner(_spec(userdata=_USERDATA), miner)

    assert (out.disposition, out.exit_code, out.registered) == (
        baseline.disposition,
        baseline.exit_code,
        baseline.registered,
    )
