"""`dispatch_order_settled` — a miner order whose answer was LOST (Edge
502/504, or the miner still running it: 409 ``order-in-flight``) is re-asked
with the SAME ``order_id`` until the miner's recorded outcome comes back.

Live case: a §24 EoL graceful stop outlasted the Edge's 30 s forward, vali
read the 502 as a failure and took the ack-timeout forced-reclaim path,
while libvirt had destroyed the domain one second after the 502.
"""

from __future__ import annotations

from typing import Any

import pytest

from apps.lifecycle.models import Vm, VmState
from apps.miners.models import MinerIdentity
from apps.orchestration import effects, order_dispatch
from apps.orchestration.order_dispatch import (
    DispatchResult,
    OrderDispatchUnavailable,
    dispatch_order_settled,
)

# The autouse `fx` fixture shadows `effects.dispatch_graceful_stop` with a
# fake — keep the REAL body so the effect-level test exercises it.
_REAL_GRACEFUL_STOP = effects.dispatch_graceful_stop
_REAL_DESTROY = effects.dispatch_destroy
_REAL_SOURCE_RECLAIM = effects.dispatch_source_reclaim


def _r(status: int, classifier: str = "") -> DispatchResult:
    return DispatchResult(ok=200 <= status < 300, status=status, classifier=classifier)


class _Script:
    """A scripted `dispatch_order`: each call pops the next answer (a
    `DispatchResult` to return, or an exception to raise) and records the
    kwargs it was called with."""

    def __init__(self, *answers: DispatchResult | Exception) -> None:
        self.answers = list(answers)
        self.calls: list[dict[str, Any]] = []

    def __call__(self, **kwargs: Any) -> DispatchResult:
        self.calls.append(kwargs)
        answer = self.answers.pop(0)
        if isinstance(answer, Exception):
            raise answer
        return answer


def _settle(
    monkeypatch: pytest.MonkeyPatch, script: _Script, attempts: int = 4
) -> tuple[DispatchResult, list[float]]:
    monkeypatch.setattr(order_dispatch, "dispatch_order", script)
    sleeps: list[float] = []
    result = dispatch_order_settled(
        miner_id="miner-a",
        netbird_ip="100.64.0.9",
        order_id="dec-eol-stop-vm-1-1",
        kind="stop",
        payload_json=b"{}",
        attempts=attempts,
        retry_after_s=7.0,
        sleep=sleeps.append,
    )
    return result, sleeps


def test_a_lost_answer_is_re_asked_and_the_recorded_success_returned(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    script = _Script(_r(502), _r(200, "idempotent-replay"))
    result, sleeps = _settle(monkeypatch, script)
    assert result.ok and result.classifier == "idempotent-replay"
    assert sleeps == [7.0]
    # The SAME order_id every time — that is what makes the re-ask safe.
    assert {c["order_id"] for c in script.calls} == {"dec-eol-stop-vm-1-1"}


def test_an_order_still_in_flight_is_waited_out(monkeypatch: pytest.MonkeyPatch) -> None:
    script = _Script(_r(504), _r(409, "order-in-flight"), _r(200, "idempotent-replay"))
    result, sleeps = _settle(monkeypatch, script)
    assert result.ok
    assert len(script.calls) == 3 and sleeps == [7.0, 7.0]


@pytest.mark.parametrize(
    ("status", "classifier"),
    [
        (200, "stopped"),
        (400, "bad-signature"),
        (409, "order-id-collision"),  # a 409 that is NOT "still running"
        (500, "lifecycle-error"),
    ],
)
def test_a_known_answer_is_returned_at_once(
    monkeypatch: pytest.MonkeyPatch, status: int, classifier: str
) -> None:
    script = _Script(_r(status, classifier))
    result, sleeps = _settle(monkeypatch, script)
    assert (result.status, result.classifier) == (status, classifier)
    assert len(script.calls) == 1 and sleeps == []


def test_an_answer_still_unknown_after_the_last_attempt_is_returned(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    script = _Script(_r(502), _r(502), _r(502))
    result, sleeps = _settle(monkeypatch, script, attempts=3)
    assert result.status == 502 and not result.ok
    assert len(script.calls) == 3 and sleeps == [7.0, 7.0]


def test_an_unreachable_edge_is_re_asked_then_raises_on_the_last_attempt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    script = _Script(OrderDispatchUnavailable("edge down"), _r(200, "idempotent-replay"))
    result, _ = _settle(monkeypatch, script)
    assert result.ok

    script = _Script(*[OrderDispatchUnavailable("edge down")] * 2)
    with pytest.raises(OrderDispatchUnavailable):
        _settle(monkeypatch, script, attempts=2)
    assert len(script.calls) == 2


class _Clock:
    """Monotonic clock the scripted dispatch and the pauses advance."""

    def __init__(self) -> None:
        self.t = 0.0

    def __call__(self) -> float:
        return self.t


def test_the_deadline_bounds_the_whole_exchange(monkeypatch: pytest.MonkeyPatch) -> None:
    """Under a request's worker timeout the re-asks must stop in time: each
    attempt's HTTP timeout is clipped to what is left, and no re-ask starts
    that could not finish."""
    clock = _Clock()
    timeouts: list[float] = []

    def _dispatch(**kw: Any) -> DispatchResult:
        timeouts.append(kw["timeout_s"])
        clock.t += min(30.0, kw["timeout_s"])  # the Edge's 30 s forward, or less
        return _r(502)

    def _pause(s: float) -> None:
        clock.t += s

    monkeypatch.setattr(order_dispatch, "dispatch_order", _dispatch)
    result = dispatch_order_settled(
        miner_id="miner-a",
        netbird_ip="100.64.0.9",
        order_id="pwr-stop-vm-1-abc",
        kind="stop",
        payload_json=b"{}",
        deadline_s=50.0,
        sleep=_pause,
        clock=clock,
    )
    assert result.status == 502
    assert clock.t <= 50.0, f"exchange ran {clock.t} s past a 50 s deadline"
    assert timeouts[0] == 45.0 and timeouts[1] == pytest.approx(10.0)
    assert len(timeouts) == 2


def test_production_defaults() -> None:
    """Pinned so a tweak is a visible decision: 4 attempts, 10 s apart."""
    import inspect

    params = inspect.signature(dispatch_order_settled).parameters
    assert params["attempts"].default == 4
    assert params["retry_after_s"].default == 10.0
    assert effects.EOL_STOP_DEADLINE_S == 120.0


@pytest.mark.parametrize("deadline", [0.0, -5.0])
def test_a_spent_deadline_is_a_caller_bug(deadline: float) -> None:
    with pytest.raises(ValueError):
        dispatch_order_settled(
            miner_id="m",
            netbird_ip="100.64.0.9",
            order_id="o",
            kind="stop",
            payload_json=b"{}",
            deadline_s=deadline,
        )


def test_attempts_below_one_is_a_caller_bug() -> None:
    with pytest.raises(ValueError):
        dispatch_order_settled(
            miner_id="m",
            netbird_ip="100.64.0.9",
            order_id="o",
            kind="stop",
            payload_json=b"{}",
            attempts=0,
        )


@pytest.mark.django_db
def test_a_graceful_stop_whose_502_hid_a_success_does_not_raise(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The §24 / power-stop effect: the Edge's 502 must not become a
    recorded failure when the miner in fact completed the stop."""
    MinerIdentity.objects.create(
        miner_id="miner-a",
        pubkey_hex="ab" * 32,
        platform_id="plat-1",
        netbird_ip="100.64.0.9",
    )
    vm = Vm.objects.create(
        vm_id="vm-stop",
        lease_id="lease-vm-stop",
        state=VmState.DECOMMISSIONING,
        generation=1,
        host="miner-a",
        lifecycle_vk=bytes(32),
        eol_nonce=bytes(range(32)),
    )
    script = _Script(_r(502), _r(200, "idempotent-replay"))
    monkeypatch.setattr(order_dispatch, "dispatch_order", script)
    monkeypatch.setattr(order_dispatch.time, "sleep", lambda _s: None)
    _REAL_GRACEFUL_STOP(vm)  # must not raise
    assert [c["kind"] for c in script.calls] == ["stop", "stop"]
    # §24 stops a generation once — its id stays per-generation.
    assert {c["order_id"] for c in script.calls} == {"dec-eol-stop-vm-stop-1"}


def _miner_and_vm(vm_id: str, host: str = "miner-a") -> Vm:
    MinerIdentity.objects.get_or_create(
        miner_id=host,
        defaults={"pubkey_hex": "ab" * 32, "platform_id": "plat-1", "netbird_ip": "100.64.0.9"},
    )
    return Vm.objects.create(
        vm_id=vm_id,
        lease_id=f"lease-{vm_id}",
        state=VmState.DECOMMISSIONING,
        generation=1,
        host=host,
        lifecycle_vk=bytes(32),
        eol_nonce=bytes(range(32)),
    )


@pytest.mark.django_db
def test_a_destroy_whose_502_hid_a_success_does_not_fail(monkeypatch) -> None:
    """A destroy (force stop + multi-GB unlink) can outlast the Edge's 30 s
    forward; the re-ask reads the miner's recorded outcome instead of failing
    the step."""
    vm = _miner_and_vm("vm-destroy")
    script = _Script(_r(502), _r(200, "destroyed"))
    monkeypatch.setattr(order_dispatch, "dispatch_order", script)
    monkeypatch.setattr(order_dispatch.time, "sleep", lambda _s: None)
    _REAL_DESTROY(vm)
    assert [c["kind"] for c in script.calls] == ["destroy", "destroy"]
    assert len({c["order_id"] for c in script.calls}) == 1


@pytest.mark.django_db
def test_a_source_reclaim_whose_502_hid_a_success_does_not_fail(monkeypatch) -> None:
    vm = _miner_and_vm("vm-reclaim", host="miner-dst")
    MinerIdentity.objects.get_or_create(
        miner_id="miner-src",
        defaults={"pubkey_hex": "cd" * 32, "platform_id": "plat-2", "netbird_ip": "100.64.0.10"},
    )
    script = _Script(_r(502), _r(200, "destroyed"))
    monkeypatch.setattr(order_dispatch, "dispatch_order", script)
    monkeypatch.setattr(order_dispatch.time, "sleep", lambda _s: None)
    _REAL_SOURCE_RECLAIM(vm, source_node_id="miner-src", job_id="job-1")
    assert len(script.calls) == 2
    assert script.calls[0]["order_id"] == "mig-reclaim-vm-reclaim-job-1"


@pytest.mark.django_db
def test_a_hanging_destroy_is_bounded_for_the_tick(monkeypatch) -> None:
    """It runs inside the orchestration tick: at most one re-ask, within
    DESTROY_DEADLINE_S; a still-unknown answer fails the step (retried next
    tick) rather than blocking the tick."""
    vm = _miner_and_vm("vm-hang")
    script = _Script(_r(502), _r(502), _r(502))
    monkeypatch.setattr(order_dispatch, "dispatch_order", script)
    monkeypatch.setattr(order_dispatch.time, "sleep", lambda _s: None)
    with pytest.raises(effects.EffectError):
        _REAL_DESTROY(vm)
    assert len(script.calls) == 2
    assert all(c["timeout_s"] <= effects.DESTROY_DEADLINE_S for c in script.calls)


def test_the_destroy_budget_stays_near_the_old_one_shot_worst_case() -> None:
    """Destroy/reclaim run serially inside the tick. The budget must still
    leave room for the re-ask after the Edge's 30 s 502 (30 + 10 pause + 5
    useful), yet stay close to the old single 45 s attempt."""
    assert 30 + 10 + 5 < effects.DESTROY_DEADLINE_S <= 50

