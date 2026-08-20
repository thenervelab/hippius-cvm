"""§23 gate (e), launch side — the OBSERVATION that feeds the ledger.

`launch_on_miner` is where vali watches a host either start a
confidential guest or refuse to. `/v1/miner/order/launch` AWAITS its
dispatch task, so a 2xx means the miner really created and started the
domain, and a non-2xx after the KBS register means the host was asked to
and could not — which is exactly the shape a wedged SEV-SNP subsystem
produces (`sev_common_kvm_init … EBUSY` → libvirt refuses the domain →
`handle_launch` errors → 5xx).

These drive the REAL `launch_on_miner` (the collaborator stubs come from
`test_launch_service`, which owns them) because a unit test of the
recorder cannot catch the recorder never being CALLED.
"""

from __future__ import annotations

from datetime import timedelta

import pytest
from django.utils import timezone

from apps.orchestration.services import launch
from apps.scheduler import chain, cvm_capability
from apps.scheduler.models import MinerCapacity
from apps.scheduler.tests.factories import make_miner, make_snapshot, node_id

from .test_launch_service import (  # isort: skip
    _fake_the_launch_choreography,
    _register_miner,
    _spec,
)

pytestmark = pytest.mark.django_db

_USERDATA = b"#cloud-config\n# {{NETBIRD_SETUP_KEY}}\n"


def _mirror(seed: int) -> MinerCapacity:
    return MinerCapacity.objects.create(
        miner_node_id=node_id(seed),
        status="active",
        capacity_slots=4,
        observed_epoch=10,
        data_epoch=10,
        refreshed_at=timezone.now(),
    )


def test_an_accepted_dispatch_records_the_host_capable(monkeypatch) -> None:
    _mirror(1)
    miner = _register_miner(1)
    _fake_the_launch_choreography(monkeypatch, dispatch_ok=True)

    out = launch.launch_on_miner(_spec(userdata=_USERDATA), miner)

    assert out.disposition == launch.ACCEPTED, out.emit
    assert cvm_capability.capability_of(node_id(1)) == cvm_capability.PROVEN


def test_a_rejected_dispatch_records_ONE_failure_and_only_degrades(
    monkeypatch,
) -> None:
    """The launch-side twin of the live §25 failure: the host was handed a
    real launch order and could not start the guest.

    One rejection de-rates it SOFTLY. Hard-excluding here would be wrong:
    the underlying EBUSY is measurably intermittent, and a host that hit
    it once will very likely accept the next launch."""
    _mirror(1)
    miner = _register_miner(1)
    _fake_the_launch_choreography(monkeypatch, dispatch_ok=False)

    out = launch.launch_on_miner(_spec(userdata=_USERDATA), miner)

    assert out.disposition == launch.RETRIABLE
    assert cvm_capability.capability_of(node_id(1)) == cvm_capability.DEGRADED
    row = MinerCapacity.objects.get(miner_node_id=node_id(1))
    assert row.cvm_fail_streak == 1
    assert row.cvm_last_fail_reason == cvm_capability.REASON_LAUNCH_REJECTED


def test_an_accepted_launch_between_failures_keeps_the_host_in_the_fleet(
    monkeypatch,
) -> None:
    """The measured live pattern, replayed: a host that hits this EBUSY
    every couple of days but starts a CVM successfully in between must
    NEVER accumulate an exclusion. Its streak resets on every success."""
    _mirror(1)
    miner = _register_miner(1)

    for _ in range(4):
        _fake_the_launch_choreography(monkeypatch, dispatch_ok=False)
        launch.launch_on_miner(_spec(userdata=_USERDATA), miner)
        assert cvm_capability.capability_of(node_id(1)) == cvm_capability.DEGRADED

        _fake_the_launch_choreography(monkeypatch, dispatch_ok=True)
        launch.launch_on_miner(_spec(userdata=_USERDATA), miner)
        assert cvm_capability.capability_of(node_id(1)) == cvm_capability.PROVEN

    assert MinerCapacity.objects.get(miner_node_id=node_id(1)).cvm_fail_streak == 0


def test_consecutive_rejected_launches_do_exclude(monkeypatch) -> None:
    """The other direction — a host rejecting every launch in a row is not
    an intermittent fault, and must stop being chosen."""
    _mirror(1)
    miner = _register_miner(1)
    _fake_the_launch_choreography(monkeypatch, dispatch_ok=False)

    for _ in range(cvm_capability.fail_threshold()):
        launch.launch_on_miner(_spec(userdata=_USERDATA), miner)

    assert cvm_capability.capability_of(node_id(1)) == cvm_capability.INCAPABLE


def test_a_preflight_failure_is_NOT_recorded_as_incapacity(monkeypatch) -> None:
    """The negative signal is deliberately high-precision: it HARD-excludes
    a host, so it may only be written from evidence about the SNP start
    itself. A preflight rejection is an artifact staging/fetch/digest
    problem — the soft circuit-breaker already routes around those, and
    treating one as "this host cannot run confidential VMs" would let a
    bad image take a healthy miner out of the fleet for an hour."""
    from apps.orchestration.effects import EffectError
    from apps.orchestration.services import preflight as preflight_svc

    _mirror(1)
    miner = _register_miner(1)
    _fake_the_launch_choreography(monkeypatch, dispatch_ok=True)

    def _boom(*a, **k):
        raise EffectError("artifact sha mismatch")

    monkeypatch.setattr(preflight_svc, "dispatch_preflight", _boom)

    out = launch.launch_on_miner(_spec(userdata=_USERDATA), miner)

    assert out.disposition == launch.RETRIABLE
    assert out.registered is False
    assert cvm_capability.capability_of(node_id(1)) == cvm_capability.UNKNOWN


def test_the_record_is_keyed_on_valis_own_bridge_not_the_miner_reply(
    monkeypatch,
) -> None:
    """A miner can only ever mark ITSELF. The node id comes from the
    operator-curated, DB-unique `MinerIdentity.chain_node_id` row vali
    dispatched to; a rival's row is untouched no matter what comes back on
    the wire. (Here the dispatch result even carries the rival's id as its
    classifier — the recorder has no way to read it.)"""
    from apps.orchestration import order_dispatch

    _mirror(1)
    _mirror(2)
    miner = _register_miner(1)
    _register_miner(2)
    _fake_the_launch_choreography(monkeypatch, dispatch_ok=False)
    monkeypatch.setattr(
        order_dispatch,
        "dispatch_order",
        lambda *a, **k: order_dispatch.DispatchResult(
            ok=False, status=500, classifier=node_id(2)
        ),
    )

    launch.launch_on_miner(_spec(userdata=_USERDATA), miner)

    assert cvm_capability.capability_of(node_id(1)) == cvm_capability.DEGRADED
    assert cvm_capability.capability_of(node_id(2)) == cvm_capability.UNKNOWN
    assert MinerCapacity.objects.get(miner_node_id=node_id(2)).cvm_fail_streak == 0


def _two_miner_fleet(monkeypatch, *, failing: str) -> list[str]:
    """Wire a two-miner fleet where `failing` rejects every launch, and
    return the mutable list of dispatched node_ids."""
    _mirror(1)
    _mirror(2)
    _register_miner(1)
    _register_miner(2)
    monkeypatch.setattr(
        chain,
        "read_miner_status",
        lambda: make_snapshot(10, [make_miner(1), make_miner(2)]),
    )
    dispatched: list[str] = []

    def _fake(spec, miner):
        dispatched.append(miner.chain_node_id)
        ok = miner.chain_node_id != failing
        # Mirror what the real `launch_on_miner` records at its dispatch
        # return; `launch_on_miner` itself is stubbed out here so the test
        # can pin the SCHEDULER loop.
        if ok:
            cvm_capability.record_start_ok(miner.chain_node_id)
        else:
            cvm_capability.record_start_failure(
                miner.chain_node_id,
                reason=cvm_capability.REASON_LAUNCH_REJECTED,
            )
        return launch.LaunchOutcome(
            disposition=launch.ACCEPTED if ok else launch.RETRIABLE,
            emit={"ok": ok},
            exit_code=0 if ok else 2,
            cose_ticket=b"cose" if ok else None,
            ticket_id="tk" if ok else None,
            registered=True,
        )

    monkeypatch.setattr(launch, "launch_on_miner", _fake)
    monkeypatch.setattr(launch.time, "sleep", lambda _s: None)
    return dispatched


def _actor():
    from apps.identity.models import PrincipalScope, ServiceClient

    return ServiceClient.objects.create(
        scope=PrincipalScope.OPERATOR.value, name="launch-actor"
    )


def test_one_failure_only_de_prioritises_the_host_for_the_next_launch(
    monkeypatch,
) -> None:
    """THE SOFT HALF, end to end. Miner 1 wins every pre-existing signal
    (lower node_id, same capacity, same load). A single observed failure
    is enough to send the NEXT launch elsewhere — and NOT enough to
    remove miner 1 from the fleet: when miner 2 is full, miner 1 still
    gets the work."""
    dispatched = _two_miner_fleet(monkeypatch, failing=node_id(1))
    actor = _actor()

    cvm_capability.record_start_failure(
        node_id(1), reason=cvm_capability.REASON_LAUNCH_REJECTED
    )
    assert cvm_capability.capability_of(node_id(1)) == cvm_capability.DEGRADED

    assert launch.launch_vm(_spec(vm_id="vm-cap-a"), actor).ok is True
    assert dispatched == [node_id(2)]

    # ...and it is a PREFERENCE, not a veto: fill miner 2 to its cap and
    # the degraded host is still chosen rather than the launch failing.
    dispatched.clear()
    MinerCapacity.objects.filter(miner_node_id=node_id(2)).update(capacity_slots=1)
    result = launch.launch_vm(_spec(vm_id="vm-cap-b"), actor)
    # (It is dispatched more than once — a post-register rejection retries
    # the SAME miner. What matters is that the degraded host was CHOSEN.)
    assert set(dispatched) == {node_id(1)}, result.emit


def test_a_host_that_fails_every_attempt_is_not_chosen_by_the_next_launch(
    monkeypatch,
) -> None:
    """THE HARD HALF, end to end — the defect in one test. Miner 1 rejects
    every launch it is handed; the very next `launch_vm` must route around
    it. Before this change nothing recorded the failures at all, so miner 1
    won the next placement too, and every one after that, until a human
    noticed."""
    dispatched = _two_miner_fleet(monkeypatch, failing=node_id(1))
    actor = _actor()

    # Attempt 1 lands on miner 1. The post-register rejection retries the
    # SAME miner (a re-place would kbs-admin-conflict), so miner 2 is
    # never tried within this job — which is exactly why the exclusion has
    # to be DURABLE to help, and why one job's worth of rejections is
    # already a full streak.
    first = launch.launch_vm(_spec(vm_id="vm-cap-1"), actor)
    assert first.ok is False
    assert set(dispatched) == {node_id(1)}
    assert cvm_capability.capability_of(node_id(1)) == cvm_capability.INCAPABLE

    # Attempt 2 — a fresh launch. The observed streak now excludes it.
    dispatched.clear()
    second = launch.launch_vm(_spec(vm_id="vm-cap-2"), actor)
    assert second.ok is True
    assert dispatched == [node_id(2)]


def test_the_exclusion_does_not_expire_into_another_burned_launch(
    monkeypatch,
) -> None:
    """**2026-08-13 replayed.** The exclusion above worked, and then it
    quietly undid itself:

    ```
    12:00  synmon-cs10-…  → miner-3, 3 rejected dispatches
    12:01  ledger: streak=3 ⇒ INCAPABLE            ← the gate fired
    13:51  stamp-fed-1    → miner-3 AGAIN          ← 1 h 50 m later
    13:52  outcome=dispatch-failed-after-register  ← a second tenant
                                                     launch burned
    ```

    Nothing had observed miner-3 recover. The 1 h failure window had
    simply elapsed, the verdict fell back to UNKNOWN — i.e. to
    indistinguishable from a host nobody had ever tried — and since a host
    that starts nothing has all its capacity free, it ranked FIRST.

    Two miners were `proven` at that moment, which is what makes this a
    pure loss: the re-admission bought no availability and cost a launch.
    """
    dispatched = _two_miner_fleet(monkeypatch, failing=node_id(1))
    actor = _actor()

    # (distinct tenants, as on the day — a shared family would exclude
    # miner 2 by anti-affinity and mask what is being measured here.)
    first = launch.launch_vm(_spec(vm_id="vm-burn-1", tenant_id="t-burn-1"), actor)
    assert first.ok is False
    assert cvm_capability.capability_of(node_id(1)) == cvm_capability.INCAPABLE

    # Miner 2 takes a launch and is PROVEN — the fleet has somewhere good
    # to go, exactly as on the day.
    launch.launch_vm(_spec(vm_id="vm-burn-2", tenant_id="t-burn-2"), actor)
    assert cvm_capability.capability_of(node_id(2)) == cvm_capability.PROVEN

    # Age the failed host's evidence past the HARD window, by the real gap.
    MinerCapacity.objects.filter(miner_node_id=node_id(1)).update(
        cvm_last_fail_at=timezone.now() - timedelta(hours=1, minutes=50)
    )
    assert cvm_capability.capability_of(node_id(1)) == cvm_capability.DEGRADED

    dispatched.clear()
    third = launch.launch_vm(_spec(vm_id="vm-burn-3", tenant_id="t-burn-3"), actor)

    assert third.ok is True
    assert dispatched == [node_id(2)], "the still-unproven host was chosen again"


def test_probation_still_yields_to_a_fleet_with_nowhere_else_to_go(
    monkeypatch,
) -> None:
    """The anti-flap side of the same rule, and the reason probation is
    SOFT. A host on probation is a preference, never a veto: when it is
    the only capacity left, the launch still goes there rather than
    failing. That is also the only way a host with no other traffic can
    ever prove itself again."""
    dispatched = _two_miner_fleet(monkeypatch, failing=node_id(1))
    actor = _actor()

    launch.launch_vm(_spec(vm_id="vm-sole-1"), actor)
    MinerCapacity.objects.filter(miner_node_id=node_id(1)).update(
        cvm_last_fail_at=timezone.now() - timedelta(hours=2)
    )
    assert cvm_capability.capability_of(node_id(1)) == cvm_capability.DEGRADED

    # Take the healthy miner out of the running.
    MinerCapacity.objects.filter(miner_node_id=node_id(2)).update(capacity_slots=0)
    dispatched.clear()
    launch.launch_vm(_spec(vm_id="vm-sole-2"), actor)

    assert set(dispatched) == {node_id(1)}


# ─── which rejections count as evidence about the host ───────────────


def _reject_with(monkeypatch, classifier: str) -> None:
    """Make the dispatch return the miner's real wire shape: a non-2xx
    plus that static class."""
    from apps.orchestration import order_dispatch

    monkeypatch.setattr(
        order_dispatch,
        "dispatch_order",
        lambda *a, **k: order_dispatch.DispatchResult(
            ok=False, status=500, classifier=classifier
        ),
    )


def test_a_vm_fault_rejection_is_not_recorded_against_the_host(
    monkeypatch,
) -> None:
    """`launch-input` (422) says the ORDER was unprocessable — a bad
    digest or bad launch inputs. That is a statement about this VM, and
    this ledger HARD-excludes hosts, so it must not be written from it:
    three bad launch specs inside an hour would otherwise take a
    perfectly healthy miner out of the fleet."""
    _mirror(1)
    miner = _register_miner(1)
    _fake_the_launch_choreography(monkeypatch, dispatch_ok=False)
    _reject_with(monkeypatch, "launch-input")

    for _ in range(cvm_capability.fail_threshold() + 1):
        out = launch.launch_on_miner(_spec(userdata=_USERDATA), miner)
        assert out.disposition == launch.RETRIABLE

    assert cvm_capability.capability_of(node_id(1)) == cvm_capability.UNKNOWN
    assert MinerCapacity.objects.get(miner_node_id=node_id(1)).cvm_fail_streak == 0


@pytest.mark.parametrize(
    "classifier",
    ["insufficient-resources", "vsock-cid-exhausted", "ticket-delivery-failed"],
)
def test_the_other_excused_classes_are_not_capability_evidence(
    monkeypatch, classifier
) -> None:
    """A FULL host (capacity — #668's gate), a CID collision (the
    same-miner retry exists for it), and a ticket push that failed AFTER
    the domain reached `Running` (the host demonstrably DID start a
    confidential guest). None of the three is a SEV-start statement."""
    _mirror(1)
    miner = _register_miner(1)
    _fake_the_launch_choreography(monkeypatch, dispatch_ok=False)
    _reject_with(monkeypatch, classifier)

    launch.launch_on_miner(_spec(userdata=_USERDATA), miner)

    assert cvm_capability.capability_of(node_id(1)) == cvm_capability.UNKNOWN


def test_the_class_that_carried_the_live_failure_DOES_count(monkeypatch) -> None:
    """The other direction, pinned to the wire string the live miner
    actually returned. `dispatch-failed` is the catch-all whose detail log
    read `class=libvirt-driver/create` — `virsh start` refused the domain,
    the shape a wedged SEV-SNP subsystem produces."""
    _mirror(1)
    miner = _register_miner(1)
    _fake_the_launch_choreography(monkeypatch, dispatch_ok=False)
    _reject_with(monkeypatch, "dispatch-failed")

    launch.launch_on_miner(_spec(userdata=_USERDATA), miner)

    assert cvm_capability.capability_of(node_id(1)) == cvm_capability.DEGRADED
    row = MinerCapacity.objects.get(miner_node_id=node_id(1))
    assert row.cvm_fail_streak == 1
    # The miner's string is never persisted — the reason stays vali's own.
    assert row.cvm_last_fail_reason == cvm_capability.REASON_LAUNCH_REJECTED

