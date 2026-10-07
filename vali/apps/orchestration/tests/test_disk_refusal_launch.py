"""A DATA-disk refusal (507 `insufficient-disk`) is a CAPACITY event.

Never evidence about SEV start capability (which hard-excludes a host),
never the CPU/RAM `start-failed` halving — it cuts the earned DISK
ceiling. At preflight it re-places; after the KBS register it cannot
(no deregister exists), so it retries the same miner and gives up.

These drive the REAL `launch_on_miner` (collaborators stubbed by
`test_launch_service`), because a unit test of a classifier cannot catch
the classifier never being consulted.
"""

from __future__ import annotations

import pytest
from django.utils import timezone

from apps.orchestration.services import launch
from apps.scheduler import capacity_earn, cvm_capability
from apps.scheduler.models import CapacityTrustClass, MinerCapacity
from apps.scheduler.tests.factories import node_id

from .test_launch_service import (  # isort: skip
    _fake_the_launch_choreography,
    _register_miner,
    _spec,
)

pytestmark = pytest.mark.django_db

_USERDATA = b"#cloud-config\n# {{NETBIRD_SETUP_KEY}}\n"


def _earned_mirror(seed: int) -> MinerCapacity:
    return MinerCapacity.objects.create(
        miner_node_id=node_id(seed),
        status="active",
        capacity_slots=4,
        observed_epoch=10,
        data_epoch=10,
        refreshed_at=timezone.now(),
        trust_class=CapacityTrustClass.EARNED,
        earned_vms=10,
        earned_vcpus=20,
        earned_memory_mb=81920,
        declared_disk_gb_budget=1000,
        disk_reported_at=timezone.now(),
    )


# ─── classification ─────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("classifier", "is_disk", "is_sev"),
    [
        ("insufficient-disk", True, False),
        ("INSUFFICIENT-DISK", True, False),
        ("data-disk/insufficient-space", True, False),
        ("insufficient-space", True, False),
        ("dispatch-failed", False, True),  # a real start failure still counts
        ("insufficient-resources", False, False),
        ("", False, True),
    ],
)
def test_disk_refusals_are_capacity_not_sev(classifier: str, is_disk: bool, is_sev: bool) -> None:
    assert cvm_capability.is_disk_refusal(classifier) is is_disk
    assert cvm_capability.is_start_capability_failure(classifier) is is_sev


def test_a_dest_activation_out_of_space_never_reached_a_boot() -> None:
    assert not cvm_capability.is_dest_activation_start_failure("migration/insufficient-space")
    assert cvm_capability.is_dest_activation_start_failure("migration/launch-failed")


@pytest.mark.parametrize(
    ("status", "classifier", "charged"),
    [
        (507, "insufficient-disk", True),
        (500, "data-disk/insufficient-space", True),
        (502, "insufficient-disk", False),  # an Edge status is never the miner's word
        (500, "dispatch-failed", False),
    ],
)
def test_only_a_miner_answered_disk_refusal_is_a_disk_event(
    status: int, classifier: str, charged: bool
) -> None:
    assert launch._launch_refusal_is_disk(status, classifier) is charged
    # …and it is never ALSO a start-failed halving.
    if charged:
        assert not launch._start_failure_is_miner_attributable(status, classifier)


# ─── preflight: re-place, disk event, no SEV record ─────────────────


def test_a_preflight_disk_refusal_re_places_and_cuts_only_the_disk_ceiling(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from apps.orchestration.services import preflight as preflight_svc

    _earned_mirror(1)
    miner = _register_miner(1)
    _fake_the_launch_choreography(monkeypatch, dispatch_ok=True)

    def _refuse(*a: object, **k: object) -> None:
        raise preflight_svc.PreflightRejected("507", classifier="insufficient-disk")

    monkeypatch.setattr(preflight_svc, "dispatch_preflight", _refuse)
    out = launch.launch_on_miner(_spec(userdata=_USERDATA), miner)

    assert out.disposition == launch.RETRIABLE  # `launch_vm` re-places
    assert out.registered is False
    row = MinerCapacity.objects.get(miner_node_id=node_id(1))
    assert row.earned_disk_gb == 500
    assert row.earned_last_reason == capacity_earn.DISK_INSUFFICIENT
    # Not the CPU/RAM "preflight-insufficient" cut, not the SEV ledger.
    assert (row.earned_vms, row.earned_vcpus, row.earned_memory_mb) == (10, 20, 81920)
    assert cvm_capability.capability_of(node_id(1)) == cvm_capability.UNKNOWN


def test_a_preflight_resources_refusal_still_takes_the_cpu_ram_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from apps.orchestration.services import preflight as preflight_svc

    seen: list[str] = []
    monkeypatch.setattr(
        capacity_earn, "record_event", lambda nid, kind, **_k: seen.append(kind) or True
    )
    _earned_mirror(1)
    miner = _register_miner(1)
    _fake_the_launch_choreography(monkeypatch, dispatch_ok=True)

    def _refuse(*a: object, **k: object) -> None:
        raise preflight_svc.PreflightRejected("503", classifier="insufficient-resources")

    monkeypatch.setattr(preflight_svc, "dispatch_preflight", _refuse)
    launch.launch_on_miner(_spec(userdata=_USERDATA), miner)
    assert seen == [capacity_earn.PREFLIGHT_INSUFFICIENT]


# ─── launch (post-register): no SEV penalty, disk event ─────────────


def _dispatch_answers(monkeypatch: pytest.MonkeyPatch, status: int, classifier: str) -> None:
    from apps.orchestration import order_dispatch

    monkeypatch.setattr(
        order_dispatch,
        "dispatch_order",
        lambda *a, **k: order_dispatch.DispatchResult(
            ok=False, status=status, classifier=classifier
        ),
    )


def test_a_launch_disk_refusal_is_not_a_sev_failure_and_cuts_the_disk_ceiling(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _earned_mirror(1)
    miner = _register_miner(1)
    _fake_the_launch_choreography(monkeypatch, dispatch_ok=False)
    _dispatch_answers(monkeypatch, 507, "insufficient-disk")

    out = launch.launch_on_miner(_spec(userdata=_USERDATA), miner)

    assert out.disposition == launch.RETRIABLE and out.registered is True
    row = MinerCapacity.objects.get(miner_node_id=node_id(1))
    assert row.cvm_fail_streak == 0
    assert cvm_capability.capability_of(node_id(1)) == cvm_capability.UNKNOWN
    assert row.earned_disk_gb == 500
    # No `start-failed` halving of CPU/RAM.
    assert (row.earned_vms, row.earned_vcpus, row.earned_memory_mb) == (10, 20, 81920)


def test_a_legacy_dispatch_failed_still_counts_as_a_start_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A legacy agent answered a disk-full launch as a bare
    `dispatch-failed`: indistinguishable from a real start failure, so it
    is still charged as one (and no disk ceiling moves)."""
    _earned_mirror(1)
    miner = _register_miner(1)
    _fake_the_launch_choreography(monkeypatch, dispatch_ok=False)
    _dispatch_answers(monkeypatch, 500, "dispatch-failed")

    launch.launch_on_miner(_spec(userdata=_USERDATA), miner)

    row = MinerCapacity.objects.get(miner_node_id=node_id(1))
    assert row.cvm_fail_streak == 1
    assert row.earned_disk_gb is None
    assert row.earned_vms == 5  # the start-failed halving


# ─── edge-mode rules not loaded (C2): re-place, never a host penalty ──


def test_a_preflight_net_policy_not_loaded_re_places_without_any_penalty(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from apps.orchestration.services import preflight as preflight_svc

    seen: list[str] = []
    monkeypatch.setattr(
        capacity_earn, "record_event", lambda nid, kind, **_k: seen.append(kind) or True
    )
    _earned_mirror(1)
    miner = _register_miner(1)
    _fake_the_launch_choreography(monkeypatch, dispatch_ok=True)

    def _refuse(*a: object, **k: object) -> None:
        raise preflight_svc.PreflightRejected("503", classifier="net-policy-not-loaded")

    monkeypatch.setattr(preflight_svc, "dispatch_preflight", _refuse)
    out = launch.launch_on_miner(_spec(userdata=_USERDATA), miner)

    assert out.disposition == launch.RETRIABLE  # `launch_vm` re-places
    assert out.registered is False
    assert seen == []
    assert cvm_capability.capability_of(node_id(1)) == cvm_capability.UNKNOWN


def test_a_launch_net_policy_not_loaded_is_not_a_start_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _earned_mirror(1)
    miner = _register_miner(1)
    _fake_the_launch_choreography(monkeypatch, dispatch_ok=False)
    _dispatch_answers(monkeypatch, 503, "net-policy-not-loaded")

    out = launch.launch_on_miner(_spec(userdata=_USERDATA), miner)

    assert out.disposition == launch.RETRIABLE
    row = MinerCapacity.objects.get(miner_node_id=node_id(1))
    assert row.cvm_fail_streak == 0
    assert (row.earned_vms, row.earned_vcpus, row.earned_memory_mb) == (10, 20, 81920)
