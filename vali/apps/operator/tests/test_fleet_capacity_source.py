"""`/v1/operator/fleet` — `capacity.capacity_source`, the `earned` block,
and the `no-hardware-anchor` alert under `VALI_CAPACITY_DECLARED_CEILING`."""

from __future__ import annotations

import pytest
from django.test import override_settings
from django.utils import timezone
from rest_framework.test import APIClient

from apps.scheduler import chain
from apps.scheduler.models import CapacityTrustClass, MinerCapacity
from apps.scheduler.tests.factories import make_dispatchable_identity, node_id

from .test_fleet import _fleet, _mirror, _row

pytestmark = pytest.mark.django_db


@pytest.fixture(autouse=True)
def _no_chain(monkeypatch: pytest.MonkeyPatch) -> None:
    def _down() -> chain.ChainSnapshot:
        raise chain.ChainReadUnavailable("rpc down (test)")

    monkeypatch.setattr(chain, "read_miner_status", _down)


V2 = override_settings(VALI_SCHEDULER_RESOURCE_ADMISSION=True)
CEILING_ON = override_settings(VALI_CAPACITY_DECLARED_CEILING=True)


def _earned(seed: int) -> None:
    make_dispatchable_identity(seed)
    _mirror(seed)
    MinerCapacity.objects.filter(miner_node_id=node_id(seed)).update(
        declared_cpu_budget=10,
        declared_memory_mb_budget=40000,
        declared_asid_capacity=9,
        declared_at=timezone.now(),
    )


def _operator(seed: int, *, anchored: bool) -> None:
    make_dispatchable_identity(seed)
    _mirror(seed, mem=125000 if anchored else None, cpus=24 if anchored else None)
    MinerCapacity.objects.filter(miner_node_id=node_id(seed)).update(
        trust_class=CapacityTrustClass.OPERATOR
    )


def test_v1_an_unanchored_host_is_unknown_and_alerted(operator_client: APIClient) -> None:
    """Default settings: exactly the pre-change alert, plus the new field."""
    _earned(1)
    row = _row(_fleet(operator_client), 1)
    assert row["capacity"]["capacity_source"] == "unknown"
    assert "no-hardware-anchor" in row["alerts"]


@V2
def test_flag_off_keeps_the_legacy_alert(operator_client: APIClient) -> None:
    """Flag off: the field says `declared+earned`, the alert is untouched."""
    _earned(1)
    row = _row(_fleet(operator_client), 1)
    assert row["capacity"]["capacity_source"] == "declared+earned"
    assert "no-hardware-anchor" in row["alerts"]


@V2
@CEILING_ON
def test_flag_on_alerts_only_where_vali_cannot_size_the_host(
    operator_client: APIClient,
) -> None:
    _earned(1)
    _operator(2, anchored=True)
    _operator(3, anchored=False)
    make_dispatchable_identity(4)
    _mirror(4)  # earned, nothing declared: sized by the floor alone
    body = _fleet(operator_client)
    seeds = (1, 2, 3, 4)
    sources = {s: _row(body, s)["capacity"]["capacity_source"] for s in seeds}
    assert sources == {1: "declared+earned", 2: "trusted", 3: "unknown", 4: "earned"}
    alerted = {s for s in seeds if "no-hardware-anchor" in _row(body, s)["alerts"]}
    assert alerted == {3, 4}


@V2
def test_the_earned_block(operator_client: APIClient) -> None:
    _earned(1)
    earned = _row(_fleet(operator_client), 1)["capacity"]["earned"]
    assert {k: earned[k] for k in ("vms", "vcpus", "memory_mb")} == {
        "vms": 4,
        "vcpus": 8,
        "memory_mb": 32768,
    }
    assert earned["hardware_ceiling"] == {"vms": 6, "vcpus": 10, "memory_mb": 40000}
    assert earned["declared_at"] is not None
    assert earned["last_reason"] is None and earned["last_change_at"] is None
