"""Integration tests for `GET /v1/scheduler/capacity` (#587 Phase 3).

The `read-miner-status` shell-out is mocked at the
`apps.scheduler.chain.read_miner_status` boundary; dispatchable miners
are seeded as real `MinerIdentity` rows (the same gate `decide_placement`
uses), so the capacity view reflects only miners vali can actually
launch onto.
"""

from __future__ import annotations

import pytest
from django.urls import reverse
from django.utils import timezone
from rest_framework import status
from rest_framework.test import APIClient

from apps.miners.models import MinerIdentity, MinerStatus
from apps.scheduler import chain
from apps.scheduler.models import PlacementStatus

from .factories import make_miner, make_placement, make_snapshot, make_vm, node_id

pytestmark = pytest.mark.django_db

CAPACITY_URL = reverse("scheduler_capacity")


def _mock_chain(monkeypatch, snapshot) -> None:
    monkeypatch.setattr(chain, "read_miner_status", lambda: snapshot)


def _dispatchable(seed: int) -> MinerIdentity:
    """A `MinerIdentity` that passes `dispatchable_node_ids` — active,
    bridged (`chain_node_id`), reachable (`netbird_ip`), real CHIP_ID,
    fresh heartbeat."""
    nid = node_id(seed)
    return MinerIdentity.objects.create(
        miner_id=f"miner-{seed}",
        pubkey_hex=f"{seed:02x}" + "ab" * 15,
        # unique real CHIP_ID per miner: 32 hex chars ≥ _CHIP_ID_MIN_HEX, even.
        platform_id=f"{seed:02x}" + "cd" * 15,
        chain_node_id=nid,
        netbird_ip=f"100.64.0.{seed}",
        last_seen_at=timezone.now(),
        last_heartbeat_sequence=1,
        status=MinerStatus.ACTIVE,
    )


def test_capacity_unauthenticated_rejected() -> None:
    resp = APIClient().get(CAPACITY_URL)
    assert resp.status_code in (
        status.HTTP_401_UNAUTHORIZED,
        status.HTTP_403_FORBIDDEN,
    )


def test_capacity_chain_down_503(authed_client: APIClient, monkeypatch: pytest.MonkeyPatch) -> None:
    def _raise():
        raise chain.ChainReadUnavailable("test: chain unreachable")

    monkeypatch.setattr(chain, "read_miner_status", _raise)
    resp = authed_client.get(CAPACITY_URL)
    assert resp.status_code == status.HTTP_503_SERVICE_UNAVAILABLE
    assert resp.json()["category"] == "internal"


def test_capacity_reports_free_slots_and_totals(
    authed_client: APIClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    _dispatchable(1)
    _dispatchable(2)
    _mock_chain(
        monkeypatch,
        make_snapshot(
            10,
            [
                make_miner(1, status="active", data_epoch=10, quality=99),
                make_miner(2, status="active", data_epoch=10, quality=5),
            ],
        ),
    )
    # One active placement on miner 1 → load=1 there.
    make_placement(make_vm("vm-load"), node_id(1), status=PlacementStatus.BOUND.value)

    resp = authed_client.get(CAPACITY_URL)
    assert resp.status_code == status.HTTP_200_OK, resp.content
    body = resp.json()
    assert body["current_epoch"] == 10
    assert body["dispatchable_miners"] == 2
    # default capacity = 4/miner (autouse fixture) ⇒ 8 total.
    assert body["total_capacity_slots"] == 8
    # miner 1 load=1 → free 3 ; miner 2 free 4 ⇒ 7 free.
    assert body["total_free_slots"] == 7
    assert body["has_capacity"] is True
    by_node = {m["node_id"]: m for m in body["miners"]}
    assert by_node[node_id(1)]["load"] == 1
    assert by_node[node_id(1)]["free_slots"] == 3
    assert by_node[node_id(2)]["free_slots"] == 4
    # sorted by free_slots desc → miner 2 first.
    assert body["miners"][0]["node_id"] == node_id(2)


def test_capacity_excludes_non_dispatchable_miner(
    authed_client: APIClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    # miner 1 is on-chain active but has NO MinerIdentity ⇒ not dispatchable.
    _dispatchable(2)
    _mock_chain(
        monkeypatch,
        make_snapshot(
            10,
            [
                make_miner(1, status="active", data_epoch=10),
                make_miner(2, status="active", data_epoch=10),
            ],
        ),
    )
    body = authed_client.get(CAPACITY_URL).json()
    assert body["dispatchable_miners"] == 1
    assert body["miners"][0]["node_id"] == node_id(2)


def test_capacity_stale_epoch_miner_contributes_zero_free(
    authed_client: APIClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    _dispatchable(1)
    # data_epoch 5 vs current 10 ⇒ lag 5 > max_epoch_lag (2) ⇒ stale.
    _mock_chain(
        monkeypatch,
        make_snapshot(10, [make_miner(1, status="active", data_epoch=5)]),
    )
    body = authed_client.get(CAPACITY_URL).json()
    assert body["dispatchable_miners"] == 1
    m = body["miners"][0]
    assert m["epoch_fresh"] is False
    assert m["free_slots"] == 0
    assert body["total_free_slots"] == 0
    assert body["has_capacity"] is False


def test_capacity_empty_when_no_dispatchable(
    authed_client: APIClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    _mock_chain(
        monkeypatch,
        make_snapshot(10, [make_miner(1, status="active", data_epoch=10)]),
    )
    body = authed_client.get(CAPACITY_URL).json()
    # Exact-equality on purpose: this pins the FULL response contract, so a
    # new field has to be added here deliberately rather than appearing
    # unannounced in a caller's payload. `pallet_live` was added knowingly —
    # the fossil caveat, see the two tests at the end of this module — and
    # so was `cvm_incapable_miners`, the §23 gate-(e) count (a fleet that
    # is placeable-empty because every host has been OBSERVED failing to
    # start a confidential guest must not look like a fleet that is merely
    # out of capacity).
    assert body == {
        "current_epoch": 10,
        "pallet_live": True,
        "dispatchable_miners": 0,
        "total_capacity_slots": 0,
        "total_free_slots": 0,
        "has_capacity": False,
        "cvm_incapable_miners": 0,
        "miners": [],
    }


# ─── Circuit-breaker: recent_failures_by_node (AUDIT-4) ──────────────


def test_recent_failures_by_node_counts_failed_placements_in_window(settings) -> None:
    from apps.scheduler import service

    settings.VALI_SCHEDULER_MAX_RECENT_FAILURES = 3
    settings.VALI_SCHEDULER_FAILURE_WINDOW_S = 600

    # node1: two FAILED placements; node2: one FAILED; a BOUND row does
    # not count.
    make_placement(make_vm("vm-f1"), node_id(1), status=PlacementStatus.FAILED.value)
    make_placement(make_vm("vm-f2"), node_id(1), status=PlacementStatus.FAILED.value)
    make_placement(make_vm("vm-f3"), node_id(2), status=PlacementStatus.FAILED.value)
    make_placement(make_vm("vm-ok"), node_id(2), status=PlacementStatus.BOUND.value)

    got = service.recent_failures_by_node()
    assert got == {node_id(1): 2, node_id(2): 1}


def test_recent_failures_by_node_empty_when_breaker_disabled(settings) -> None:
    from apps.scheduler import service

    settings.VALI_SCHEDULER_MAX_RECENT_FAILURES = 0
    make_placement(make_vm("vm-f1"), node_id(1), status=PlacementStatus.FAILED.value)
    # Disabled ⇒ the query is skipped entirely.
    assert service.recent_failures_by_node() == {}


# ─── the fossil caveat (#895/#917 reporting half) ────────────────────


def test_capacity_reports_pallet_live_true_on_a_healthy_chain(
    authed_client: APIClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """CLAIM: a live chain reports `pallet_live: true`.

    The twin of the fossil case below. Without it, a mutant that hardcodes
    `False` would look correct on the test that matters most.
    """
    _dispatchable(1)
    _mock_chain(
        monkeypatch,
        make_snapshot(10, [make_miner(1, status="active", data_epoch=10, quality=99)]),
    )

    body = authed_client.get(CAPACITY_URL).json()
    assert body["pallet_live"] is True


def test_capacity_flags_a_fossil_beside_the_quality_it_taints(
    authed_client: APIClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """CLAIM: when the pallet is gone, the response SAYS so.

    `quality` still carries its last-written value — that is the whole
    trap: a dropped pallet leaves its storage prefix answering reads, so
    the number looks like merit while being frozen at the last epoch
    close. `/v1/admin/epoch-weights` has surfaced `pallet_live` since
    #895; this endpoint served the same tainted number with no caveat,
    which is exactly how a caller takes it at face value.

    Asserting the quality is STILL PRESENT is deliberate: the fix is to
    label the value, not to hide it. Hiding it would break callers and
    destroy the evidence an operator needs to recognise the freeze.
    """
    _dispatchable(1)
    _mock_chain(
        monkeypatch,
        make_snapshot(
            5002,
            [make_miner(1, status="active", data_epoch=5002, quality=100170)],
            pallet_live=False,
        ),
    )

    body = authed_client.get(CAPACITY_URL).json()
    assert body["pallet_live"] is False
    assert body["current_epoch"] == 5002
    assert body["miners"][0]["quality"] == "100170"


# ─── §23 gate (e): the capability an operator can SEE ─────────────────


def _seed_capability(seed: int, **fields) -> None:
    """Write the OBSERVED start-capability columns on the miner's mirror
    row. `refresh_miner_capacity` (which the view calls) preserves them.
    """
    from apps.scheduler.models import MinerCapacity

    MinerCapacity.objects.update_or_create(
        miner_node_id=node_id(seed),
        defaults={
            "status": "active",
            "capacity_slots": 4,
            "observed_epoch": 10,
            "data_epoch": 10,
            "refreshed_at": timezone.now(),
            **fields,
        },
    )


def test_capacity_reports_the_observed_cvm_capability(
    authed_client: APIClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """CLAIM: a host being skipped by gate (e) says so where an operator
    looks BEFORE a launch, instead of surfacing as an unexplained
    `no-eligible-miner` afterwards.

    Without this the view reports the broken host as the one with the MOST
    free slots — free capacity is exactly what a host that starts nothing
    has — which is how the scheduler came to prefer it on the live fleet.
    """
    _dispatchable(1)
    _dispatchable(2)
    _mock_chain(
        monkeypatch,
        make_snapshot(
            10,
            [
                make_miner(1, status="active", data_epoch=10),
                make_miner(2, status="active", data_epoch=10),
            ],
        ),
    )
    # miner 1: a streak of OBSERVED start failures ⇒ hard-excluded.
    _seed_capability(1, cvm_last_fail_at=timezone.now(), cvm_fail_streak=3)
    # miner 2: an observed start SUCCESS ⇒ proven.
    _seed_capability(2, cvm_last_ok_at=timezone.now())

    body = authed_client.get(CAPACITY_URL).json()

    by_node = {m["node_id"]: m for m in body["miners"]}
    assert by_node[node_id(1)]["cvm_capability"] == "incapable"
    assert by_node[node_id(2)]["cvm_capability"] == "proven"
    # An incapable host offers NO slots — placement hard-excludes it with
    # no fallback, so counting them would advertise capacity that cannot
    # be launched onto.
    assert by_node[node_id(1)]["free_slots"] == 0
    assert by_node[node_id(1)]["capacity_slots"] == 4
    assert body["total_free_slots"] == 4
    assert body["cvm_incapable_miners"] == 1


def test_capacity_does_not_zero_a_merely_degraded_host(
    authed_client: APIClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The soft half stays soft. A single observed failure — or a host on
    post-exclusion probation — is a PREFERENCE, not a veto: it can still
    take a launch when nothing better exists, so its slots are real and
    must keep being advertised."""
    _dispatchable(1)
    _mock_chain(
        monkeypatch,
        make_snapshot(10, [make_miner(1, status="active", data_epoch=10)]),
    )
    _seed_capability(1, cvm_last_fail_at=timezone.now(), cvm_fail_streak=1)

    body = authed_client.get(CAPACITY_URL).json()

    assert body["miners"][0]["cvm_capability"] == "degraded"
    assert body["miners"][0]["free_slots"] == 4
    assert body["cvm_incapable_miners"] == 0


def test_capacity_reports_unknown_for_a_host_with_no_evidence(
    authed_client: APIClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The fail-safe default is reported as what it is — absence of
    evidence — not as a claim of capability."""
    _dispatchable(1)
    _mock_chain(
        monkeypatch,
        make_snapshot(10, [make_miner(1, status="active", data_epoch=10)]),
    )

    body = authed_client.get(CAPACITY_URL).json()

    assert body["miners"][0]["cvm_capability"] == "unknown"
    assert body["miners"][0]["free_slots"] == 4
    assert body["cvm_incapable_miners"] == 0
