"""Integration tests for the scheduler endpoints.

The `read-miner-status` shell-out is mocked at the
`apps.scheduler.chain.read_miner_status` boundary so the suite is
fast + Cargo-independent.
"""

from __future__ import annotations

import pytest
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APIClient

from apps.packer.models import PackerBuild
from apps.scheduler import chain
from apps.scheduler.models import (
    MinerCapacity,
    Placement,
    PlacementFailureSource,
    PlacementStatus,
)

from .factories import (
    make_dispatchable_identity,
    make_miner,
    make_placement,
    make_snapshot,
    make_vm,
    make_vm_with_ticket,
    node_id,
)

pytestmark = pytest.mark.django_db


@pytest.fixture(autouse=True)
def _seed_dispatchable_miners() -> None:
    """Seed dispatchable `MinerIdentity` rows for the seeds the view
    snapshots reference (1–3). The §23 placement gate excludes any
    on-chain-Active miner without a complete + live local identity; the
    view suite predates that gate and built snapshots only. Seeding here
    keeps the on-chain `status`/epoch gates (quarantined/stale tests)
    authoritative while letting active+fresh miners be real candidates.
    """
    for seed in (1, 2, 3):
        make_dispatchable_identity(seed)


PLACE_URL = reverse("scheduler_place")


def _bind_url(vm_id: str) -> str:
    return reverse("scheduler_bind", kwargs={"vm_id": vm_id})


def _fail_url(vm_id: str) -> str:
    return reverse("scheduler_fail", kwargs={"vm_id": vm_id})


def _mock_chain(monkeypatch: pytest.MonkeyPatch, snapshot) -> None:
    monkeypatch.setattr(chain, "read_miner_status", lambda: snapshot)


def _mock_chain_down(monkeypatch: pytest.MonkeyPatch) -> None:
    def _raise():
        raise chain.ChainReadUnavailable("test: chain unreachable")

    monkeypatch.setattr(chain, "read_miner_status", _raise)


# ─── POST /v1/scheduler/place ────────────────────────────────────────


def test_place_unauthenticated_rejected() -> None:
    resp = APIClient().post(PLACE_URL, {"vm_id": "vm-1", "resource_class": "std"}, format="json")
    assert resp.status_code in (
        status.HTTP_401_UNAUTHORIZED,
        status.HTTP_403_FORBIDDEN,
    )


def test_place_requires_the_root_principal(authed_client: APIClient) -> None:
    # RA-L2 — /place is a chain-read/capacity-refresh/image-build amplifier
    # and creates a Placement, so it is root-gated like bind/fail. A
    # non-root authenticated client is forbidden BEFORE any handler work.
    resp = authed_client.post(PLACE_URL, {"vm_id": "vm-1", "resource_class": "std"}, format="json")
    assert resp.status_code == status.HTTP_403_FORBIDDEN
    # No placement was created by the rejected caller.
    assert not Placement.objects.exists()


def test_place_happy_path(root_client: APIClient, monkeypatch: pytest.MonkeyPatch) -> None:
    vm = make_vm_with_ticket("vm-1", "tenant-1")
    _mock_chain(
        monkeypatch,
        make_snapshot(10, [make_miner(1, status="active", data_epoch=10, quality=99)]),
    )
    resp = root_client.post(PLACE_URL, {"vm_id": "vm-1", "resource_class": "std"}, format="json")
    assert resp.status_code == status.HTTP_201_CREATED, resp.content
    body = resp.json()
    assert body["status"] == "pending"
    assert body["miner_node_id"] == node_id(1)
    assert body["vm_family"] == "tenant-1"
    assert body["chain_epoch"] == 10
    assert body["version"] == 1
    assert Placement.objects.filter(vm=vm, status=PlacementStatus.PENDING).count() == 1


def test_place_refreshes_the_miner_capacity_mirror(
    root_client: APIClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    make_vm_with_ticket("vm-1", "tenant-1")
    _mock_chain(
        monkeypatch,
        make_snapshot(
            7,
            [
                make_miner(1, status="active", data_epoch=7, quality=42),
                make_miner(2, status="quarantined", data_epoch=7),
            ],
        ),
    )
    root_client.post(PLACE_URL, {"vm_id": "vm-1", "resource_class": "std"}, format="json")
    row = MinerCapacity.objects.get(miner_node_id=node_id(1))
    assert row.status == "active"
    assert row.quality == 42
    assert row.observed_epoch == 7
    # Seeded with the configured default cap (autouse fixture = 4).
    assert row.capacity_slots == 4
    assert MinerCapacity.objects.count() == 2


def test_place_is_idempotent_for_an_already_placed_vm(
    root_client: APIClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    make_vm_with_ticket("vm-1", "tenant-1")
    _mock_chain(monkeypatch, make_snapshot(10, [make_miner(1)]))
    first = root_client.post(PLACE_URL, {"vm_id": "vm-1", "resource_class": "std"}, format="json")
    assert first.status_code == status.HTTP_201_CREATED
    second = root_client.post(PLACE_URL, {"vm_id": "vm-1", "resource_class": "std"}, format="json")
    # Idempotent: 200 (not 201), same row, no duplicate.
    assert second.status_code == status.HTTP_200_OK
    assert second.json()["id"] == first.json()["id"]
    assert Placement.objects.count() == 1


def test_place_cas_race_returns_the_winning_row(
    root_client: APIClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Simulate two schedulers racing the same vm_id: a placement
    # already exists, but we force the idempotency pre-check to miss
    # it so the view proceeds to INSERT — which the partial unique
    # index rejects. The view must recover the winning row, not 500.
    vm = make_vm_with_ticket("vm-1", "tenant-1")
    existing = make_placement(
        vm, node_id(9), status=PlacementStatus.PENDING.value, vm_family="tenant-1"
    )
    monkeypatch.setattr("apps.scheduler.views._active_placement", lambda _vm: None)
    _mock_chain(monkeypatch, make_snapshot(10, [make_miner(1)]))

    resp = root_client.post(PLACE_URL, {"vm_id": "vm-1", "resource_class": "std"}, format="json")
    assert resp.status_code == status.HTTP_200_OK
    assert resp.json()["id"] == str(existing.id)
    assert Placement.objects.count() == 1


def test_place_cas_race_with_resource_class_mismatch_is_409(
    root_client: APIClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Same race, but the losing request asked for a different
    # resource_class — the recovery path must 409 (not silently 200
    # for a placement it never requested), matching the pre-check.
    vm = make_vm_with_ticket("vm-1", "tenant-1")
    make_placement(
        vm,
        node_id(9),
        status=PlacementStatus.PENDING.value,
        vm_family="tenant-1",
        resource_class="std",
    )
    monkeypatch.setattr("apps.scheduler.views._active_placement", lambda _vm: None)
    _mock_chain(monkeypatch, make_snapshot(10, [make_miner(1)]))

    resp = root_client.post(PLACE_URL, {"vm_id": "vm-1", "resource_class": "gpu"}, format="json")
    assert resp.status_code == status.HTTP_409_CONFLICT
    assert resp.json()["category"] == "placement-conflict"
    assert Placement.objects.count() == 1


def test_place_respects_anti_affinity_across_families(
    root_client: APIClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    make_vm_with_ticket("vm-a", "tenant-shared")
    make_vm_with_ticket("vm-b", "tenant-shared")
    _mock_chain(
        monkeypatch,
        make_snapshot(
            10,
            [
                make_miner(1, status="active", data_epoch=10, quality=5),
                make_miner(2, status="active", data_epoch=10, quality=5),
            ],
        ),
    )
    ra = root_client.post(PLACE_URL, {"vm_id": "vm-a", "resource_class": "std"}, format="json")
    rb = root_client.post(PLACE_URL, {"vm_id": "vm-b", "resource_class": "std"}, format="json")
    assert ra.status_code == status.HTTP_201_CREATED
    assert rb.status_code == status.HTTP_201_CREATED
    # Same family ⇒ the two VMs must land on different miners.
    assert ra.json()["miner_node_id"] != rb.json()["miner_node_id"]


def test_place_rejects_when_the_only_miner_is_stale(
    root_client: APIClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    make_vm_with_ticket("vm-1", "tenant-1")
    # current_epoch 20, miner data reflects epoch 5 ⇒ lag 15 > max 2.
    _mock_chain(
        monkeypatch,
        make_snapshot(20, [make_miner(1, status="active", data_epoch=5)]),
    )
    resp = root_client.post(PLACE_URL, {"vm_id": "vm-1", "resource_class": "std"}, format="json")
    assert resp.status_code == status.HTTP_409_CONFLICT
    assert resp.json()["category"] == "no-eligible-miner"


def test_place_rejects_when_all_miners_quarantined(
    root_client: APIClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    make_vm_with_ticket("vm-1", "tenant-1")
    _mock_chain(
        monkeypatch,
        make_snapshot(10, [make_miner(1, status="quarantined", data_epoch=10)]),
    )
    resp = root_client.post(PLACE_URL, {"vm_id": "vm-1", "resource_class": "std"}, format="json")
    assert resp.status_code == status.HTTP_409_CONFLICT
    assert resp.json()["category"] == "no-eligible-miner"


def test_place_503_when_chain_read_unavailable(
    root_client: APIClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    make_vm_with_ticket("vm-1", "tenant-1")
    _mock_chain_down(monkeypatch)
    resp = root_client.post(PLACE_URL, {"vm_id": "vm-1", "resource_class": "std"}, format="json")
    assert resp.status_code == status.HTTP_503_SERVICE_UNAVAILABLE
    assert resp.json()["category"] == "internal"


def test_place_404_unknown_vm(root_client: APIClient) -> None:
    resp = root_client.post(PLACE_URL, {"vm_id": "ghost", "resource_class": "std"}, format="json")
    assert resp.status_code == status.HTTP_404_NOT_FOUND


def test_place_409_when_vm_has_no_order_ticket(
    root_client: APIClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    make_vm("vm-1")  # VM but no OrderTicketIntake ⇒ family unknown.
    _mock_chain(monkeypatch, make_snapshot(10, [make_miner(1)]))
    resp = root_client.post(PLACE_URL, {"vm_id": "vm-1", "resource_class": "std"}, format="json")
    assert resp.status_code == status.HTTP_409_CONFLICT
    assert resp.json()["category"] == "family-unknown"


def test_place_400_missing_resource_class(root_client: APIClient) -> None:
    make_vm_with_ticket("vm-1", "tenant-1")
    resp = root_client.post(PLACE_URL, {"vm_id": "vm-1"}, format="json")
    assert resp.status_code == status.HTTP_400_BAD_REQUEST
    assert resp.json()["category"] == "wire"


def test_place_409_on_resource_class_mismatch(
    root_client: APIClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    make_vm_with_ticket("vm-1", "tenant-1")
    _mock_chain(monkeypatch, make_snapshot(10, [make_miner(1)]))
    root_client.post(PLACE_URL, {"vm_id": "vm-1", "resource_class": "std"}, format="json")
    resp = root_client.post(PLACE_URL, {"vm_id": "vm-1", "resource_class": "gpu"}, format="json")
    assert resp.status_code == status.HTTP_409_CONFLICT
    assert resp.json()["category"] == "placement-conflict"


def test_place_kicks_a_guest_image_packer_build(
    root_client: APIClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    make_vm_with_ticket("vm-1", "tenant-1")
    _mock_chain(monkeypatch, make_snapshot(10, [make_miner(1)]))
    assert not PackerBuild.objects.filter(image_kind="guest").exists()
    root_client.post(PLACE_URL, {"vm_id": "vm-1", "resource_class": "std"}, format="json")
    assert PackerBuild.objects.filter(image_kind="guest", state="queued").count() == 1


# ─── POST /v1/scheduler/<vm_id>/bind ─────────────────────────────────


def test_bind_requires_the_root_principal(authed_client: APIClient) -> None:
    vm = make_vm("vm-1")
    make_placement(vm, node_id(1))
    resp = authed_client.post(
        _bind_url("vm-1"),
        {"if_version": 1, "kbs_release_ref": "kbs-audit-1"},
        format="json",
    )
    assert resp.status_code == status.HTTP_403_FORBIDDEN


def test_bind_happy_path(root_client: APIClient) -> None:
    vm = make_vm("vm-1")
    placement = make_placement(vm, node_id(1), status=PlacementStatus.PENDING.value)
    resp = root_client.post(
        _bind_url("vm-1"),
        {"if_version": 1, "kbs_release_ref": "kbs-audit-abc"},
        format="json",
    )
    assert resp.status_code == status.HTTP_200_OK, resp.content
    body = resp.json()
    assert body["status"] == "bound"
    assert body["version"] == 2
    assert body["kbs_release_ref"] == "kbs-audit-abc"
    placement.refresh_from_db()
    assert placement.status == PlacementStatus.BOUND
    assert placement.bound_at is not None


def test_bind_404_unknown_vm(root_client: APIClient) -> None:
    resp = root_client.post(
        _bind_url("ghost"),
        {"if_version": 1, "kbs_release_ref": "x"},
        format="json",
    )
    assert resp.status_code == status.HTTP_404_NOT_FOUND


def test_bind_409_when_no_pending_placement(root_client: APIClient) -> None:
    make_vm("vm-1")
    resp = root_client.post(
        _bind_url("vm-1"),
        {"if_version": 1, "kbs_release_ref": "x"},
        format="json",
    )
    assert resp.status_code == status.HTTP_409_CONFLICT
    assert resp.json()["category"] == "no-pending-placement"


def test_bind_409_on_stale_if_version(root_client: APIClient) -> None:
    vm = make_vm("vm-1")
    make_placement(vm, node_id(1), status=PlacementStatus.PENDING.value, version=4)
    resp = root_client.post(
        _bind_url("vm-1"),
        {"if_version": 1, "kbs_release_ref": "x"},
        format="json",
    )
    assert resp.status_code == status.HTTP_409_CONFLICT
    assert resp.json()["category"] == "version-conflict"
    assert resp.json()["current"]["version"] == 4


def test_bind_400_missing_kbs_release_ref(root_client: APIClient) -> None:
    vm = make_vm("vm-1")
    make_placement(vm, node_id(1), status=PlacementStatus.PENDING.value)
    resp = root_client.post(_bind_url("vm-1"), {"if_version": 1}, format="json")
    assert resp.status_code == status.HTTP_400_BAD_REQUEST


# ─── POST /v1/scheduler/<vm_id>/fail ─────────────────────────────────


def test_fail_requires_the_root_principal(authed_client: APIClient) -> None:
    vm = make_vm("vm-1")
    make_placement(vm, node_id(1))
    resp = authed_client.post(_fail_url("vm-1"), {"if_version": 1, "reason": "x"}, format="json")
    assert resp.status_code == status.HTTP_403_FORBIDDEN


def test_fail_marks_failed_and_replaces_elsewhere(
    root_client: APIClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    vm = make_vm("vm-1")
    make_placement(
        vm,
        node_id(1),
        status=PlacementStatus.PENDING.value,
        vm_family="tenant-1",
    )
    _mock_chain(
        monkeypatch,
        make_snapshot(10, [make_miner(1), make_miner(2)]),
    )
    resp = root_client.post(
        _fail_url("vm-1"),
        {"if_version": 1, "reason": "kbs release dropped"},
        format="json",
    )
    assert resp.status_code == status.HTTP_200_OK, resp.content
    body = resp.json()
    assert body["failed"]["status"] == "failed"
    assert body["failed"]["reason"] == "kbs release dropped"
    assert body["replacement"] is not None
    assert body["replacement"]["status"] == "pending"
    # Re-placed OFF the failed miner.
    assert body["replacement"]["miner_node_id"] == node_id(2)
    assert body["replacement_error"] is None
    # provenance: a root `/fail` is `manual`, whatever its body spells —
    # the operator readout never surfaces it as a refusal
    failed = Placement.objects.get(vm=vm, status=PlacementStatus.FAILED.value)
    assert failed.failure_source == PlacementFailureSource.MANUAL


def test_replace_wires_owner_budget_and_circuit_breaker(
    root_client: APIClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    # RA-M3 — re-placement must carry the per-owner sub-budget + circuit
    # breaker into decide_placement (previously only launch_vm did), so a
    # churning VM does not silently re-concentrate one owner onto a miner.
    from apps.scheduler import service
    from apps.scheduler import views as sched_views

    vm = make_vm("vm-1")
    make_placement(
        vm,
        node_id(1),
        status=PlacementStatus.PENDING.value,
        vm_family="tenant-1",
        owner="alice",
    )
    _mock_chain(monkeypatch, make_snapshot(10, [make_miner(1), make_miner(2)]))

    captured: dict = {}
    real = sched_views.decide_placement

    def _spy(**kwargs):
        captured.update(kwargs)
        return real(**kwargs)

    monkeypatch.setattr(sched_views, "decide_placement", _spy)
    resp = root_client.post(_fail_url("vm-1"), {"if_version": 1, "reason": "drop"}, format="json")
    assert resp.status_code == status.HTTP_200_OK, resp.content
    # The per-owner budget + circuit-breaker inputs are now passed (they
    # were omitted before RA-M3 ⇒ decide_placement fell back to its inert
    # defaults on every re-placement).
    assert captured.get("owner_load_by_node") is not None
    assert (
        captured.get("max_owner_placements_per_miner") == service.max_owner_placements_per_miner()
    )
    assert captured.get("recent_failures_by_node") is not None
    assert captured.get("max_recent_failures") == service.max_recent_failures()


def test_fail_replacement_null_when_no_alternative_miner(
    root_client: APIClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    vm = make_vm("vm-1")
    make_placement(
        vm,
        node_id(1),
        status=PlacementStatus.PENDING.value,
        vm_family="tenant-1",
    )
    # Only the failed miner exists ⇒ nowhere to re-place.
    _mock_chain(monkeypatch, make_snapshot(10, [make_miner(1)]))
    resp = root_client.post(_fail_url("vm-1"), {"if_version": 1, "reason": "drop"}, format="json")
    assert resp.status_code == status.HTTP_200_OK
    body = resp.json()
    assert body["failed"]["status"] == "failed"
    assert body["replacement"] is None
    assert body["replacement_error"]["category"] == "no-eligible-miner"


def test_fail_succeeds_even_when_chain_down_for_replacement(
    root_client: APIClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    vm = make_vm("vm-1")
    make_placement(
        vm,
        node_id(1),
        status=PlacementStatus.PENDING.value,
        vm_family="tenant-1",
    )
    _mock_chain_down(monkeypatch)
    resp = root_client.post(_fail_url("vm-1"), {"if_version": 1, "reason": "drop"}, format="json")
    # The fail itself always succeeds (200); replacement is null.
    assert resp.status_code == status.HTTP_200_OK
    body = resp.json()
    assert body["failed"]["status"] == "failed"
    assert body["replacement"] is None
    assert body["replacement_error"]["category"] == "internal"


def test_fail_409_when_no_pending_placement(root_client: APIClient) -> None:
    make_vm("vm-1")
    resp = root_client.post(_fail_url("vm-1"), {"if_version": 1, "reason": "x"}, format="json")
    assert resp.status_code == status.HTTP_409_CONFLICT
    assert resp.json()["category"] == "no-pending-placement"


# ─── GET /v1/edge/registry (Edge permissionless-auth feed, PR-2) ──────

REGISTRY_URL = reverse("edge_registry_feed")


def _clear_feed_cache() -> None:
    from django.core.cache import cache

    cache.delete("edge_registry_feed_v1")


def test_edge_registry_feed_unauthenticated_ok(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Public on-chain data → no auth required; the Edge polls it directly.
    _clear_feed_cache()
    _mock_chain(
        monkeypatch,
        make_snapshot(
            current_epoch=7,
            miners=[
                make_miner(1, status="active", quality=5),
                make_miner(2, status="quarantined", quality=0),
            ],
        ),
    )
    resp = APIClient().get(REGISTRY_URL)
    assert resp.status_code == status.HTTP_200_OK
    body = resp.json()
    assert body["current_epoch"] == 7
    assert len(body["miners"]) == 2
    m0 = body["miners"][0]
    # Shape matches `hippius_onchain_registry::fetch_feed`.
    assert set(m0) == {
        "node_id_hex",
        "status",
        "last_transition_epoch",
        "data_epoch",
        "quality_dec",
    }
    # u128 quality is a decimal STRING, not a JSON number.
    assert m0["quality_dec"] == "5"
    assert isinstance(m0["quality_dec"], str)


def test_edge_registry_feed_chain_down_is_503(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Fail-closed: a chain-read failure surfaces as 503, never an empty
    # set (the Edge keeps its last good set + flips unhealthy).
    _clear_feed_cache()
    _mock_chain_down(monkeypatch)
    resp = APIClient().get(REGISTRY_URL)
    assert resp.status_code == status.HTTP_503_SERVICE_UNAVAILABLE


def test_edge_registry_feed_is_cached(monkeypatch: pytest.MonkeyPatch) -> None:
    # The cache coalesces Edge polls into one chain read per TTL window.
    _clear_feed_cache()
    calls = {"n": 0}

    def _counting():
        calls["n"] += 1
        return make_snapshot(current_epoch=1, miners=[make_miner(1)])

    monkeypatch.setattr(chain, "read_miner_status", _counting)
    APIClient().get(REGISTRY_URL)
    APIClient().get(REGISTRY_URL)
    assert calls["n"] == 1  # second poll served from cache


def test_edge_registry_feed_is_signed_over_the_exact_bytes(
    monkeypatch: pytest.MonkeyPatch, settings
) -> None:
    # Audit M-registry-mTLS: with a signing key configured, the response
    # carries an Ed25519 signature over the EXACT served bytes so the Edge
    # can fail-closed on a tampered in-cluster feed.
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
    )
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        PublicFormat,
    )

    _clear_feed_cache()
    seed = bytes(range(32))
    settings.VALI_EDGE_REGISTRY_FEED_SIGNING_SEED_VAULT_PATH = ""
    settings.VALI_EDGE_REGISTRY_FEED_SIGNING_SEED_HEX = seed.hex()
    pub = (
        Ed25519PrivateKey.from_private_bytes(seed)
        .public_key()
        .public_bytes(Encoding.Raw, PublicFormat.Raw)
    )
    _mock_chain(monkeypatch, make_snapshot(current_epoch=3, miners=[make_miner(1)]))
    resp = APIClient().get(REGISTRY_URL)
    assert resp.status_code == status.HTTP_200_OK
    sig_hex = resp.headers.get("X-Hippius-Registry-Sig")
    assert sig_hex, "signed feed must carry the signature header"
    # The signature verifies over the EXACT response body bytes — a tamper
    # would raise InvalidSignature here (the Edge's fail-closed gate).
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PublicKey,
    )

    vk = Ed25519PublicKey.from_public_bytes(pub)
    vk.verify(bytes.fromhex(sig_hex), resp.content)


def test_edge_registry_feed_unsigned_when_no_key(monkeypatch: pytest.MonkeyPatch, settings) -> None:
    # Pre-key-provisioning window: no signing key ⇒ no signature header
    # (the Edge only fail-closes once ITS pubkey is pinned).
    _clear_feed_cache()
    settings.VALI_EDGE_REGISTRY_FEED_SIGNING_SEED_VAULT_PATH = ""
    settings.VALI_EDGE_REGISTRY_FEED_SIGNING_SEED_HEX = ""
    _mock_chain(monkeypatch, make_snapshot(current_epoch=1, miners=[make_miner(1)]))
    resp = APIClient().get(REGISTRY_URL)
    assert resp.status_code == status.HTTP_200_OK
    assert "X-Hippius-Registry-Sig" not in resp.headers


# ─── Gate (f): /place and re-placement honour the VM's launch region ──


def _locate_seed(seed: int, country: str) -> None:
    from django.utils import timezone

    from apps.miners.models import LocationVerdict, MinerIdentity, MinerLocation

    MinerLocation.objects.create(
        miner=MinerIdentity.objects.get(chain_node_id=node_id(seed)),
        connection_ip="146.10.20.30",
        country_code=country,
        verdict=LocationVerdict.VERIFIED,
        observed_at=timezone.now(),
    )


def test_place_honours_the_region_the_launch_asked_for(
    root_client: APIClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`/place` carries no region of its own; it must read the LaunchJob's.
    Miner 1 would win the tie-break — it is in DE, the VM asked for FR."""
    from apps.orchestration.tests.factories import make_launch_record

    vm = make_vm_with_ticket("vm-1", "tenant-1")
    make_launch_record(vm, region="FR")
    _locate_seed(1, "DE")
    _locate_seed(2, "FR")
    _mock_chain(monkeypatch, make_snapshot(10, [make_miner(1), make_miner(2)]))
    resp = root_client.post(PLACE_URL, {"vm_id": "vm-1", "resource_class": "std"}, format="json")
    assert resp.status_code == status.HTTP_201_CREATED, resp.content
    assert resp.json()["miner_node_id"] == node_id(2)


def test_place_409s_no_miner_in_region_rather_than_placing_elsewhere(
    root_client: APIClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    from apps.orchestration.tests.factories import make_launch_record

    vm = make_vm_with_ticket("vm-1", "tenant-1")
    make_launch_record(vm, region="FR")
    _locate_seed(1, "DE")
    _mock_chain(monkeypatch, make_snapshot(10, [make_miner(1), make_miner(2)]))
    resp = root_client.post(PLACE_URL, {"vm_id": "vm-1", "resource_class": "std"}, format="json")
    assert resp.status_code == status.HTTP_409_CONFLICT
    assert resp.json()["category"] == "no-miner-in-region"
    assert Placement.objects.count() == 0


def test_replace_after_fail_stays_in_the_vm_region(
    root_client: APIClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Off miner 1; miner 2 is the tie-break winner but in DE; the VM was
    sold in FR ⇒ miner 3."""
    from apps.orchestration.tests.factories import make_launch_record

    vm = make_vm("vm-1")
    make_placement(vm, node_id(1), status=PlacementStatus.PENDING.value, vm_family="tenant-1")
    make_launch_record(vm, region="fr")
    _locate_seed(1, "FR")
    _locate_seed(2, "DE")
    _locate_seed(3, "FR")
    _mock_chain(monkeypatch, make_snapshot(10, [make_miner(1), make_miner(2), make_miner(3)]))
    resp = root_client.post(_fail_url("vm-1"), {"if_version": 1, "reason": "drop"}, format="json")
    assert resp.status_code == status.HTTP_200_OK, resp.content
    body = resp.json()
    assert body["replacement"]["miner_node_id"] == node_id(3)
    assert body["replacement_error"] is None


def test_replace_reports_no_miner_in_region_when_the_region_is_empty(
    root_client: APIClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The failed row is still marked failed; the VM is simply not moved
    out of its region. The category tells the caller WHY."""
    from apps.orchestration.tests.factories import make_launch_record

    vm = make_vm("vm-1")
    make_placement(vm, node_id(1), status=PlacementStatus.PENDING.value, vm_family="tenant-1")
    make_launch_record(vm, region="FR")
    _locate_seed(1, "FR")
    _locate_seed(2, "DE")
    _mock_chain(monkeypatch, make_snapshot(10, [make_miner(1), make_miner(2)]))
    resp = root_client.post(_fail_url("vm-1"), {"if_version": 1, "reason": "drop"}, format="json")
    assert resp.status_code == status.HTTP_200_OK
    body = resp.json()
    assert body["failed"]["status"] == "failed"
    assert body["replacement"] is None
    assert body["replacement_error"]["category"] == "no-miner-in-region"
