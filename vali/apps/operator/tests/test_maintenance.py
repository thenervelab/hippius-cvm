"""The node owner's maintenance cordon
(`POST /v1/operator/miners/{node_id}/maintenance`, `apps.scheduler.cordon`):
the storage API's auth (principal + family on chain), set / lift,
idempotency, the audit trail, the refusal to touch a staff or automatic
cordon, the node-row fields, and that the scheduler honours it."""

from __future__ import annotations

from io import StringIO
from typing import Any

import pytest
from django.core.management import CommandError, call_command
from django.urls import reverse
from django.utils import timezone
from rest_framework.test import APIClient

from apps.disktier import node_family
from apps.disktier.tests.conftest import (  # noqa: F401 — pytest fixtures
    FAMILY_A,
    FAMILY_B,
    bind,
    chain,
    ss58_encode,
    writer_client,
)
from apps.scheduler import cordon, service
from apps.scheduler.models import MinerCapacity, MinerCapacityAudit, PlacementStatus
from apps.scheduler.placement import decide_placement
from apps.scheduler.tests.factories import (
    make_dispatchable_identity,
    make_miner,
    make_placement,
    make_snapshot,
    make_vm,
    node_id,
)

pytestmark = pytest.mark.django_db

NODE = node_id(1)
FAM_A = ss58_encode(FAMILY_A)
HEADERS = {"HTTP_X_HIPPIUS_ACTING_FAMILY": FAM_A, "HTTP_X_HIPPIUS_ACTING_USER": "user-42"}
URL = reverse("operator_maintenance", kwargs={"node_id": NODE})


def _capacity(seed: int = 1, **over: Any) -> MinerCapacity:
    fields: dict[str, Any] = dict(
        miner_node_id=node_id(seed),
        status="active",
        capacity_slots=8,
        observed_epoch=10,
        data_epoch=10,
        refreshed_at=timezone.now(),
    )
    fields.update(over)
    return MinerCapacity.objects.create(**fields)


@pytest.fixture
def owned(chain: dict[str, Any]) -> dict[str, Any]:  # noqa: F811
    bind(chain, NODE, FAMILY_A)
    _capacity()
    return chain


def _post(client: APIClient, body: Any, url: str = URL, **headers: Any) -> Any:
    return client.post(url, body, format="json", **{**HEADERS, **headers})


def _row() -> MinerCapacity:
    return MinerCapacity.objects.get(miner_node_id=NODE)


def _audits() -> list[tuple[str, str, Any]]:
    return list(
        MinerCapacityAudit.objects.order_by("created_at", "field").values_list(
            "actor", "field", "after"
        )
    )


# ─── auth ────────────────────────────────────────────────────────────


def test_no_credential_is_refused(owned: dict[str, Any]) -> None:
    assert _post(APIClient(), {"cordon": True}).status_code in (401, 403)
    assert _row().cordoned_at is None


def test_a_read_only_operator_principal_is_refused(owned: dict[str, Any]) -> None:
    from apps.disktier.tests.conftest import _bearer_client
    from apps.identity.models import PrincipalScope

    reader = _bearer_client("upstream-api", PrincipalScope.OPERATOR.value)
    assert _post(reader, {"cordon": True}).status_code == 403
    assert _row().cordoned_at is None


def test_another_familys_node_is_forbidden(
    chain: dict[str, Any],  # noqa: F811
    writer_client: APIClient,  # noqa: F811
) -> None:
    bind(chain, NODE, FAMILY_B)
    _capacity()
    response = _post(writer_client, {"cordon": True})
    assert response.status_code == 403
    assert response.json()["code"] == "not-family-node"
    assert _row().cordoned_at is None and not MinerCapacityAudit.objects.exists()


def test_the_family_check_is_fresh_for_the_write(
    owned: dict[str, Any],
    writer_client: APIClient,  # noqa: F811
) -> None:
    assert _post(writer_client, {"cordon": True}).status_code == 200
    # The node changed family on chain since: a cached answer must not be used.
    bind(owned, NODE, FAMILY_B)
    response = _post(writer_client, {"cordon": False})
    assert response.status_code == 403 and response.json()["code"] == "not-family-node"
    assert _row().cordoned_at is not None


def test_chain_down_fails_closed(
    chain: dict[str, Any],  # noqa: F811
    writer_client: APIClient,  # noqa: F811
) -> None:
    chain[NODE] = node_family.FamilyCheckUnavailable("rpc down")
    _capacity()
    response = _post(writer_client, {"cordon": True})
    assert response.status_code == 503 and response.json()["code"] == "chain-unavailable"
    assert _row().cordoned_at is None


def test_an_unknown_capacity_row_is_404(
    chain: dict[str, Any],  # noqa: F811
    writer_client: APIClient,  # noqa: F811
) -> None:
    bind(chain, NODE, FAMILY_A)
    response = _post(writer_client, {"cordon": True})
    assert response.status_code == 404 and response.json()["code"] == "no-capacity-record"


@pytest.mark.parametrize(
    ("body", "code"),
    [
        ({}, "body-invalid"),
        ({"cordon": "true"}, "body-invalid"),
        ({"cordon": 1}, "body-invalid"),
        ({"cordon": True, "extra": 1}, "body-invalid"),
        ([True], "body-invalid"),
        ({"cordon": True, "reason": 5}, "reason-invalid"),
        ({"cordon": True, "reason": "x" * 201}, "reason-invalid"),
        ({"cordon": True, "reason": "bad\nline"}, "reason-invalid"),
    ],
)
def test_a_malformed_body_is_400(
    owned: dict[str, Any],
    writer_client: APIClient,  # noqa: F811
    body: Any,
    code: str,
) -> None:
    response = _post(writer_client, body)
    assert response.status_code == 400 and response.json()["code"] == code
    assert _row().cordoned_at is None


def test_bad_acting_headers_are_400(
    owned: dict[str, Any],
    writer_client: APIClient,  # noqa: F811
) -> None:
    response = _post(writer_client, {"cordon": True}, HTTP_X_HIPPIUS_ACTING_FAMILY="nope")
    assert response.status_code == 400 and response.json()["code"] == "acting-family-invalid"


# ─── set / lift / idempotency / audit ────────────────────────────────


def test_set_then_lift_is_audited_and_idempotent(
    owned: dict[str, Any],
    writer_client: APIClient,  # noqa: F811
) -> None:
    response = _post(writer_client, {"cordon": True, "reason": "  swap PSU  "})
    assert response.status_code == 200
    body = response.json()
    row = _row()
    assert row.cordoned_at is not None
    assert row.cordon_reason == "owner-maintenance:swap PSU"
    assert body == {
        "node_id": NODE,
        "changed": True,
        "cordoned": True,
        "cordon_source": "owner",
        "cordon_reason": "swap PSU",
        "cordoned_at": row.cordoned_at.isoformat(),
        "hosted_vm_count": 0,
        "hosted_runner_vm_count": 0,
        "hosted_customer_vm_count": 0,
    }
    actor = f"owner:{FAM_A}"
    assert _audits() == [
        (actor, "cordon_reason", "owner-maintenance:swap PSU"),
        (actor, "cordoned_at", row.cordoned_at.isoformat()),
    ]
    audit = MinerCapacityAudit.objects.filter(field="cordoned_at").get()
    assert "user=user-42" in audit.reason and "principal=backend-operator-config" in audit.reason

    # Same call again: nothing changes, nothing is audited.
    again = _post(writer_client, {"cordon": True, "reason": "swap PSU"})
    assert again.status_code == 200 and again.json()["changed"] is False
    assert len(_audits()) == 2

    # A restated reason keeps the instant the cordon began.
    first = row.cordoned_at
    restated = _post(writer_client, {"cordon": True})
    assert restated.json()["changed"] is True and restated.json()["cordon_reason"] == ""
    assert _row().cordoned_at == first

    lifted = _post(writer_client, {"cordon": False})
    assert lifted.status_code == 200
    assert lifted.json()["changed"] is True
    assert lifted.json()["cordoned"] is False and lifted.json()["cordon_source"] is None
    row = _row()
    assert (row.cordoned_at, row.cordon_reason) == (None, "")
    assert [a for _, f, a in _audits() if f == "cordoned_at"][-1] is None

    # Lifting an uncordoned node is a no-op.
    before = MinerCapacityAudit.objects.count()
    noop = _post(writer_client, {"cordon": False})
    assert noop.status_code == 200 and noop.json()["changed"] is False
    assert MinerCapacityAudit.objects.count() == before


@pytest.mark.parametrize(
    ("reason", "source", "public"),
    [
        ("load ~350 after the runner burst", "staff", "operator-hold"),
        ("", "staff", "operator-hold"),
        ("disk-tier: pool default severe x3", "auto", "disk-tier"),
        ("quarantine: zombie", "auto", "quarantine"),
        ("auto: something", "auto", "auto"),
        # The owner prefix matches exactly, at the start: anything else is staff.
        ("Owner-maintenance:x", "staff", "operator-hold"),
        (" owner-maintenance:x", "staff", "operator-hold"),
    ],
)
def test_a_staff_or_automatic_cordon_is_never_the_owners(
    owned: dict[str, Any],
    writer_client: APIClient,  # noqa: F811
    reason: str,
    source: str,
    public: str,
) -> None:
    at = timezone.now()
    MinerCapacity.objects.filter(miner_node_id=NODE).update(cordoned_at=at, cordon_reason=reason)
    for want in (False, True):
        response = _post(writer_client, {"cordon": want, "reason": "mine"})
        assert response.status_code == 409
        assert response.json()["code"] == "cordon-not-owner"
        assert response.json()["cordon_source"] == source
        # The staff / vali reason itself never reaches the owner.
        if reason.strip():
            assert reason.strip() not in response.content.decode()
    row = _row()
    assert (row.cordoned_at, row.cordon_reason) == (at, reason)
    assert not MinerCapacityAudit.objects.exists()
    assert cordon.view_of(row) == cordon.CordonView(True, source, public)


@pytest.mark.parametrize(
    ("reason", "stored", "public"),
    [
        ("x" * 200, "owner-maintenance:" + "x" * 200, "x" * 200),
        ("   ", "owner-maintenance:", ""),
        (None, "owner-maintenance:", ""),
    ],
)
def test_reason_boundaries(
    owned: dict[str, Any],
    writer_client: APIClient,  # noqa: F811
    reason: str | None,
    stored: str,
    public: str,
) -> None:
    response = _post(writer_client, {"cordon": True, "reason": reason})
    assert response.status_code == 200
    assert _row().cordon_reason == stored
    assert response.json()["cordon_source"] == "owner"
    assert response.json()["cordon_reason"] == public


def test_an_upper_case_node_id_is_the_same_node(
    chain: dict[str, Any],  # noqa: F811
    writer_client: APIClient,  # noqa: F811
) -> None:
    seed = 0xFACADE
    node = node_id(seed)
    bind(chain, node, FAMILY_A)
    _capacity(seed)
    upper = reverse("operator_maintenance", kwargs={"node_id": node.upper()})
    assert node.upper() != node
    response = _post(writer_client, {"cordon": True}, url=upper)
    assert response.status_code == 200 and response.json()["node_id"] == node
    assert MinerCapacity.objects.get(miner_node_id=node).cordoned_at is not None


# ─── node rows ───────────────────────────────────────────────────────


def _node_row(client: APIClient) -> dict[str, Any]:
    response = client.get(reverse("operator_nodes"), {"node_id": NODE})
    assert response.status_code == 200
    return response.json()["nodes"][0]


def test_node_rows_show_the_cordon_and_the_hosted_vms(
    owned: dict[str, Any],
    writer_client: APIClient,  # noqa: F811
) -> None:
    make_dispatchable_identity(1)
    make_placement(
        make_vm("vm-r", "lease-r"),
        NODE,
        status=PlacementStatus.BOUND.value,
        resource_class="runner-small",
    )
    make_placement(
        make_vm("vm-c", "lease-c"), NODE, status=PlacementStatus.BOUND.value, resource_class="small"
    )
    make_placement(
        make_vm("vm-x", "lease-x"),
        NODE,
        status=PlacementStatus.FAILED.value,
        resource_class="runner-small",
        reason="released:vm-destroyed",
    )
    row = _node_row(writer_client)
    assert (row["cordoned"], row["cordon_source"], row["cordon_reason"]) == (False, None, None)

    response = _post(writer_client, {"cordon": True, "reason": "RAM upgrade"})
    assert response.json()["hosted_vm_count"] == 2
    assert response.json()["hosted_runner_vm_count"] == 1
    assert response.json()["hosted_customer_vm_count"] == 1

    row = _node_row(writer_client)
    assert row["cordoned"] is True
    assert row["cordon_source"] == "owner"
    assert row["cordon_reason"] == "RAM upgrade"
    # The cordon stops or moves nothing.
    assert row["hosted_vm_count"] == 2
    assert (row["hosted_runner_vm_count"], row["hosted_customer_vm_count"]) == (1, 1)

    MinerCapacity.objects.filter(miner_node_id=NODE).update(
        cordon_reason="internal: host 51.x flaky NIC"
    )
    row = _node_row(writer_client)
    assert (row["cordon_source"], row["cordon_reason"]) == ("staff", "operator-hold")


def test_hosted_vm_count_survives_a_node_id_case_drift(
    chain: dict[str, Any],  # noqa: F811
    writer_client: APIClient,  # noqa: F811
) -> None:
    """The owner waits for 0: a placement stored under another spelling of
    the node id must still be counted, never read as an empty host."""
    seed = 0xABCDEF
    node = node_id(seed)
    assert node.upper() != node
    bind(chain, node, FAMILY_A)
    _capacity(seed)
    make_placement(
        make_vm("vm-u", "lease-u"),
        node.upper(),
        status=PlacementStatus.BOUND.value,
        resource_class="runner-small",
    )
    url = reverse("operator_maintenance", kwargs={"node_id": node})
    body = _post(writer_client, {"cordon": True}, url=url).json()
    assert (body["hosted_vm_count"], body["hosted_runner_vm_count"]) == (1, 1)
    assert body["hosted_customer_vm_count"] == 0


def test_fleet_rows_mirror_the_cordon_fields(
    owned: dict[str, Any],
    writer_client: APIClient,  # noqa: F811
) -> None:
    from apps.operator.fleet import operator_fleet

    make_dispatchable_identity(1)
    _post(writer_client, {"cordon": True, "reason": "fans"})
    [miner] = [m for m in operator_fleet(include_chain=False)["miners"] if m["node_id"] == NODE]
    assert (miner["cordoned"], miner["cordon_source"], miner["cordon_reason"]) == (
        True,
        "owner",
        "fans",
    )
    # The fleet is the staff readout: the stored reason, verbatim.
    MinerCapacity.objects.filter(miner_node_id=NODE).update(cordon_reason="flaky NIC")
    [miner] = [m for m in operator_fleet(include_chain=False)["miners"] if m["node_id"] == NODE]
    assert (miner["cordon_source"], miner["cordon_reason"]) == ("staff", "flaky NIC")


# ─── the scheduler honours it ────────────────────────────────────────


def test_the_scheduler_refuses_placements_on_an_owner_cordoned_node(
    owned: dict[str, Any],
    writer_client: APIClient,  # noqa: F811
) -> None:
    _capacity(2)
    snap = make_snapshot(10, [make_miner(1), make_miner(2)])

    def _choose() -> str:
        args = service.placement_arguments(
            snapshot=snap, tenant_id="t", user_id="u", flavor="small"
        )
        return decide_placement(
            snapshot=snap,
            capacity_by_node={m.node_id: 8 for m in snap.miners},
            load_by_node={},
            family_load_by_node={},
            max_epoch_lag=2,
            cordoned=args["cordoned"],
        )

    assert _choose() == NODE
    _post(writer_client, {"cordon": True})
    assert NODE in service.cordoned_node_ids()
    assert _choose() == node_id(2)
    _post(writer_client, {"cordon": False})
    assert _choose() == NODE


# ─── the staff command ───────────────────────────────────────────────


def _staff(*args: str, reason: str = "ops hold") -> None:
    call_command(
        "vali_set_miner_capacity",
        "--node-id",
        NODE,
        *args,
        "--by",
        "ops",
        "--reason",
        reason,
        stdout=StringIO(),
    )


def test_staff_cordon_takes_over_an_owner_cordon_and_uncordon_lifts_any(
    owned: dict[str, Any],
    writer_client: APIClient,  # noqa: F811
) -> None:
    _post(writer_client, {"cordon": True, "reason": "PSU"})
    began = _row().cordoned_at
    _staff("--cordon")
    row = _row()
    assert cordon.view_of(row).source == "staff"
    assert (row.cordoned_at, row.cordon_reason) == (began, "ops hold")
    assert MinerCapacityAudit.objects.filter(actor="op:ops", field="cordon_reason").count() == 1
    response = _post(writer_client, {"cordon": False})
    assert response.status_code == 409 and response.json()["code"] == "cordon-not-owner"

    _staff("--uncordon")
    assert _row().cordoned_at is None
    _post(writer_client, {"cordon": True})
    _staff("--uncordon")
    assert _row().cordoned_at is None


def test_staff_command_refuses_an_owner_prefixed_reason(owned: dict[str, Any]) -> None:
    with pytest.raises(CommandError, match="owner-maintenance:"):
        _staff("--cordon", reason="owner-maintenance:looks like the owner's")
    assert _row().cordoned_at is None
