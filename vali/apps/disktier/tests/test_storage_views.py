"""The operator storage API (`apps.disktier.storage_views`): the auth
matrix (credential, principal, family on chain, chain down), every
endpoint, the audit trail. The chain read and the agent are stubbed."""

from __future__ import annotations

from typing import Any

import pytest
from django.urls import reverse
from django.utils import timezone
from rest_framework.test import APIClient

from apps.disktier import node_family
from apps.disktier.models import (
    DedicatedDisk,
    MinerStorageConfig,
    MinerStorageConfigAudit,
    MinerStoragePool,
)
from apps.scheduler.models import MinerCapacity
from apps.scheduler.tests.factories import make_dispatchable_identity, node_id

from .conftest import FAMILY_A, FAMILY_B, FakeAgent, bind, ss58_encode

pytestmark = pytest.mark.django_db

NODE = node_id(1)
FAM_A = ss58_encode(FAMILY_A)
FAM_B = ss58_encode(FAMILY_B)
HEADERS = {"HTTP_X_HIPPIUS_ACTING_FAMILY": FAM_A, "HTTP_X_HIPPIUS_ACTING_USER": "user-42"}


def _url(name: str, node: str = NODE, **kw: str) -> str:
    return reverse(name, kwargs={"node_id": node, **kw})


def _pool(pool_id: str = "default", **over: Any) -> dict[str, Any]:
    pool = {
        "id": pool_id,
        "path": "/var/lib/hippius-miner" if pool_id == "default" else f"/srv/{pool_id}",
        "class": "nvme" if pool_id == "default" else "hdd",
        "budget_gb": 3000 if pool_id == "default" else 500,
        "os_disks": pool_id == "default",
        "state": "active",
    }
    pool.update(over)
    return pool


def _doc(*extra: dict[str, Any], disks: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    return {"pools": [_pool(), *extra], "dedicated_disks": disks or []}


@pytest.fixture
def owned(chain: dict[str, Any]) -> dict[str, Any]:
    bind(chain, NODE, FAMILY_A)
    return chain


def _put(client: APIClient, doc: dict[str, Any], **extra: Any) -> Any:
    return client.put(_url("operator_storage"), doc, format="json", **HEADERS, **extra)


def _audit() -> list[tuple[str, int, str, str, str, str]]:
    return list(
        MinerStorageConfigAudit.objects.order_by("id").values_list(
            "action", "revision", "outcome", "principal", "family", "user"
        )
    )


# ─── auth matrix ─────────────────────────────────────────────────────


def test_no_credential_is_refused(owned: dict[str, Any]) -> None:
    assert APIClient().get(_url("operator_storage"), **HEADERS).status_code in (401, 403)
    assert APIClient().put(_url("operator_storage"), _doc(), format="json").status_code in (
        401,
        403,
    )


def test_a_tenant_principal_is_refused(owned: dict[str, Any], tenant_client: APIClient) -> None:
    assert tenant_client.get(_url("operator_storage"), **HEADERS).status_code == 403


def test_reads_take_any_operator_principal(
    owned: dict[str, Any], operator_client: APIClient
) -> None:
    response = operator_client.get(_url("operator_storage"), **HEADERS)
    assert response.status_code == 200
    assert response.json()["sync"] == {"status": "unmanaged"}


def test_writes_need_the_config_principal(
    owned: dict[str, Any], operator_client: APIClient, writer_client: APIClient
) -> None:
    assert _put(operator_client, _doc()).status_code == 403
    assert not MinerStorageConfig.objects.exists()
    assert _put(writer_client, _doc()).status_code == 202


def test_writes_fail_closed_without_a_configured_principal(
    owned: dict[str, Any], writer_client: APIClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    from django.conf import settings

    monkeypatch.setattr(settings, "VALI_OPERATOR_CONFIG_PRINCIPALS", [])
    assert _put(writer_client, _doc()).status_code == 403


def test_another_familys_node_is_forbidden(chain: dict[str, Any], writer_client: APIClient) -> None:
    bind(chain, NODE, FAMILY_B)
    for response in (
        writer_client.get(_url("operator_storage"), **HEADERS),
        _put(writer_client, _doc()),
        writer_client.get(_url("operator_storage_history"), **HEADERS),
    ):
        assert response.status_code == 403
        assert response.json()["code"] == "not-family-node"
    assert not MinerStorageConfig.objects.exists()


@pytest.mark.parametrize("state", ["unbound", "unbonding"])
def test_an_unregistered_or_unbonding_node_is_forbidden(
    chain: dict[str, Any], writer_client: APIClient, state: str
) -> None:
    if state == "unbonding":
        bind(chain, NODE, FAMILY_A, status="unbonding")
    response = _put(writer_client, _doc())
    assert response.status_code == 403 and response.json()["code"] == "not-family-node"


def test_chain_down_is_503(chain: dict[str, Any], writer_client: APIClient) -> None:
    chain[NODE] = node_family.FamilyCheckUnavailable("rpc down")
    for response in (
        writer_client.get(_url("operator_storage"), **HEADERS),
        _put(writer_client, _doc()),
    ):
        assert response.status_code == 503
        assert response.json()["code"] == "chain-unavailable"
    assert not MinerStorageConfig.objects.exists()


@pytest.mark.parametrize(
    ("headers", "code"),
    [
        ({"HTTP_X_HIPPIUS_ACTING_USER": "u"}, "acting-family-invalid"),
        (
            {"HTTP_X_HIPPIUS_ACTING_FAMILY": "not-ss58", "HTTP_X_HIPPIUS_ACTING_USER": "u"},
            "acting-family-invalid",
        ),
        ({"HTTP_X_HIPPIUS_ACTING_FAMILY": FAM_A}, "acting-user-invalid"),
        (
            {"HTTP_X_HIPPIUS_ACTING_FAMILY": FAM_A, "HTTP_X_HIPPIUS_ACTING_USER": "a b"},
            "acting-user-invalid",
        ),
    ],
)
def test_the_acting_headers_are_required(
    owned: dict[str, Any], writer_client: APIClient, headers: dict[str, str], code: str
) -> None:
    response = writer_client.get(_url("operator_storage"), **headers)
    assert response.status_code == 400 and response.json()["code"] == code
    assert owned["__calls__"] == []  # no chain read for a malformed call


def test_a_bad_node_id_is_400(owned: dict[str, Any], writer_client: APIClient) -> None:
    response = writer_client.get(_url("operator_storage", node="zz" * 32), **HEADERS)
    assert response.status_code == 400


def test_an_upper_case_node_id_is_the_same_node(
    owned: dict[str, Any], writer_client: APIClient
) -> None:
    assert _put(writer_client, _doc()).status_code == 202
    response = writer_client.get(_url("operator_storage", node=NODE.upper()), **HEADERS)
    assert response.status_code == 200 and response.json()["desired"]["revision"] == 1


def test_the_family_read_is_cached(owned: dict[str, Any], writer_client: APIClient) -> None:
    writer_client.get(_url("operator_storage"), **HEADERS)
    writer_client.get(_url("operator_storage"), **HEADERS)
    assert owned["__calls__"] == [NODE]


# ─── PUT / GET ───────────────────────────────────────────────────────


def test_put_stages_and_get_reads_it_back(owned: dict[str, Any], writer_client: APIClient) -> None:
    response = _put(writer_client, _doc(_pool("hdd0")))
    assert response.status_code == 202
    assert response.json() == {"revision": 1, "changed": True}
    assert response["ETag"] == '"1"'
    assert _put(writer_client, _doc(_pool("hdd0"))).json() == {"revision": 1, "changed": False}

    now = timezone.now()
    MinerStoragePool.objects.create(
        miner_node_id=NODE,
        pool_id="default",
        declared_class="nvme",
        budget_gb=3000,
        committed_gb=120,
        reported_state="active",
        reported_at=now,
        tier="ssd",
    )
    DedicatedDisk.objects.create(
        miner_node_id=NODE, disk_id="wwn-0x1", reported_state="free", reported_vm_id="vm-x"
    )
    data = writer_client.get(_url("operator_storage"), **HEADERS).json()
    assert data["desired"]["revision"] == 1
    assert [p["id"] for p in data["desired"]["pools"]] == ["default", "hdd0"]
    assert data["desired"]["updated_by"] == {
        "principal": "backend-operator-config",
        "family": FAM_A,
        "user": "user-42",
    }
    assert data["applied"]["pools"][0]["committed_gb"] == 120
    assert data["applied"]["dedicated_disks"][0]["desired_state"] is None
    assert "reported_vm_id" not in data["applied"]["dedicated_disks"][0]
    assert data["sync"]["status"] == "pending"
    assert data["tiers"][0]["effective_tier"] == "ssd"
    assert _audit() == [
        ("put", 1, "staged", "backend-operator-config", FAM_A, "user-42"),
        ("put", 1, "unchanged", "backend-operator-config", FAM_A, "user-42"),
    ]


def test_put_refuses_to_drop_a_pool_that_is_not_drained(
    owned: dict[str, Any], writer_client: APIClient
) -> None:
    MinerStoragePool.objects.create(
        miner_node_id=NODE, pool_id="hdd0", reported_state="active", committed_gb=0
    )
    response = _put(writer_client, _doc())
    assert response.status_code == 409
    assert response.json()["code"] == "pool-not-drained"
    assert (response.json()["pool"], response.json()["field"]) == ("hdd0", "removed")
    assert _put(writer_client, _doc(_pool("hdd0"))).status_code == 202


def test_validate_refuses_to_drop_a_pool_that_is_not_drained(
    owned: dict[str, Any], writer_client: APIClient
) -> None:
    MinerStoragePool.objects.create(
        miner_node_id=NODE, pool_id="hdd0", reported_state="active", committed_gb=0
    )
    response = writer_client.post(
        _url("operator_storage_validate"), _doc(), format="json", **HEADERS
    )
    assert response.status_code == 409
    assert (response.json()["code"], response.json()["pool"]) == ("pool-not-drained", "hdd0")


def test_put_checks_if_match(owned: dict[str, Any], writer_client: APIClient) -> None:
    assert _put(writer_client, _doc(), HTTP_IF_MATCH='"0"').status_code == 202
    response = _put(writer_client, _doc(_pool("a")), HTTP_IF_MATCH="0")
    assert response.status_code == 412
    assert response.json()["code"] == "revision-mismatch" and response.json()["revision"] == 1
    assert _put(writer_client, _doc(_pool("a")), HTTP_IF_MATCH='W/"1"').status_code == 202
    response = _put(writer_client, _doc(), HTTP_IF_MATCH="one")
    assert response.status_code == 400 and response.json()["code"] == "if-match-invalid"
    assert MinerStorageConfig.objects.get().revision == 2


@pytest.mark.parametrize(
    ("doc", "code", "subject"),
    [
        ({"pools": [_pool("a")]}, "pool-default-required", {"pool": "default"}),
        (_doc(_pool("a", path="/srv/../a")), "pool-path-invalid", {"pool": "a"}),
        (_doc(*[_pool(f"p{i}") for i in range(4)]), "too-many-pools", {}),
        (_doc(_pool("a", budget_gb=0)), "pool-budget-invalid", {"pool": "a"}),
        (_doc(disks=[{"id": "sdb", "state": "active"}]), "disk-id-invalid", {"disk": "sdb"}),
        (
            _doc(disks=[{"id": "wwn-1", "state": "active"}] * 2),
            "disk-duplicate",
            {"disk": "wwn-1"},
        ),
        (_doc(_pool("a", **{"class": "tape"})), "pool-class-invalid", {"pool": "a"}),
        ({"pools": [_pool()], "extra": 1}, "storage-config-malformed", {}),
    ],
)
def test_put_validation_mirrors_the_agent(
    owned: dict[str, Any],
    writer_client: APIClient,
    doc: dict[str, Any],
    code: str,
    subject: dict[str, str],
) -> None:
    response = _put(writer_client, doc)
    assert response.status_code == 400
    body = response.json()
    assert body["code"] == code and body["category"] == "validation"
    for key, value in subject.items():
        assert body[key] == value
    assert not MinerStorageConfig.objects.exists()


def test_put_checks_the_default_budget_against_the_report(
    owned: dict[str, Any], writer_client: APIClient
) -> None:
    MinerStoragePool.objects.create(miner_node_id=NODE, pool_id="default", budget_gb=2000)
    response = _put(writer_client, _doc())
    assert response.status_code == 400 and response.json()["code"] == "pool-conflicts-local"


# ─── pool + disk sugar ───────────────────────────────────────────────


def test_pool_edits(owned: dict[str, Any], writer_client: APIClient) -> None:
    pools = _url("operator_storage_pools")
    response = writer_client.post(pools, _pool("hdd0"), format="json", **HEADERS)
    assert response.status_code == 404 and response.json()["code"] == "storage-config-missing"
    _put(writer_client, _doc())
    assert writer_client.post(pools, _pool("hdd0"), format="json", **HEADERS).json() == {
        "revision": 2,
        "changed": True,
    }
    response = writer_client.post(pools, _pool("hdd0"), format="json", **HEADERS)
    assert response.status_code == 409 and response.json()["code"] == "pool-exists"
    response = writer_client.post(pools, _pool("Bad"), format="json", **HEADERS)
    assert response.status_code == 400 and response.json()["code"] == "pool-id-invalid"

    one = _url("operator_storage_pool", pool_id="hdd0")
    response = writer_client.patch(one, {"budget_gb": 900}, format="json", **HEADERS)
    assert response.json() == {"revision": 3, "changed": True}
    response = writer_client.patch(one, {"id": "x"}, format="json", **HEADERS)
    assert response.status_code == 400 and response.json()["code"] == "storage-config-malformed"
    response = writer_client.patch(
        one, {"budget_gb": 1}, format="json", HTTP_IF_MATCH="2", **HEADERS
    )
    assert response.status_code == 412
    missing = _url("operator_storage_pool", pool_id="nope")
    response = writer_client.patch(missing, {"budget_gb": 1}, format="json", **HEADERS)
    assert response.status_code == 404 and response.json()["code"] == "pool-not-found"

    assert writer_client.delete(one, **HEADERS).json() == {"revision": 4, "changed": True}
    body = MinerStorageConfig.objects.get().body
    assert body["pools"][1] == {**_pool("hdd0", budget_gb=900), "state": "draining"}
    response = writer_client.delete(_url("operator_storage_pool", pool_id="default"), **HEADERS)
    assert response.status_code == 400 and response.json()["code"] == "pool-conflicts-local"
    assert [a[0] for a in _audit()] == ["put", "pool-add", "pool-update", "pool-drain"]


def test_pool_edits_need_the_config_principal(
    owned: dict[str, Any], operator_client: APIClient
) -> None:
    one = _url("operator_storage_pool", pool_id="hdd0")
    assert operator_client.delete(one, **HEADERS).status_code == 403
    assert operator_client.patch(one, {}, format="json", **HEADERS).status_code == 403


def test_dedicated_disks_inventory_and_drain(
    owned: dict[str, Any], writer_client: APIClient
) -> None:
    DedicatedDisk.objects.create(
        miner_node_id=NODE,
        disk_id="wwn-0x1",
        size_bytes=18 * 10**12,
        reported_state="free",
        reported_at=timezone.now(),
    )
    drain = _url("operator_dedicated_disk_drain", disk_id="wwn-0x1")
    response = writer_client.post(drain, **HEADERS)
    assert response.status_code == 404 and response.json()["code"] == "disk-not-in-config"
    _put(writer_client, _doc(disks=[{"id": "wwn-0x1", "state": "active"}]))
    assert DedicatedDisk.objects.get().desired_state == "active"
    assert writer_client.post(drain, **HEADERS).json() == {"revision": 2, "changed": True}
    assert DedicatedDisk.objects.get().desired_state == "draining"
    data = writer_client.get(_url("operator_dedicated_disks"), **HEADERS).json()
    assert data["disks"] == [
        {
            "disk_id": "wwn-0x1",
            "size_bytes": 18 * 10**12,
            "desired_state": "draining",
            "reported_state": "free",
            "reported_error": "",
            "reported_at": data["disks"][0]["reported_at"],
            "state": "pending_probe",
            "verified_tier": "unknown",
            "last_probed_on": None,
            "behind_controller": False,
            "assigned": False,
        }
    ]


def test_disk_tiers(owned: dict[str, Any], operator_client: APIClient) -> None:
    assert operator_client.get(_url("operator_disk_tiers"), **HEADERS).json() == {
        "node_id": NODE,
        "pools": [],
    }
    MinerStoragePool.objects.create(
        miner_node_id=NODE, pool_id="default", tier="hdd", operator_override="ssd"
    )
    pools = operator_client.get(_url("operator_disk_tiers"), **HEADERS).json()["pools"]
    assert pools[0]["effective_tier"] == "ssd" and pools[0]["last_probe_on"] is None


# ─── validate / adopt / history ──────────────────────────────────────


def _dispatchable(version: str = "v2026.10.09") -> None:
    make_dispatchable_identity(1)
    MinerCapacity.objects.create(
        miner_node_id=NODE,
        status="active",
        capacity_slots=1,
        observed_epoch=1,
        data_epoch=1,
        refreshed_at=timezone.now(),
        agent_version=version,
    )


def test_validate_needs_the_push_flag(
    owned: dict[str, Any], writer_client: APIClient, agent: FakeAgent
) -> None:
    url = _url("operator_storage_validate")
    _dispatchable()
    response = writer_client.post(url, _doc(), format="json", **HEADERS)
    assert response.status_code == 409 and response.json()["code"] == "storage-config-push-disabled"


@pytest.mark.usefixtures("push_on")
def test_validate_dry_runs_on_the_host(
    owned: dict[str, Any], writer_client: APIClient, agent: FakeAgent
) -> None:
    url = _url("operator_storage_validate")
    _dispatchable()
    response = writer_client.post(url, **HEADERS)
    assert response.status_code == 404
    response = writer_client.post(url, _doc(_pool("hdd0")), format="json", **HEADERS)
    assert response.status_code == 200
    body = response.json()
    assert body["ok"] and body["code"].startswith("dry-run-ok:1:") and body["revision"] == 1
    assert agent.sent[-1]["dry_run"] is True
    assert not MinerStorageConfig.objects.exists()  # nothing staged

    _put(writer_client, _doc())
    agent.script.append((422, '{"code":"pool-not-a-mount","pool":"default"}'))
    body = writer_client.post(url, **HEADERS).json()
    assert body == {
        "revision": 1,
        "ok": False,
        "status": 422,
        "code": "pool-not-a-mount",
        "pool": "default",
    }
    agent.unreachable = True
    response = writer_client.post(url, **HEADERS)
    assert response.status_code == 502 and response.json()["code"] == "agent-unreachable"
    validates = [a for a in _audit() if a[0] == "validate"]
    assert [v[2] for v in validates] == [
        "dry-run-ok",
        "refused:pool-not-a-mount:default",
        "error:unreachable: edge-order: peer unreachable",
    ]
    assert all(v[4:] == (FAM_A, "user-42") for v in validates)
    response = writer_client.post(url, {"pools": []}, format="json", **HEADERS)
    assert response.status_code == 400


@pytest.mark.usefixtures("push_on")
def test_validate_refuses_an_old_agent(
    owned: dict[str, Any], writer_client: APIClient, agent: FakeAgent
) -> None:
    _dispatchable(version="dev")
    response = writer_client.post(
        _url("operator_storage_validate"), _doc(), format="json", **HEADERS
    )
    assert response.status_code == 409 and response.json()["code"] == "agent-version-below-min"
    assert agent.sent == []


def test_adopt(owned: dict[str, Any], writer_client: APIClient) -> None:
    url = _url("operator_storage_adopt")
    response = writer_client.post(url, {"pools": {}}, format="json", **HEADERS)
    assert response.status_code == 409 and response.json()["code"] == "storage-report-missing"
    MinerStoragePool.objects.create(
        miner_node_id=NODE,
        pool_id="default",
        declared_class="nvme",
        budget_gb=3000,
        reported_state="active",
        reported_at=timezone.now(),
    )
    response = writer_client.post(url, {"pools": {}}, format="json", **HEADERS)
    assert response.status_code == 400 and response.json()["code"] == "adopt-path-required"
    paths = {"pools": {"default": {"path": "/var/lib/hippius-miner"}}}
    response = writer_client.post(url, paths, format="json", **HEADERS)
    assert response.status_code == 202 and response.json() == {"revision": 1, "changed": True}
    response = writer_client.post(url, paths, format="json", **HEADERS)
    assert response.status_code == 409 and response.json()["code"] == "storage-config-exists"
    response = writer_client.post(url, {**paths, "force": True}, format="json", **HEADERS)
    assert response.status_code == 202 and response.json()["changed"] is False
    response = writer_client.post(url, {**paths, "force": "yes"}, format="json", **HEADERS)
    assert response.status_code == 400
    assert MinerStorageConfig.objects.get().body["pools"][0]["class"] == "nvme"
    assert [a[:3] for a in _audit()] == [("adopt", 1, "staged"), ("adopt", 1, "unchanged")]


def test_history(owned: dict[str, Any], writer_client: APIClient) -> None:
    _put(writer_client, _doc())
    _put(writer_client, _doc(_pool("hdd0")))
    url = _url("operator_storage_history")
    entries = writer_client.get(url, **HEADERS).json()["entries"]
    assert [(e["revision"], e["action"], e["outcome"]) for e in entries] == [
        (2, "put", "staged"),
        (1, "put", "staged"),
    ]
    assert entries[0]["doc"]["pools"][1]["id"] == "hdd0"
    assert entries[0]["family"] == FAM_A and entries[0]["user"] == "user-42"
    assert len(writer_client.get(url, {"limit": 1}, **HEADERS).json()["entries"]) == 1
    assert writer_client.get(url, {"limit": 0}, **HEADERS).status_code == 400
    assert writer_client.get(url, {"limit": "x"}, **HEADERS).status_code == 400


def test_a_node_that_changed_family_shows_the_new_family_nothing_of_the_old(
    chain: dict[str, Any], writer_client: APIClient
) -> None:
    bind(chain, NODE, FAMILY_A)
    _put(writer_client, _doc(_pool("hdd0")))
    # The node changes hands on chain.
    bind(chain, NODE, FAMILY_B)
    node_family.clear_cache()
    headers_b = {"HTTP_X_HIPPIUS_ACTING_FAMILY": FAM_B, "HTTP_X_HIPPIUS_ACTING_USER": "user-9"}
    data = writer_client.get(_url("operator_storage"), **headers_b).json()
    assert data["desired"] is None and data["sync"] == {"status": "unmanaged"}
    history = writer_client.get(_url("operator_storage_history"), **headers_b).json()
    assert history["entries"] == []
    one = _url("operator_storage_pool", pool_id="hdd0")
    assert writer_client.delete(one, **headers_b).status_code == 404
    # The former family is refused outright.
    assert _put(writer_client, _doc()).status_code == 403
    # The new family's first write replaces the document (If-Match 0).
    response = writer_client.put(
        _url("operator_storage"), _doc(), format="json", HTTP_IF_MATCH="0", **headers_b
    )
    assert response.status_code == 202 and response.json()["revision"] == 2
    history = writer_client.get(_url("operator_storage_history"), **headers_b).json()
    assert [(e["revision"], e["user"]) for e in history["entries"]] == [(2, "user-9")]


def test_writes_read_the_chain_afresh(chain: dict[str, Any], writer_client: APIClient) -> None:
    bind(chain, NODE, FAMILY_A)
    assert writer_client.get(_url("operator_storage"), **HEADERS).status_code == 200  # cached
    bind(chain, NODE, FAMILY_B)
    # A read may ride the 30 s cache; a write may not.
    assert writer_client.get(_url("operator_storage"), **HEADERS).status_code == 200
    response = _put(writer_client, _doc())
    assert response.status_code == 403 and response.json()["code"] == "not-family-node"


def test_history_hides_another_familys_calls_in_between(
    chain: dict[str, Any], writer_client: APIClient
) -> None:
    bind(chain, NODE, FAMILY_A)
    _put(writer_client, _doc())
    # While family B ran the node it validated a document, without writing.
    MinerStorageConfigAudit.objects.create(
        miner_node_id=NODE,
        revision=1,
        action="validate",
        family=FAM_B,
        family_account=FAMILY_B.hex(),
        user="user-9",
        outcome="dry-run-ok",
        at=timezone.now(),
    )
    # Back with family A: its history has its own entries only.
    entries = writer_client.get(_url("operator_storage_history"), **HEADERS).json()["entries"]
    assert [e["user"] for e in entries] == ["user-42"]


# ─── force-remove a dead pool (#1640) ────────────────────────────────


def test_force_remove_a_dead_pool(owned: dict[str, Any], writer_client: APIClient) -> None:
    assert _put(writer_client, _doc(_pool("nvme0"))).status_code == 202
    MinerStoragePool.objects.create(
        miner_node_id=NODE,
        pool_id="nvme0",
        reported_state="unavailable",
        reported_error="pool-path-missing",
        committed_gb=0,
        reported_at=timezone.now(),
    )
    url = _url("operator_storage_pool_force_remove", pool_id="nvme0")
    # A reason is required.
    resp = writer_client.post(url, {}, format="json", **HEADERS)
    assert (resp.status_code, resp.json()["code"]) == (400, "force-reason-required")
    resp = writer_client.post(url, {"reason": "disk pulled"}, format="json", **HEADERS)
    assert resp.status_code == 202, resp.json()
    row = MinerStorageConfig.objects.get(miner_node_id=NODE)
    assert [p["state"] for p in row.body["pools"] if p["id"] == "nvme0"] == ["draining"]
    assert row.forced_pools["nvme0"]["user"] == "user-42"
    actions = [a[0] for a in _audit()]
    assert actions[-2:] == ["pool-force", "pool-force-drain"]
    forced = MinerStorageConfigAudit.objects.get(action="pool-force")
    assert (forced.family, forced.user, forced.doc["reason"]) == (FAM_A, "user-42", "disk pulled")


def test_force_remove_refuses_a_live_pool(owned: dict[str, Any], writer_client: APIClient) -> None:
    assert _put(writer_client, _doc(_pool("nvme0"))).status_code == 202
    MinerStoragePool.objects.create(
        miner_node_id=NODE, pool_id="nvme0", reported_state="active", committed_gb=0
    )
    url = _url("operator_storage_pool_force_remove", pool_id="nvme0")
    resp = writer_client.post(url, {"reason": "x"}, format="json", **HEADERS)
    assert resp.status_code == 409
    assert (resp.json()["code"], resp.json()["pool"]) == ("pool-not-unavailable", "nvme0")
    missing = _url("operator_storage_pool_force_remove", pool_id="hdd9")
    assert writer_client.post(missing, {"reason": "x"}, format="json", **HEADERS).status_code == 404


def test_force_remove_needs_the_config_writer(
    owned: dict[str, Any], operator_client: APIClient
) -> None:
    url = _url("operator_storage_pool_force_remove", pool_id="nvme0")
    resp = operator_client.post(url, {"reason": "x"}, format="json", **HEADERS)
    assert resp.status_code == 403


def test_force_remove_on_a_document_that_drops_another_pool_is_409(
    owned: dict[str, Any], writer_client: APIClient
) -> None:
    assert _put(writer_client, _doc(_pool("nvme0"), _pool("hdd0"))).status_code == 202
    row = MinerStorageConfig.objects.get(miner_node_id=NODE)
    # hdd0 in force (active), the body (pre-guard) drops it.
    MinerStorageConfig.objects.filter(pk=row.pk).update(
        acked_revision=row.revision,
        acked_body=_doc(_pool("nvme0"), _pool("hdd0")),
        reported_revision=row.revision,
        body=_doc(_pool("nvme0")),
    )
    MinerStoragePool.objects.create(
        miner_node_id=NODE, pool_id="nvme0", reported_state="unavailable", committed_gb=0
    )
    url = _url("operator_storage_pool_force_remove", pool_id="nvme0")
    resp = writer_client.post(url, {"reason": "x"}, format="json", **HEADERS)
    assert (resp.status_code, resp.json()["code"]) == (409, "pool-not-drained")
    assert MinerStorageConfig.objects.get(pk=row.pk).forced_pools == {}
