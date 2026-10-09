"""The HTTP surface: `/v1/vm/<id>/backup-policy` and `/v1/vm/<id>/backups`."""

from __future__ import annotations

import pytest
from django.conf import settings
from django.urls import URLPattern, URLResolver, get_resolver, reverse
from rest_framework.test import APIClient

from apps.backup import service
from apps.backup.models import BackupPolicy
from apps.identity import scoping
from apps.lifecycle.views import _serialize_vm
from apps.orchestration.permissions import IsOrchestrationRoot

from .conftest import FakeMiner, make_vm

pytestmark = [pytest.mark.django_db, pytest.mark.usefixtures("mock_s3")]


def _policy_url(vm_id: str = "vm-1") -> str:
    return reverse("vm_backup_policy", kwargs={"vm_id": vm_id})


def _backups_url(vm_id: str = "vm-1") -> str:
    return reverse("vm_backups", kwargs={"vm_id": vm_id})


def _backup_routes() -> list[tuple[str, type]]:
    out: list[tuple[str, type]] = []

    def walk(patterns, prefix: str = "") -> None:
        for p in patterns:
            if isinstance(p, URLResolver):
                walk(p.url_patterns, prefix + str(p.pattern))
            elif isinstance(p, URLPattern):
                cls = getattr(p.callback, "cls", None)
                if cls is not None and cls.__module__ == "apps.backup.views":
                    out.append((prefix + str(p.pattern), cls))

    walk(get_resolver().url_patterns)
    return out


def test_every_backup_route_is_root_only_and_operator_scoped() -> None:
    """`/v1/vm` is a public Ingress prefix: pin the gate on every route."""
    routes = _backup_routes()
    assert len(routes) == 2
    for route, cls in routes:
        assert IsOrchestrationRoot in cls.permission_classes, route
        assert scoping.declared_scope(cls) == scoping.OPERATOR_ONLY, route


@pytest.mark.parametrize(
    ("method", "url"),
    [
        ("get", "/v1/vm/vm-1/backup-policy"),
        ("put", "/v1/vm/vm-1/backup-policy"),
        ("delete", "/v1/vm/vm-1/backup-policy"),
        ("get", "/v1/vm/vm-1/backups"),
    ],
)
def test_tenant_and_non_root_principals_are_refused(
    method: str, url: str, tenant_client: APIClient, operator_client: APIClient
) -> None:
    make_vm()
    body = {"interval_s": 3600}
    assert getattr(tenant_client, method)(url, body, format="json").status_code == 403
    assert getattr(operator_client, method)(url, body, format="json").status_code == 403
    assert not BackupPolicy.objects.exists()


def test_put_creates_then_updates_the_policy(root_client: APIClient) -> None:
    make_vm()
    resp = root_client.put(_policy_url(), {"interval_s": 3600}, format="json")
    assert resp.status_code == 201, resp.content
    assert resp.json()["interval_s"] == 3600
    assert resp.json()["retention_days"] == 7
    assert resp.json()["failover_mode"] == "manual", "manual unless the customer opts in"

    resp = root_client.put(
        _policy_url(),
        {"interval_s": 900, "retention_days": 14, "failover_mode": "manual"},
        format="json",
    )
    assert resp.status_code == 200
    assert resp.json()["interval_s"] == 900 and resp.json()["failover_mode"] == "manual"

    resp = root_client.get(_policy_url())
    assert resp.status_code == 200 and resp.json()["retention_days"] == 14


@pytest.mark.parametrize(
    ("body", "code"),
    [
        ({"interval_s": 60}, "bad-interval"),
        ({}, "bad-interval"),
        ({"interval_s": 3600, "retention_days": 0}, "bad-retention"),
        ({"interval_s": 3600, "failover_mode": "x"}, "bad-failover-mode"),
        ({"interval_s": 3600, "target": "s3://mine"}, "bad-request"),
    ],
)
def test_put_validates_the_body(root_client: APIClient, body: dict, code: str) -> None:
    make_vm()
    resp = root_client.put(_policy_url(), body, format="json")
    assert resp.status_code == 400
    assert resp.json()["error"] == code


def test_put_refuses_a_legacy_vm(root_client: APIClient) -> None:
    make_vm(golden=False)
    resp = root_client.put(_policy_url(), {"interval_s": 3600}, format="json")
    assert resp.status_code == 409 and resp.json()["error"] == "not-golden"


def test_put_is_unavailable_while_backups_are_disabled(
    root_client: APIClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(settings, "VALI_BACKUP_ENABLED", False)
    make_vm()
    resp = root_client.put(_policy_url(), {"interval_s": 3600}, format="json")
    assert resp.status_code == 503 and resp.json()["error"] == "backup-unavailable"


def test_unknown_vm_and_missing_policy_are_404(root_client: APIClient) -> None:
    assert root_client.get(_policy_url("nope")).json()["error"] == "vm-not-found"
    assert root_client.get(_backups_url("nope")).status_code == 404
    make_vm()
    resp = root_client.get(_policy_url())
    assert resp.status_code == 404 and resp.json()["error"] == "no-backup-policy"
    assert root_client.delete(_policy_url()).status_code == 404


def test_delete_disables_the_policy(root_client: APIClient) -> None:
    make_vm()
    root_client.put(_policy_url(), {"interval_s": 3600}, format="json")
    assert root_client.delete(_policy_url()).status_code == 204
    assert root_client.get(_policy_url()).status_code == 404
    assert not BackupPolicy.objects.get().enabled


def test_backups_lists_chains_restore_point_and_stored_bytes(
    root_client: APIClient, fake_miner: FakeMiner, mock_s3
) -> None:
    vm = make_vm()
    root_client.put(_policy_url(), {"interval_s": 3600}, format="json")
    service.tick()
    fake_miner.finish()
    service.tick()

    body = root_client.get(_backups_url()).json()
    assert body["vm_id"] == "vm-1"
    assert body["backup_state"] == "ok"
    assert body["policy"]["interval_s"] == 3600
    assert body["stored_bytes"] == 40 * 1024**3 + 1024**2
    [chain] = body["chains"]
    assert chain["restorable"] and chain["boot_counter"] == 3
    [run] = chain["runs"]
    assert run["kind"] == "full" and run["status"] == "done"
    assert body["restore_point"]["run_id"] == run["run_id"]
    assert body["last_failure"] is None
    # Nothing a tenant or the layer above could use to reach the bucket.
    assert "key" not in str(body) and "upload" not in str(body)

    assert _serialize_vm(vm)["backup_state"] == "ok"


def test_the_vm_wire_shape_carries_backup_state(root_client: APIClient) -> None:
    vm = make_vm()
    assert _serialize_vm(vm)["backup_state"] == "disabled"
    root_client.put(_policy_url(), {"interval_s": 3600}, format="json")
    assert _serialize_vm(vm)["backup_state"] == "pending"
