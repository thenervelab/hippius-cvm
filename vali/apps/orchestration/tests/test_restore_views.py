"""The restore routes (C-2): root-only, stable error codes, the RestoreJob
shape."""

from __future__ import annotations

import pytest
from django.conf import settings
from rest_framework.test import APIClient

from apps.orchestration.models import MigrationJob, MigrationState

from .test_restore import _chain, _golden_vm, _restore_env  # noqa: F401 — autouse fixture

pytestmark = pytest.mark.django_db

_JOB_KEYS = {
    "job_id",
    "vm_id",
    "kind",
    "run_id",
    "chain_id",
    "point_taken_at",
    "rollback",
    "undo",
    "phase",
    "pct",
    "reason",
    "reverted",
    "prior_power_state",
    "source_node_id",
    "dest_node_id",
    "eta_s",
    "created_at",
    "finished_at",
}


def _post(client: APIClient, vm_id: str, body: dict) -> object:
    return client.post(f"/v1/vm/{vm_id}/restore", body, format="json")


def test_post_opens_a_restore_and_replays_on_the_same_request_id(root_client) -> None:
    vm = _golden_vm()
    run = _chain(vm)[-1]
    resp = _post(root_client, vm.vm_id, {"run_id": run.run_id, "request_id": "r-1"})
    assert resp.status_code == 202, resp.content
    body = resp.json()
    assert set(body) == _JOB_KEYS
    assert body["kind"] == "restore" and body["phase"] == "staging"
    assert body["run_id"] == run.run_id and body["chain_id"] == run.chain.chain_id
    assert body["pct"] == 0 and body["reverted"] is False
    assert body["prior_power_state"] == "running"
    assert body["source_node_id"] == body["dest_node_id"] == "node-src"

    again = _post(root_client, vm.vm_id, {"run_id": run.run_id, "request_id": "r-1"})
    assert again.status_code == 202 and again.json()["job_id"] == body["job_id"]
    assert MigrationJob.objects.count() == 1

    latest = root_client.get(f"/v1/vm/{vm.vm_id}/restore")
    assert latest.status_code == 200 and latest.json()["job_id"] == body["job_id"]
    one = root_client.get(f"/v1/vm/{vm.vm_id}/restore/{body['job_id']}")
    assert one.status_code == 200 and one.json() == latest.json()


def test_the_routes_are_root_only(authed_client) -> None:
    vm = _golden_vm()
    run = _chain(vm)[-1]
    resp = _post(authed_client, vm.vm_id, {"run_id": run.run_id, "request_id": "r"})
    assert resp.status_code == 403
    assert authed_client.get(f"/v1/vm/{vm.vm_id}/restore").status_code == 403
    assert not MigrationJob.objects.exists()


@pytest.mark.parametrize(
    ("setup", "body", "status", "code"),
    [
        ("flag-off", {}, 503, "restore-disabled"),
        (None, {"extra": 1}, 400, "bad-request"),
        (None, {"run_id": "nope"}, 400, "bad-request"),
        ("rollback", {}, 409, "rollback-unsupported"),
        ("unknown-run", {}, 409, "point-not-restorable"),
    ],
)
def test_refusals_carry_a_stable_code(root_client, monkeypatch, setup, body, status, code) -> None:
    vm = _golden_vm(counter=4 if setup == "rollback" else 3)
    run = _chain(vm, counter=3)[-1]
    if setup == "flag-off":
        monkeypatch.setattr(settings, "VALI_RESTORE_ENABLED", False)
    payload = {"run_id": run.run_id, "request_id": "r-2", **body}
    if setup == "unknown-run":
        payload["run_id"] = "f" * 32
    resp = _post(root_client, vm.vm_id, payload)
    assert resp.status_code == status, resp.content
    assert resp.json()["error"] == code


def test_unknown_vm_and_no_restore_are_404(root_client) -> None:
    assert root_client.get("/v1/vm/ghost/restore").json()["error"] == "vm-not-found"
    vm = _golden_vm()
    resp = root_client.get(f"/v1/vm/{vm.vm_id}/restore")
    assert resp.status_code == 404 and resp.json()["error"] == "no-restore"
    resp = root_client.get(f"/v1/vm/{vm.vm_id}/restore/" + "0" * 32)
    assert resp.status_code == 404 and resp.json()["error"] == "no-restore"


def test_a_migration_job_is_not_a_restore(root_client) -> None:
    from apps.orchestration.tests.factories import make_migration_job

    vm = _golden_vm()
    job = make_migration_job(vm)
    resp = root_client.get(f"/v1/vm/{vm.vm_id}/restore/{job.job_id}")
    assert resp.status_code == 404


def test_cancel_route(root_client) -> None:
    vm = _golden_vm()
    run = _chain(vm)[-1]
    job_id = _post(root_client, vm.vm_id, {"run_id": run.run_id, "request_id": "r-3"}).json()[
        "job_id"
    ]
    resp = root_client.post(f"/v1/vm/{vm.vm_id}/restore/{job_id}/cancel")
    assert resp.status_code == 200 and resp.json()["phase"] == "failed"
    assert MigrationJob.objects.get(job_id=job_id).state == MigrationState.FAILED.value
    again = root_client.post(f"/v1/vm/{vm.vm_id}/restore/{job_id}/cancel")
    assert again.status_code == 409 and again.json()["error"] == "not-cancellable"
