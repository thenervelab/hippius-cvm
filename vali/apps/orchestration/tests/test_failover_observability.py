"""What a restore / failover job says about itself: the job dict, the
`GET /v1/vm/<id>/restore` list and the VM's `last_failover`."""

from __future__ import annotations

from datetime import timedelta
from typing import Any

import pytest
from django.utils import timezone

from apps.miners.models import LocationVerdict, MinerIdentity, MinerLocation
from apps.orchestration import restore
from apps.orchestration.models import DestAuthorization, MigrationJob, MigrationState

from .conftest import FakeEffects
from .factories import make_service_client
from .test_failover import (  # noqa: F401 — autouse fixture
    _advance,
    _done,
    _failover,
    _failover_env,
    _verifying,
    _World,
)
from .test_restore import (  # noqa: F401 — autouse fixture
    _age_phase,
    _chain,
    _golden_vm,
    _grant,
    _original_grant,
    _Power,
    _restore_env,
)

pytestmark = pytest.mark.django_db


@pytest.fixture
def pwr(monkeypatch: pytest.MonkeyPatch) -> _Power:
    return _Power(monkeypatch)


@pytest.fixture
def world(monkeypatch: pytest.MonkeyPatch) -> _World:
    return _World(monkeypatch)


def _fresh(job: MigrationJob) -> MigrationJob:
    return MigrationJob.objects.select_related("vm", "restore_run", "authorization").get(
        pk=job.pk
    )


def _state(client: Any, vm_id: str) -> dict[str, Any]:
    resp = client.get(f"/v1/vm/{vm_id}/state")
    assert resp.status_code == 200, resp.content
    return resp.json()


# ── the job dict ─────────────────────────────────────────────────────


def test_a_running_failover_names_itself_and_its_evidence(world: _World) -> None:
    vm = _golden_vm()
    run = _chain(vm)[-1]
    world.kill()
    job = _fresh(_failover(vm))
    body = restore.serialize(job)
    assert body["kind"] == "failover" and body["failover_id"] == job.job_id
    assert body["trigger"] == "operator"
    assert body["outcome"] is None and body["committed_at"] is None
    assert body["started_at"] == job.started_at.isoformat()
    assert body["restored_point_at"] == run.created_at.isoformat()
    evidence = body["dead_miner_evidence"]
    assert evidence["edge_unreachable"] is True
    # `kill()` dates both signals an hour back.
    assert 3500 <= evidence["heartbeat_silent_s"] <= 3700
    assert 3500 <= evidence["netbird_silent_s"] <= 3700


def test_the_evidence_is_read_from_the_recheck_before_the_fence(world: _World) -> None:
    vm = _golden_vm()
    _chain(vm)
    world.kill()
    job = _failover(vm)
    now = timezone.now()
    auth = DestAuthorization.objects.get(pk=job.authorization_id)
    auth.evidence = {
        **auth.evidence,
        "recheck": {
            "checked_at": now.isoformat(),
            "heartbeat_last_seen_at": (now - timedelta(seconds=1000)).isoformat(),
            "netbird_last_seen_at": None,
            "edge": "unknown",
        },
    }
    auth.save(update_fields=["evidence"])
    assert restore.dead_miner_evidence(_fresh(job)) == {
        "heartbeat_silent_s": 1000,
        "netbird_silent_s": None,
        "edge_unreachable": False,
    }


def test_a_restore_has_no_failover_id_and_no_dead_miner_evidence() -> None:
    vm = _golden_vm()
    run = _chain(vm)[-1]
    job, _ = restore.start_restore(
        vm=vm, run_id=run.run_id, request_id="r-1", decided_by=make_service_client()
    )
    body = restore.serialize(_fresh(job))
    assert body["kind"] == "restore" and body["failover_id"] is None
    assert body["dead_miner_evidence"] is None and body["trigger"] == "operator"


def test_a_committed_failover_has_its_commit_instant(fx: FakeEffects, world: _World) -> None:
    vm, job = _done(fx, world)
    job = _fresh(job)
    assert job.committed_at is not None
    body = restore.serialize(job)
    assert body["committed_at"] == job.committed_at.isoformat()
    assert (body["phase"], body["outcome"]) == ("done", "committed")


def test_a_cancelled_restore_is_cancelled() -> None:
    vm = _golden_vm()
    run = _chain(vm)[-1]
    job, _ = restore.start_restore(
        vm=vm, run_id=run.run_id, request_id="r-1", decided_by=make_service_client()
    )
    job = restore.cancel_restore(job=job, decided_by=make_service_client())
    body = restore.serialize(_fresh(job))
    assert body["phase"] == "failed" and body["outcome"] == "cancelled"
    assert body["committed_at"] is None


def test_a_reverted_failover_is_reverted(fx: FakeEffects, world: _World, pwr) -> None:
    vm = _golden_vm()
    _chain(vm)
    world.kill()
    job = _verifying(fx, world, _failover(vm))
    _original_grant(fx, job)
    _age_phase(job)
    job = _advance(_advance(job))
    assert job.state == MigrationState.FAILED.value and job.reverted
    body = restore.serialize(_fresh(job))
    assert (body["phase"], body["outcome"]) == ("reverted", "reverted")
    assert body["committed_at"] is None


def test_a_failed_job_is_failed() -> None:
    vm = _golden_vm()
    run = _chain(vm)[-1]
    job, _ = restore.start_restore(
        vm=vm, run_id=run.run_id, request_id="r-1", decided_by=make_service_client()
    )
    MigrationJob.objects.filter(pk=job.pk).update(
        state=MigrationState.FAILED.value, reason="stage-failed", finished_at=timezone.now()
    )
    assert restore.serialize(_fresh(job))["outcome"] == "failed"


# ── the list ─────────────────────────────────────────────────────────


def _jobs(vm: Any, n: int) -> list[MigrationJob]:
    run = _chain(vm)[-1]
    jobs = []
    for i in range(n):
        job, _ = restore.start_restore(
            vm=vm, run_id=run.run_id, request_id=f"r-{i}", decided_by=make_service_client()
        )
        restore.cancel_restore(job=job, decided_by=make_service_client())
        MigrationJob.objects.filter(pk=job.pk).update(
            started_at=timezone.now() - timedelta(hours=n - i)
        )
        jobs.append(job)
    return jobs


def test_the_list_is_newest_first_and_limited(root_client, monkeypatch) -> None:
    monkeypatch.setattr(restore, "_rate_limit", lambda last: None)
    vm = _golden_vm()
    jobs = _jobs(vm, 3)
    listed = root_client.get(f"/v1/vm/{vm.vm_id}/restore").json()["jobs"]
    assert [j["job_id"] for j in listed] == [j.job_id for j in reversed(jobs)]
    one = root_client.get(f"/v1/vm/{vm.vm_id}/restore?limit=1").json()["jobs"]
    assert [j["job_id"] for j in one] == [jobs[-1].job_id]
    assert len(root_client.get(f"/v1/vm/{vm.vm_id}/restore?limit=100").json()["jobs"]) == 3


@pytest.mark.parametrize("raw", ["0", "101", "x", "-1"])
def test_a_bad_limit_is_a_400(root_client, raw: str) -> None:
    vm = _golden_vm()
    resp = root_client.get(f"/v1/vm/{vm.vm_id}/restore?limit={raw}")
    assert resp.status_code == 400 and resp.json()["error"] == "bad-request"


def test_the_list_defaults_to_twenty(root_client, monkeypatch) -> None:
    monkeypatch.setattr(restore, "_rate_limit", lambda last: None)
    vm = _golden_vm()
    _jobs(vm, 21)
    assert len(root_client.get(f"/v1/vm/{vm.vm_id}/restore").json()["jobs"]) == 20


# ── last_failover on the VM ──────────────────────────────────────────


def test_last_failover_is_null_until_a_failover_starts(root_client) -> None:
    vm = _golden_vm()
    _chain(vm)
    assert _state(root_client, vm.vm_id)["last_failover"] is None
    run = vm.backup_runs.order_by("-seq").first()
    restore.start_restore(
        vm=vm, run_id=run.run_id, request_id="r-1", decided_by=make_service_client()
    )
    assert _state(root_client, vm.vm_id)["last_failover"] is None, "a restore is not a failover"


def test_last_failover_follows_the_job_to_its_commit(
    root_client, fx: FakeEffects, world: _World
) -> None:
    vm = _golden_vm()
    run = _chain(vm)[-1]
    world.kill()
    job = _failover(vm)
    view = _state(root_client, vm.vm_id)["last_failover"]
    assert view["failover_id"] == job.job_id and view["trigger"] == "operator"
    assert view["phase"] == "activating" and view["outcome"] is None
    assert view["committed_at"] is None
    assert view["restored_point_at"] == run.created_at.isoformat()
    assert view["to_node_ref"] == restore.node_ref("node-dst")
    assert "node-dst" not in str(view), "the destination stays opaque"

    job = _verifying(fx, world, job)
    _grant(fx, job)
    job = _advance(job)
    assert job.state == MigrationState.DONE.value
    view = _state(root_client, vm.vm_id)["last_failover"]
    assert view["committed_at"] == _fresh(job).committed_at.isoformat()


def test_last_failover_is_the_newest_one(root_client, fx: FakeEffects, world: _World) -> None:
    vm, first = _done(fx, world)
    MigrationJob.objects.filter(pk=first.pk).update(
        started_at=timezone.now() - timedelta(days=3)
    )
    newer = MigrationJob.objects.get(pk=first.pk)
    newer.pk = None
    newer.job_id = "job-newer"
    newer.request_id = "fo-newer"
    newer.started_at = timezone.now()
    newer.save()
    assert _state(root_client, vm.vm_id)["last_failover"]["failover_id"] == "job-newer"


def test_from_region_is_the_dead_sources_last_known_country(
    root_client, world: _World
) -> None:
    vm = _golden_vm()
    _chain(vm)
    world.kill()
    MinerLocation.objects.create(
        miner=MinerIdentity.objects.get(miner_id="node-src"),
        country_code="FR",
        verdict=LocationVerdict.VERIFIED,
        observed_at=timezone.now() - timedelta(days=2),
    )
    _failover(vm)
    assert _state(root_client, vm.vm_id)["last_failover"]["from_region"] == "FR"
    listed = root_client.get("/v1/vm").json()["vms"]
    assert [v["last_failover"]["from_region"] for v in listed] == ["FR"]


def test_node_ref_is_stable_and_opaque() -> None:
    assert restore.node_ref("node-a") == restore.node_ref("node-a")
    assert restore.node_ref("node-a") != restore.node_ref("node-b")
    assert restore.node_ref("node-a").startswith("n-") and "node" not in restore.node_ref("node-a")
    assert restore.node_ref("") is None


def test_the_failover_route_without_a_point_is_a_409(root_client, world: _World) -> None:
    vm = _golden_vm()
    world.kill()
    resp = root_client.post(
        f"/v1/vm/{vm.vm_id}/failover",
        {"request_id": "fo-r", "dest_node_id": "node-dst"},
        format="json",
    )
    assert resp.status_code == 409 and resp.json()["error"] == "no-backup-point"


def test_the_migration_backfills_committed_at_past_the_commit_point() -> None:
    import importlib

    from django.apps import apps as django_apps

    vm = _golden_vm()
    run = _chain(vm)[-1]
    finished = timezone.now() - timedelta(days=1)
    reasons = {
        "done": (MigrationState.DONE.value, ""),
        "after": (MigrationState.FAILED.value, "failed-after-commit:x"),
        "raced": (MigrationState.FAILED.value, "revert-failed:blocked:revert-raced-commit:y"),
        "before": (MigrationState.FAILED.value, "stage-failed"),
    }
    jobs = {}
    for i, (name, (state, reason)) in enumerate(reasons.items()):
        job, _ = restore.start_restore(
            vm=vm, run_id=run.run_id, request_id=f"m-{i}", decided_by=make_service_client()
        )
        MigrationJob.objects.filter(pk=job.pk).update(
            state=state, reason=reason, finished_at=finished, committed_at=None
        )
        jobs[name] = job
    module = importlib.import_module(
        "apps.orchestration.migrations.0038_migration_job_trigger_committed_at"
    )
    module.committed_at_of_done_restores(django_apps, None)
    committed = {
        name: MigrationJob.objects.get(pk=job.pk).committed_at for name, job in jobs.items()
    }
    assert committed == {"done": finished, "after": finished, "raced": finished, "before": None}
