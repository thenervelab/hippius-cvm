"""The operator's cross-region override (`allow_cross_region` + the
destination `region` + a `reason`): on the operator paths only — POST
migrate / restore / failover and the operator drain — recorded on the job,
and the VM's region from then on. Every automatic path stays in-region."""

from __future__ import annotations

import inspect

import pytest
from django.urls import reverse
from django.utils import timezone
from rest_framework import status
from rest_framework.test import APIClient

from apps.backup import service as backup_service
from apps.miners.models import MinerIdentity, MinerStatus
from apps.orchestration import restore, service
from apps.orchestration.models import MigrationJob, MigrationState
from apps.orchestration.service import CrossRegion

from .factories import make_launch_record, make_service_client, make_vm
from .test_move_region import _locate, _miners  # noqa: F401 — autouse fixture

pytestmark = pytest.mark.django_db

EVAC = CrossRegion(region="DE", reason="FR host evacuated for a BIOS fix", operator="julien")


@pytest.mark.parametrize(
    ("allow", "region", "reason", "operator", "ok"),
    [
        (None, "", None, None, None),
        (False, "", None, None, None),
        (True, "de", "why", " julien ", CrossRegion("DE", "why", "julien")),
        (True, "", "why", "j", ValueError),
        (True, "DEU", "why", "j", ValueError),
        (True, "DE", "", "j", ValueError),
        (True, "DE", "x" * 257, "j", ValueError),
        (True, "DE", "why\nFORGED log line", "j", ValueError),
        (True, "DE", "why", None, ValueError),
        (True, "DE", "why", "", ValueError),
        ("yes", "DE", "why", "j", ValueError),
        (None, "", "a reason without the flag", None, ValueError),
        (None, "", None, "an operator without the flag", ValueError),
    ],
)
def test_parse_cross_region(allow, region, reason, operator, ok) -> None:
    if ok is ValueError:
        with pytest.raises(ValueError):
            service.parse_cross_region(allow, region, reason, operator)
    else:
        assert service.parse_cross_region(allow, region, reason, operator) == ok


def test_an_operator_migration_crosses_regions_recorded() -> None:
    vm = make_vm(host="node-src")
    make_launch_record(vm, region="FR")
    actor = make_service_client()
    with pytest.raises(service.StartError) as exc:
        service.start_migration(vm=vm, dest_node_id="node-fr", decided_by=actor, cross_region=EVAC)
    assert exc.value.category == "cross-region", "the destination is in the NAMED region"
    job = service.start_migration(
        vm=vm, dest_node_id="node-de", decided_by=actor, cross_region=EVAC
    )
    assert (job.region, job.cross_region_override, job.cross_region_from) == ("DE", True, "FR")
    assert (job.cross_region_reason, job.cross_region_by) == (EVAC.reason, "julien")
    assert job.decided_by_id == actor.pk and job.started_at is not None


def test_an_override_into_the_vms_own_region_is_refused() -> None:
    vm = make_vm(host="node-src")
    make_launch_record(vm, region="DE")
    with pytest.raises(service.StartError) as exc:
        service.start_migration(
            vm=vm, dest_node_id="node-de", decided_by=make_service_client(), cross_region=EVAC
        )
    assert exc.value.category == "not-cross-region"


def test_once_it_took_the_vm_lives_in_the_new_region() -> None:
    """The region of record follows the override that took — so every
    automatic path keeps the VM there, never moving it back on its own."""
    vm = make_vm(host="node-src")
    make_launch_record(vm, region="FR")
    job = service.start_migration(
        vm=vm, dest_node_id="node-de", decided_by=make_service_client(), cross_region=EVAC
    )
    assert backup_service.vm_region(vm) == "FR", "not before it took"
    done = timezone.now()
    MigrationJob.objects.filter(pk=job.pk).update(state=MigrationState.DONE.value, finished_at=done)
    assert backup_service.vm_region(vm) == "DE"
    MigrationJob.objects.filter(pk=job.pk).update(state=MigrationState.FAILED.value)
    assert backup_service.vm_region(vm) == "FR", "a move that failed never took"
    MigrationJob.objects.filter(pk=job.pk).update(committed_at=done)
    assert backup_service.vm_region(vm) == "DE", "failed after its commit: the vm moved"
    MigrationJob.objects.filter(pk=job.pk).update(reverted=True)
    assert backup_service.vm_region(vm) == "FR", "reverted: back where it was"


def test_an_override_back_wins_once_it_took() -> None:
    vm = make_vm(host="node-src")
    make_launch_record(vm, region="FR")
    done = timezone.now()
    there = service.start_migration(
        vm=vm, dest_node_id="node-de", decided_by=make_service_client(), cross_region=EVAC
    )
    MigrationJob.objects.filter(pk=there.pk).update(
        state=MigrationState.DONE.value, finished_at=done
    )
    assert backup_service.vm_region(vm) == "DE"
    back = service.start_migration(
        vm=vm,
        dest_node_id="node-fr",
        decided_by=make_service_client(),
        cross_region=CrossRegion("FR", "BIOS fixed, home", "julien"),
    )
    assert back.cross_region_from == "DE"
    assert backup_service.vm_region(vm) == "DE", "until it took"
    MigrationJob.objects.filter(pk=back.pk).update(
        state=MigrationState.DONE.value, finished_at=timezone.now()
    )
    assert backup_service.vm_region(vm) == "FR"


def test_the_migrate_api_takes_the_override(root_client: APIClient) -> None:
    vm = make_vm("vm-1", host="node-src")
    make_launch_record(vm, region="FR")
    url = "/v1/vm/vm-1/migrate"
    resp = root_client.post(
        url,
        {"dest_node_id": "node-de", "allow_cross_region": True, "region": "DE", "operator": "j"},
        format="json",
    )
    assert resp.status_code == status.HTTP_400_BAD_REQUEST, "a reason is required"
    resp = root_client.post(url, {"dest_node_id": "node-de"}, format="json")
    assert resp.json()["category"] == "cross-region"
    resp = root_client.post(
        url,
        {
            "dest_node_id": "node-de",
            "allow_cross_region": True,
            "region": "DE",
            "reason": "evac",
            "operator": "julien",
        },
        format="json",
    )
    assert resp.status_code == status.HTTP_202_ACCEPTED, resp.content
    assert resp.json()["cross_region"] == {
        "from": "FR",
        "to": "DE",
        "reason": "evac",
        "operator": "julien",
    }


def test_an_automatic_failover_never_takes_the_override(settings) -> None:
    settings.VALI_FAILOVER_AUTO_ENABLED = True
    vm = make_vm(host="node-src")
    with pytest.raises(restore.RestoreError) as exc:
        restore.start_failover(
            vm=vm,
            request_id="auto-1",
            decided_by=make_service_client(),
            trigger="auto",
            cross_region=EVAC,
        )
    assert exc.value.code == "bad-request"


def test_no_automatic_path_can_carry_the_override() -> None:
    """The automatic worker, the auto drain tick, `/fail`, the price watch
    and resize have no way to pass one: none of them takes the parameter."""
    from apps.orchestration import failover_auto, resize
    from apps.scheduler import views as scheduler_views
    from apps.scheduler.management.commands import vali_price_watch

    for fn in (
        failover_auto.tick,
        failover_auto._try_one,
        resize._pick_destination,
        resize._start_migration,
        scheduler_views._replace,
        vali_price_watch.Command._suggest_dest,
    ):
        params = inspect.signature(fn).parameters
        assert "cross_region" not in params, fn
        assert not any(p.kind is inspect.Parameter.VAR_KEYWORD for p in params.values()), fn


def test_the_operator_drain_endpoint(root_client: APIClient, monkeypatch) -> None:
    from apps.scheduler import chain

    calls: list[dict] = []
    outcome: list = [0]

    def fake_enroll(**kw):
        calls.append(kw)
        if isinstance(outcome[0], Exception):
            raise outcome[0]
        kw["report"]["vm-x"] = "job-in-flight"
        return outcome[0]

    monkeypatch.setattr(service, "enroll_departing_miner_migrations", fake_enroll)
    url = reverse("miner_drain", args=["node-src"])
    body = {"allow_cross_region": True, "region": "DE", "reason": "evac", "operator": "julien"}
    resp = root_client.post(url, {"region": "DE"}, format="json")
    assert resp.status_code == status.HTTP_400_BAD_REQUEST, "region needs the override"
    outcome[0] = service.NotDeparting("c" * 64)
    resp = root_client.post(url, body, format="json")
    assert resp.status_code == status.HTTP_409_CONFLICT
    assert resp.json()["category"] == "miner-not-departing"
    outcome[0] = chain.ChainReadUnavailable("down")
    assert root_client.post(url, body, format="json").status_code == 503
    outcome[0] = 1
    resp = root_client.post(url, body, format="json")
    assert resp.status_code == status.HTTP_200_OK, resp.content
    assert resp.json() == {
        "miner_id": "node-src",
        "enrolled": 1,
        "not_moved": {"vm-x": "job-in-flight"},
    }
    assert calls[-1]["only_node"] == "c" * 64
    assert calls[-1]["cross_region"] == CrossRegion("DE", "evac", "julien")


def test_the_orchestration_tick_drains_with_no_override(monkeypatch) -> None:
    """The real tick: the drain it runs carries nothing an operator gives."""
    calls: list[dict] = []
    monkeypatch.setattr(
        service, "enroll_departing_miner_migrations", lambda **kw: calls.append(kw) or 0
    )
    service.tick_once()
    assert calls == [{}]


def test_the_operator_drain_of_a_miner_not_leaving_is_refused(monkeypatch) -> None:
    from types import SimpleNamespace

    from apps.scheduler import chain

    monkeypatch.setattr(
        chain, "read_miner_status", lambda: SimpleNamespace(miners=[], current_epoch=1)
    )
    with pytest.raises(service.NotDeparting):
        service.enroll_departing_miner_migrations(only_node="c" * 64, report={})
    MinerIdentity.objects.filter(miner_id="node-src").update(status=MinerStatus.QUARANTINED)
    assert service.enroll_departing_miner_migrations(only_node="c" * 64, report={}) == 0
