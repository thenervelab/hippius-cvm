"""The launch `purpose` marker (`orchestration.launch_purpose`): accepted
only from vali's own launchers, persisted on the job and the placements,
and every VM that carries one earns the miner NOTHING — no usage weight,
no snapshot weight, no priced bill, no capacity fill proof, no webhook to
the product backend.

Each test names the claim it defends; breaking the claim must fail it."""

from __future__ import annotations

import secrets
from typing import Any

import pytest
from django.test import override_settings
from django.utils import timezone

from apps.identity.models import PrincipalScope, ServiceClient
from apps.orchestration import launch_jobs, launch_purpose, webhook
from apps.orchestration.models import LaunchJob, LaunchJobState
from apps.scheduler import scoring
from apps.scheduler.models import Placement, PlacementStatus, UsageAccrual
from apps.scheduler.tests.factories import make_placement, make_vm, node_id, observe_chain_epoch

from .conftest import ROOT_PRINCIPAL
from .test_launch_api import LAUNCH_URL, _intent, stub_vault_put  # noqa: F401 — fixture

# Vault is stubbed for every test (intake stages userdata / the KEK).
pytestmark = [pytest.mark.django_db, pytest.mark.usefixtures("stub_vault_put")]


def _client(name: str, scope: str = PrincipalScope.OPERATOR.value) -> ServiceClient:
    tenant = "t-api" if scope == PrincipalScope.TENANT.value else ""
    return ServiceClient.objects.create(name=name, scope=scope, tenant_id=tenant)


def _start(decided_by: ServiceClient, **overrides: Any) -> LaunchJob:
    body = _intent(**overrides)
    userdata = body.pop("userdata").encode()
    return launch_jobs.start_launch(intent=body, userdata=userdata, decided_by=decided_by)


# ─── intake: who may set it ──────────────────────────────────────────


@pytest.mark.parametrize("purpose", sorted(launch_purpose.PURPOSES))
def test_root_may_mark_a_launch_and_it_is_persisted(purpose: str) -> None:
    job = _start(_client(ROOT_PRINCIPAL), purpose=purpose)
    assert job.purpose == purpose
    # On the row, never in `spec_json`: an older worker mid-roll would
    # crash on the unknown `LaunchSpec` key.
    assert "purpose" not in job.spec_json


def test_a_tenant_launch_records_no_purpose() -> None:
    job = _start(_client(ROOT_PRINCIPAL))
    assert job.purpose == ""


def test_the_disk_probe_actor_may_mark_its_launch() -> None:
    assert _start(_client("disk-probe"), purpose="probe").purpose == "probe"


@override_settings(VALI_LAUNCH_PURPOSE_PRINCIPALS=["load-tester"])
def test_an_added_internal_launcher_may_mark_its_launch() -> None:
    assert _start(_client("load-tester"), purpose="load_test").purpose == "load_test"


@pytest.mark.parametrize(
    ("name", "scope"),
    [
        ("upstream-api", PrincipalScope.OPERATOR.value),  # an operator, not ours
        (ROOT_PRINCIPAL, PrincipalScope.TENANT.value),  # the root NAME without the scope
        ("load-tester", PrincipalScope.OPERATOR.value),  # not configured
    ],
)
def test_any_other_caller_is_refused_and_stages_nothing(
    request: pytest.FixtureRequest, name: str, scope: str
) -> None:
    staged = request.getfixturevalue("stub_vault_put")
    with pytest.raises(launch_jobs.LaunchIntentError) as exc:
        _start(_client(name, scope), purpose="probe", tenant_id="t-api")
    assert exc.value.category == launch_purpose.CATEGORY_FORBIDDEN
    assert staged == []  # refused before any Vault write
    assert not LaunchJob.objects.exists()


def test_a_purpose_off_the_enum_is_refused() -> None:
    with pytest.raises(launch_jobs.LaunchIntentError) as exc:
        _start(_client(ROOT_PRINCIPAL), purpose="free-vm")
    assert exc.value.category == launch_purpose.CATEGORY_INVALID


def test_a_vms_purpose_is_fixed_by_its_first_launch() -> None:
    """A re-POST can neither clear the purpose of one of our VMs nor mark
    a tenant VM as ours — which is what lets every pay read key on "any
    launch or placement of the VM carried it"."""
    root = _client(ROOT_PRINCIPAL)
    first = _start(root, vm_id="vm-fixed", purpose="probe")
    LaunchJob.objects.filter(pk=first.pk).update(
        state=LaunchJobState.FAILED.value, finished_at=timezone.now()
    )
    for other in ("", "canary"):
        with pytest.raises(launch_jobs.LaunchIntentError) as exc:
            _start(root, vm_id="vm-fixed", purpose=other or None)
        assert exc.value.category == launch_purpose.CATEGORY_FIXED
    assert _start(root, vm_id="vm-fixed", purpose="probe").purpose == "probe"

    tenant = _start(root, vm_id="vm-tenant")
    LaunchJob.objects.filter(pk=tenant.pk).update(
        state=LaunchJobState.SUCCEEDED.value, finished_at=timezone.now()
    )
    with pytest.raises(launch_jobs.LaunchIntentError) as exc:
        _start(root, vm_id="vm-tenant", purpose="load_test")
    assert exc.value.category == launch_purpose.CATEGORY_FIXED


def test_an_existing_vm_without_a_launch_job_cannot_take_one() -> None:
    make_vm("vm-cli", "l")
    with pytest.raises(launch_jobs.LaunchIntentError) as exc:
        _start(_client(ROOT_PRINCIPAL), vm_id="vm-cli", purpose="canary")
    assert exc.value.category == launch_purpose.CATEGORY_FIXED


def test_the_worker_hands_the_jobs_purpose_to_the_launch(monkeypatch) -> None:
    from apps.orchestration.services import launch

    seen: list[str] = []

    def fake_launch_vm(spec, *a, **k):
        seen.append(spec.purpose)
        raise RuntimeError("stop here")

    monkeypatch.setattr(launch, "launch_vm", fake_launch_vm)
    monkeypatch.setattr(launch, "open_userdata_intake_copy", lambda *a, **k: b"#cloud-config\n")
    _start(_client(ROOT_PRINCIPAL), vm_id="vm-work", purpose="synmon")
    try:
        launch_jobs.tick_once()
    except Exception:  # noqa: BLE001 — only the spec handed over matters here
        pass
    assert seen == ["synmon"]


def test_http_maps_forbidden_to_403() -> None:
    from apps.orchestration.views import _launch_http_status

    assert _launch_http_status(launch_purpose.CATEGORY_FORBIDDEN) == 403
    assert _launch_http_status(launch_purpose.CATEGORY_INVALID) == 400


def test_the_api_accepts_it_from_root_and_echoes_it(root_client) -> None:
    resp = root_client.post(LAUNCH_URL, _intent(purpose="synmon"), format="json")
    assert resp.status_code == 202, resp.content
    assert resp.json()["purpose"] == "synmon"


# ─── the placement carries it ────────────────────────────────────────


def test_the_scheduled_launch_stamps_its_placement(monkeypatch) -> None:
    """`launch_vm` → the scheduler's Pending row carries the purpose."""
    from apps.orchestration.services import launch
    from apps.scheduler import chain
    from apps.scheduler.models import MinerCapacity
    from apps.scheduler.tests.factories import make_miner, make_snapshot

    from .test_launch_service import _register_miner, _spec

    MinerCapacity.objects.create(
        miner_node_id=node_id(1),
        status="active",
        capacity_slots=4,
        observed_epoch=10,
        data_epoch=10,
        refreshed_at=timezone.now(),
    )
    _register_miner(1)
    monkeypatch.setattr(chain, "read_miner_status", lambda: make_snapshot(10, [make_miner(1)]))
    monkeypatch.setattr(
        launch,
        "launch_on_miner",
        lambda spec, miner, **_k: launch.LaunchOutcome(
            disposition=launch.ACCEPTED,
            emit={"ok": True},
            exit_code=0,
            cose_ticket=b"cose",
            ticket_id="tk",
            registered=True,
        ),
    )
    result = launch.launch_vm(_spec(vm_id="vm-load-1", purpose="load_test"), _client("actor"))
    assert result.ok is True, result.emit
    assert set(Placement.objects.values_list("purpose", flat=True)) == {"load_test"}


def test_a_migrated_vm_keeps_it() -> None:
    """The row that carries the VM's reservation to a §25 destination
    copies the purpose, so the VM stays ours after it moves."""
    from apps.scheduler import service
    from apps.scheduler.tests.factories import make_service_client

    vm = make_vm("vm-carry", "l")
    row = make_placement(vm, node_id(1), status=PlacementStatus.BOUND.value)
    Placement.objects.filter(pk=row.pk).update(purpose="canary")
    moved = service.move_placement_to_node(
        vm,
        node_id=node_id(2),
        decided_by=make_service_client(),
        reason="migrated:job-x",
        release_ref="migration:job-x",
    )
    assert moved is not None and moved.purpose == "canary"


# ─── it earns NOTHING ────────────────────────────────────────────────

# A real tenant's owner: only the purpose can exclude these VMs.
TENANT_OWNER = "operator-1"


def _ours(
    vm_id: str, node: str, *, epoch: int, units: int, on: str = "placement", purpose: str = "probe"
) -> None:
    vm = make_vm(vm_id=vm_id, lease_id=f"{vm_id}-lease")
    row = make_placement(
        vm, node, status=PlacementStatus.BOUND.value, owner=TENANT_OWNER, resource_class="small"
    )
    if on == "placement":
        Placement.objects.filter(pk=row.pk).update(purpose=purpose)
    else:  # only the launch job knows (a row written by a purpose-blind path)
        LaunchJob.objects.create(
            job_id=secrets.token_hex(8),
            vm_id=vm_id,
            tenant_id="t",
            flavor="small",
            spec_json={},
            userdata_vault_path="x",
            userdata_vault_version=1,
            kek_vault_path="x",
            state=LaunchJobState.SUCCEEDED.value,
            phase_started_at=timezone.now(),
            finished_at=timezone.now(),
            purpose=purpose,
            decided_by=_client(f"actor-{vm_id}"),
        )
    UsageAccrual.objects.create(
        epoch=epoch,
        miner_node_id=node,
        vm_id=vm_id,
        resource_class="small",
        lease_id=f"{vm_id}-lease",
        unit_seconds=units,
        billable_seconds=units,
    )


def _tenant(vm_id: str, node: str, *, epoch: int, units: int) -> None:
    vm = make_vm(vm_id=vm_id, lease_id=f"{vm_id}-lease")
    make_placement(
        vm, node, status=PlacementStatus.BOUND.value, owner=TENANT_OWNER, resource_class="small"
    )
    UsageAccrual.objects.create(
        epoch=epoch,
        miner_node_id=node,
        vm_id=vm_id,
        resource_class="small",
        lease_id=f"{vm_id}-lease",
        unit_seconds=units,
        billable_seconds=units,
    )


_USAGE = override_settings(VALI_EPOCH_WEIGHT_SOURCE="usage", VALI_REWARD_EXCLUDED_OWNERS=[])


@_USAGE
@pytest.mark.parametrize("on", ["placement", "launch_job"])
def test_a_purpose_vm_earns_no_usage_weight(on: str) -> None:
    observe_chain_epoch(50)
    _ours("vm-probe", node_id(1), epoch=50, units=1_000_000, on=on)
    _tenant("vm-tenant", node_id(2), epoch=50, units=777)
    assert scoring.compute_epoch_weights() == {node_id(2): 777}


@_USAGE
def test_the_registration_load_test_earns_the_miner_nothing() -> None:
    """Julien's rule, the case that prompted it: a miner whose only VMs are
    our registration load test gets no weight and no bill."""
    observe_chain_epoch(50)
    for i in range(3):
        _ours(f"vm-load-{i}", node_id(1), epoch=50, units=10_000_000, purpose="load_test")
    assert scoring.compute_epoch_weights() == {}
    assert scoring.compute_owed_micro_usd({node_id(1): 5_000_000}) == {}


@_USAGE
def test_a_purpose_vm_is_never_billed() -> None:
    observe_chain_epoch(50)
    _ours("vm-canary", node_id(1), epoch=50, units=3_600_000, purpose="canary")
    _tenant("vm-tenant", node_id(1), epoch=50, units=3_600_000)
    assert scoring._billable_usage_rows(50) == [(node_id(1), 3_600_000)]  # the tenant's only
    with_probe = scoring.compute_owed_micro_usd({node_id(1): 5_000_000})[node_id(1)]
    UsageAccrual.objects.filter(vm_id="vm-canary").delete()
    assert scoring.compute_owed_micro_usd({node_id(1): 5_000_000})[node_id(1)] == with_probe


@override_settings(VALI_EPOCH_WEIGHT_SOURCE="snapshot", VALI_REWARD_EXCLUDED_OWNERS=[])
def test_a_purpose_vm_earns_no_snapshot_weight() -> None:
    observe_chain_epoch(50)
    _ours("vm-probe", node_id(1), epoch=50, units=1)
    _tenant("vm-tenant", node_id(2), epoch=50, units=1)
    assert set(scoring._snapshot_weights()) == {node_id(2)}


@override_settings(VALI_EPOCH_WEIGHT_SOURCE="snapshot", VALI_REWARD_EXCLUDED_OWNERS=[])
def test_a_purpose_blind_replacement_row_is_still_ours() -> None:
    """A row written by a path that does not copy the purpose (e.g. the
    root `/v1/scheduler/place`) is still excluded: the VM's EARLIER row
    carried it."""
    observe_chain_epoch(50)
    _ours("vm-probe", node_id(1), epoch=50, units=1)
    old = Placement.objects.get(vm__vm_id="vm-probe")
    Placement.objects.filter(pk=old.pk).update(
        status=PlacementStatus.FAILED.value,
        reason="seed",
        failure_source="manual",
        failed_at=timezone.now(),
    )
    make_placement(old.vm, node_id(3), status=PlacementStatus.BOUND.value, owner=TENANT_OWNER)
    assert scoring._snapshot_weights() == {}


def test_a_purpose_launch_never_reaches_the_backend(settings) -> None:
    settings.VALI_WEBHOOK_URL = "https://backend.example/hook"
    settings.VALI_WEBHOOK_SECRET = "s"
    _ours("vm-probe", node_id(1), epoch=1, units=1, on="launch_job")
    job = LaunchJob.objects.get(vm_id="vm-probe")
    assert webhook.enqueue_launch_terminal(job) is None
    LaunchJob.objects.filter(pk=job.pk).update(purpose="")
    job.refresh_from_db()
    assert webhook.enqueue_launch_terminal(job) is not None  # a tenant's still goes


def test_the_disk_probe_marks_its_launch_with_its_own_actor() -> None:
    """The disk-tier probe's intent names `purpose: probe`, and its actor
    is one the intake accepts it from."""
    from types import SimpleNamespace

    from apps.disktier import probe
    from apps.disktier.probe_owners import ProbeOwner

    run = SimpleNamespace(
        vm_id="hipc-4242-0a0b0c0d", flavor="medium", chip_id="ab" * 32, os_pool_id="default"
    )
    intent = probe.launch_intent(run, ProbeOwner(user_id="4242", tenant_id="5" * 48))
    assert intent["purpose"] == launch_purpose.PROBE
    assert probe.ACTOR_NAME in launch_purpose.allowed_principals()


def test_the_purpose_is_rechecked_inside_the_insert_transaction(monkeypatch) -> None:
    """The intake check and the insert are apart (Vault staging between):
    a launch of the VM that turned terminal in between is seen by the
    in-transaction recheck."""
    root = _client(ROOT_PRINCIPAL)
    real = launch_purpose.check_fixed
    calls: list[int] = []

    def racing(vm_id, purpose, existing):
        calls.append(1)
        if len(calls) == 2:  # between the two checks, a tenant launch lands
            LaunchJob.objects.create(
                job_id=secrets.token_hex(8),
                vm_id=vm_id,
                tenant_id="t",
                flavor="small",
                spec_json={},
                userdata_vault_path="x",
                userdata_vault_version=1,
                kek_vault_path="x",
                state=LaunchJobState.FAILED.value,
                phase_started_at=timezone.now(),
                finished_at=timezone.now(),
                decided_by=root,
            )
        return real(vm_id, purpose, existing)

    monkeypatch.setattr(launch_purpose, "check_fixed", racing)
    with pytest.raises(launch_jobs.LaunchIntentError) as exc:
        _start(root, vm_id="vm-race", purpose="probe")
    assert exc.value.category == launch_purpose.CATEGORY_FIXED
    assert len(calls) == 2
    assert not LaunchJob.objects.filter(vm_id="vm-race", purpose="probe").exists()


def test_the_extra_launchers_come_from_the_environment() -> None:
    from django.conf import settings

    assert settings.VALI_LAUNCH_PURPOSE_PRINCIPALS == []
