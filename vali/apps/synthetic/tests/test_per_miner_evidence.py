"""Per-miner probe — the pinned launch, the `resources` stage, and the
evidence a probe leaves: a failed start counts like a tenant's, the VM
never bills, and its shortfall corroborates as ONE tenant. (`last_probe`
on `/v1/operator/nodes` is pinned in `apps/operator/tests/test_nodes.py`.)

The launch-path claims drive the REAL `launch_on_miner` (collaborators
stubbed by `test_launch_service`) with the probe's own identity, so a
future "skip the synthetic tenant" anywhere in that path fails here.
"""

from __future__ import annotations

import hashlib
import itertools
from datetime import timedelta
from typing import Any

import pytest
from django.conf import settings
from django.test import override_settings
from django.utils import timezone

from apps.lifecycle.models import Vm
from apps.orchestration.services import launch
from apps.scheduler import capacity_earn, scoring
from apps.scheduler.capacity_admin import STRIKE_FIELD
from apps.scheduler.models import (
    CapacityTrustClass,
    MinerCapacity,
    MinerCapacityAudit,
    PlacementStatus,
)
from apps.scheduler.tests.factories import (
    make_placement,
    make_vm,
    node_id,
)
from apps.synthetic import e2e
from apps.telemetry.models import GuestResourceShortfall, VmLiveAttestation

pytestmark = pytest.mark.django_db

PROBE_VM = "synmon-pm-000000000000-1792500000"
_SEQ = itertools.count(1)


# ─── the pinned launch body ──────────────────────────────────────────


def test_the_probe_launch_is_pinned_and_attributable(blessed_ubuntu) -> None:
    body = e2e.build_launch_body("ubuntu", PROBE_VM, platform_id="ab" * 32, flavor="small")
    assert body["platform_id"] == "ab" * 32
    assert body["flavor"] == "small"
    assert body["vm_id"] == PROBE_VM
    # Owner = the synthetic tenant: what `Placement.owner` records, what
    # the reward/billing exclusion and the reaper key on.
    assert body["tenant_id"] == body["user_id"] == settings.VALI_SYNTHETIC_TENANT_ID
    # …and the authenticated second key: never paid, whatever the owner list.
    assert body["purpose"] == "probe"
    assert e2e.build_launch_body("ubuntu", "synmon-ubuntu-1")["purpose"] == "synmon"


class _Api:
    def __init__(self) -> None:
        self.bodies: list[dict] = []

    def launch(self, body: dict) -> dict:
        self.bodies.append(body)
        return {"job_id": "j1", "state": "queued"}

    def poll_launch(self, job_id: str) -> dict:
        return {"job_id": job_id, "state": "succeeded"}

    def decommission(self, vm_id: str) -> dict:
        return {"job_id": "d1"}

    def poll_decommission(self, vm_id: str, job_id: str) -> dict:
        return {"job_id": job_id, "state": "done"}


@pytest.fixture
def happy_path(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Every stage but `resources` passes; returns the order they ran in."""
    ran: list[str] = []
    monkeypatch.setattr(e2e, "_sleep", lambda *_: None)
    monkeypatch.setattr(e2e, "_await_boot_phase", lambda vm, target, d: ran.append(target) or True)
    monkeypatch.setattr(e2e, "_verify_kek_alive", lambda vm: ran.append("kek_alive") or True)
    monkeypatch.setattr(e2e, "_await_netbird", lambda vm, d: ran.append("netbird") or True)
    monkeypatch.setattr(
        e2e, "_verify_crypto_erase", lambda vm, kek_was_alive: ran.append("erase") or True
    )
    monkeypatch.setattr(e2e, "_teardown", lambda api, vm: ("clean", False))
    return ran


def _target(check: bool = True) -> e2e.Target:
    return e2e.Target(vm_id=PROBE_VM, platform_id="ab" * 32, flavor="small", check_resources=check)


def test_run_e2e_checks_resources_after_boot(
    blessed_ubuntu, happy_path: list[str], monkeypatch
) -> None:
    monkeypatch.setattr(
        e2e, "_verify_guest_resources", lambda vm, d: happy_path.append("resources") or True
    )
    api = _Api()
    outcome = e2e.run_e2e(api=api, distro="ubuntu", budget_s=60, target=_target())
    assert outcome.success and outcome.vm_id == PROBE_VM
    assert api.bodies[0]["platform_id"] == "ab" * 32
    assert happy_path == ["kek_released", "kek_alive", "running", "resources", "netbird", "erase"]
    assert [s.name for s in outcome.stages][4:6] == ["boot", "resources"]


def test_a_resource_shortfall_fails_the_probe(blessed_ubuntu, happy_path, monkeypatch) -> None:
    def short(vm: str, d: float) -> bool:
        raise e2e.ApiError("guest attested short")

    monkeypatch.setattr(e2e, "_verify_guest_resources", short)
    outcome = e2e.run_e2e(api=_Api(), distro="ubuntu", budget_s=60, target=_target())
    assert outcome.success is False
    assert outcome.stages[-1].name == "resources" and not outcome.stages[-1].ok
    assert "netbird" not in happy_path  # stops at the finding (teardown still runs)


def test_without_resource_attestation_the_stage_is_absent(
    blessed_ubuntu, happy_path, monkeypatch
) -> None:
    monkeypatch.setattr(e2e, "_verify_guest_resources", lambda vm, d: pytest.fail("checked"))
    outcome = e2e.run_e2e(api=_Api(), distro="ubuntu", budget_s=60, target=_target(False))
    assert outcome.success
    assert "resources" not in [s.name for s in outcome.stages]


def test_the_full_tier_never_checks_resources(blessed_ubuntu, happy_path, monkeypatch) -> None:
    monkeypatch.setattr(e2e, "_verify_guest_resources", lambda vm, d: pytest.fail("checked"))
    api = _Api()
    outcome = e2e.run_e2e(api=api, distro="ubuntu", budget_s=60)
    assert outcome.success and api.bodies[0]["platform_id"] == ""


# ─── `_verify_guest_resources` reads the ingest's verdict ────────────


def _live(verdict: str, *, age_s: int = 0, **figures: int) -> None:
    seq = next(_SEQ)
    at = int(timezone.now().timestamp()) - age_s
    VmLiveAttestation.objects.create(
        vm_id=PROBE_VM,
        node_id_hex="aa" * 32,
        attestation_seq=seq,
        epoch=1,
        observed_at_unix=at,
        verified_at_unix=at,
        expiry_unix=at + 600,
        measurement="ab" * 48,
        snp_report_digest="11" * 32,
        body_digest=hashlib.sha256(f"{PROBE_VM}/{seq}".encode()).hexdigest(),
        resource_verdict=verdict,
        **figures,
    )


@pytest.fixture
def fast_clock(monkeypatch: pytest.MonkeyPatch, settings: Any) -> None:
    settings.VALI_SYNTHETIC_PER_MINER_RESOURCE_TIMEOUT_S = 30
    settings.VALI_SYNTHETIC_POLL_INTERVAL_S = 10
    clock = itertools.count(0, 10)
    monkeypatch.setattr(e2e, "_now", lambda: float(next(clock)))
    monkeypatch.setattr(e2e, "_sleep", lambda *_: None)


def test_an_ok_verdict_passes(fast_clock) -> None:
    _live("ok", vcpus_online=1, mem_firmware_kib=4 * 1024 * 1024)
    assert e2e._verify_guest_resources(PROBE_VM, 1e9) is True


def test_a_short_sample_fails_even_if_a_later_one_is_ok(fast_clock) -> None:
    _live("short", age_s=120, vcpus_online=1, mem_firmware_kib=2 * 1024 * 1024)
    _live("ok")
    with pytest.raises(e2e.ApiError, match="guest attested short"):
        e2e._verify_guest_resources(PROBE_VM, 1e9)


def test_a_superseded_sample_fails(fast_clock) -> None:
    _live("superseded")
    with pytest.raises(e2e.ApiError, match="superseded"):
        e2e._verify_guest_resources(PROBE_VM, 1e9)


def test_an_unattested_guest_fails(fast_clock) -> None:
    _live("unattested")
    with pytest.raises(e2e.ApiError, match="unattested"):
        e2e._verify_guest_resources(PROBE_VM, 1e9)


def test_no_judged_sample_in_time_fails(fast_clock) -> None:
    _live("")  # an unjudged sample is not an answer
    with pytest.raises(e2e.ApiError, match="within timeout"):
        e2e._verify_guest_resources(PROBE_VM, 1e9)


# ─── a failed probe start counts exactly like a tenant's ─────────────


def _probe_spec() -> launch.LaunchSpec:
    from apps.orchestration.tests.test_launch_service import _spec

    tenant = settings.VALI_SYNTHETIC_TENANT_ID
    return _spec(
        tenant_id=tenant,
        user_id=tenant,
        vm_id=PROBE_VM,
        lease_id=f"synmon-{PROBE_VM}",
        userdata=b"#cloud-config\n# {{NETBIRD_SETUP_KEY}}\n",
    )


def _earned(seed: int, **over: Any) -> MinerCapacity:
    fields: dict[str, Any] = dict(
        miner_node_id=node_id(seed),
        status="active",
        capacity_slots=4,
        observed_epoch=10,
        data_epoch=10,
        refreshed_at=timezone.now(),
        trust_class=CapacityTrustClass.EARNED,
        earned_vms=10,
        earned_vcpus=20,
        earned_memory_mb=81920,
    )
    fields.update(over)
    return MinerCapacity.objects.create(**fields)


def _fail_the_probe_start(monkeypatch: pytest.MonkeyPatch, seed: int) -> None:
    from apps.orchestration import order_dispatch
    from apps.orchestration.tests.test_launch_service import (
        _fake_the_launch_choreography,
        _register_miner,
    )

    miner = _register_miner(seed)
    _fake_the_launch_choreography(monkeypatch, dispatch_ok=False)
    monkeypatch.setattr(
        order_dispatch,
        "dispatch_order",
        lambda *a, **k: order_dispatch.DispatchResult(
            ok=False, status=500, classifier="dispatch-failed"
        ),
    )
    launch.launch_on_miner(_probe_spec(), miner)


def test_a_failed_probe_start_feeds_every_ledger_a_tenant_failure_does(monkeypatch) -> None:
    from apps.miners.models import MinerLaunchErrors

    _earned(1)
    _fail_the_probe_start(monkeypatch, 1)
    row = MinerCapacity.objects.get(miner_node_id=node_id(1))
    assert row.cvm_fail_streak == 1  # the §23 CVM-start ledger
    assert row.earned_vms == 5  # the capacity `start-failed` halving
    assert MinerCapacityAudit.objects.filter(
        miner_node_id=node_id(1), actor="event:start-failed", reason=f"start-failed vm={PROBE_VM}"
    ).exists()
    assert MinerLaunchErrors.objects.get(miner__miner_id="miner-a").fail_streak == 1


@override_settings(VALI_CAPACITY_DECLARED_CEILING=True)
@pytest.mark.parametrize("started_before", [False, True])
def test_probation_applies_to_a_probe_failure(monkeypatch, started_before: bool) -> None:
    """At the floor a charged failure is a strike — but not before the
    host's first successful start (#1737), probe or tenant alike."""
    floors = capacity_earn._floors()
    _earned(
        1,
        earned_vms=floors["vms"],
        earned_vcpus=floors["vcpus"],
        earned_memory_mb=floors["memory_mb"],
        cvm_last_ok_at=timezone.now() - timedelta(days=1) if started_before else None,
    )
    _fail_the_probe_start(monkeypatch, 1)
    strikes = MinerCapacityAudit.objects.filter(miner_node_id=node_id(1), field=STRIKE_FIELD)
    assert strikes.exists() is started_before


# ─── never billed, never paid ────────────────────────────────────────


def test_a_probe_vm_is_excluded_from_rewards_and_billing() -> None:
    vm = make_vm(PROBE_VM, f"synmon-{PROBE_VM}")
    make_placement(
        vm,
        node_id(1),
        status=PlacementStatus.BOUND.value,
        owner=settings.VALI_SYNTHETIC_TENANT_ID,
    )
    assert PROBE_VM in scoring._excluded_vm_ids()


# ─── the shortfall corroborates as ONE independent tenant ────────────


def _short(vm_id: str, tenant: str, node: str) -> None:
    vm = make_vm(vm_id, f"lease-{vm_id}")
    Vm.objects.filter(pk=vm.pk).update(tenant_id=tenant)
    now = timezone.now()
    GuestResourceShortfall.objects.create(
        vm_id=vm_id,
        node_id_hex=node,
        flavor="small",
        want_vcpus=1,
        want_memory_mb=4096,
        vcpus_online=1,
        mem_firmware_kib=2 * 1024 * 1024,
        reason="mem-firmware",
        first_seen_at=now,
        last_seen_at=now,
        last_body_digest="ab" * 32,
    )


def test_probes_alone_never_corroborate_a_shortfall() -> None:
    synth = settings.VALI_SYNTHETIC_TENANT_ID
    _short("synmon-pm-a-1", synth, node_id(1))
    _short("synmon-pm-a-2", synth, node_id(1))
    assert capacity_earn.shortfall_incident(node_id(1), now=timezone.now()) == ""


def test_a_probe_and_one_tenant_corroborate() -> None:
    _short("synmon-pm-a-1", settings.VALI_SYNTHETIC_TENANT_ID, node_id(1))
    _short("vm-tenant", "tenant-a", node_id(1))
    incident = capacity_earn.shortfall_incident(node_id(1), now=timezone.now())
    assert incident.startswith("tenants=2 ")
