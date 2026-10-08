"""The CDN fleet reconciler (CDN plan V3)."""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass, field
from typing import Any
from unittest import mock

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from django.conf import settings
from django.utils import timezone

from apps.images.models import GoldenImage
from apps.lifecycle.models import Vm, VmBootPhase, VmPowerState, VmState
from apps.network.models import IngressEdge, PublicIP, PublicIpPool, PublicIpState
from apps.orchestration.models import DecommissionJob, LaunchJob
from apps.orchestration.tests.factories import make_service_client

from .. import ca, fleet, reconcile, userdata
from ..models import (
    CdnFleetKey,
    CdnFleetKeyState,
    CdnNode,
    CdnNodeState,
    CdnRegion,
    CdnRevision,
    DrainReason,
)
from .conftest import CDN_TENANT, PREFIX, FakeTransit, raw_public

pytestmark = pytest.mark.django_db

BAKE = "gb-cdn-1"


@pytest.fixture(autouse=True)
def _fleet_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "VALI_CDN_RECONCILE_ENABLED", True)
    monkeypatch.setattr(settings, "VALI_CDN_LAUNCH_ROLE", True)
    monkeypatch.setattr(settings, "VALI_CDN_BACKEND_URL", "https://api.example.test")
    monkeypatch.setattr(settings, "VALI_CDN_IMAGE_NAME", "cdn-node")
    CdnFleetKey.objects.create(
        version=1,
        x25519_public=b"\x01" * 32,
        kbs_kid_hex="ab",
        kbs_signature=b"\x02" * 64,
        state=CdnFleetKeyState.ACTIVE,
    )
    GoldenImage.objects.create(
        image_name="cdn-node",
        distro="debian",
        bake_id=BAKE,
        blessed_at=timezone.now(),
        restricted_tenant=CDN_TENANT,
    )


@dataclass
class Fleet:
    """Fakes for the launch and the address pool; the CA is the real one
    over the fake Transit."""

    transit: FakeTransit
    launches: list[dict[str, Any]] = field(default_factory=list)
    refuse_launch: str = ""
    no_address: bool = False
    _ips: int = 0

    def start_launch(
        self, *, intent: dict[str, Any], userdata: bytes, decided_by: Any, cdn_node: bool = False
    ) -> LaunchJob:
        from apps.orchestration.launch_jobs import LaunchIntentError

        if self.refuse_launch:
            raise LaunchIntentError(self.refuse_launch, "no-eligible-miner")
        self.launches.append({"intent": intent, "userdata": userdata, "cdn_node": cdn_node})
        now = timezone.now()
        return LaunchJob.objects.create(
            job_id=f"lj-{intent['vm_id']}",
            vm_id=intent["vm_id"],
            tenant_id=intent["tenant_id"],
            flavor=intent["flavor"],
            spec_json=intent,
            userdata_vault_path="x",
            userdata_vault_version=1,
            kek_vault_path="x",
            state="queued",
            phase_started_at=now,
            decided_by=make_service_client(),
        )

    def attach_cdn(self, vm: Vm) -> tuple[PublicIP, bool]:
        from apps.network.service import NetworkError

        if self.no_address:
            raise NetworkError("no-free-public-ip", "none")
        region = CdnNode.objects.get(vm=vm).region
        edge = IngressEdge.objects.filter(region=region).first() or IngressEdge.objects.create(
            name=f"edge-{region.lower()}",
            region=region,
            netbird_ip=f"100.90.0.{IngressEdge.objects.count() + 1}",
        )
        self._ips += 1
        ip = PublicIP.objects.create(
            edge=edge,
            address=f"203.0.113.{self._ips}",
            vm=vm,
            state=PublicIpState.ATTACHED,
            target_ip=vm.netbird_ip or None,
            pool=PublicIpPool.CDN,
            cap_mbps=2000,
            attached_at=timezone.now(),
        )
        return ip, True

    def finish(
        self,
        node_id: str,
        *,
        ok: bool = True,
        alive: bool = True,
        host: str = "miner-a",
        outcome: str = "no-eligible-miner",
    ) -> Vm | None:
        """The launch worker's end of a node's launch."""
        job = LaunchJob.objects.get(vm_id=node_id)
        if not ok:
            LaunchJob.objects.filter(pk=job.pk).update(
                state="failed", result_json={"outcome": outcome}, finished_at=timezone.now()
            )
            return None
        seed = Ed25519PrivateKey.generate().private_bytes_raw()
        self.transit.kv[f"{PREFIX}/{node_id}/lifecycle-key"] = seed
        vm = Vm.objects.create(
            vm_id=node_id,
            lease_id=f"cdn-{node_id}",
            tenant_id=CDN_TENANT,
            state=VmState.ACTIVE,
            generation=1,
            host=host,
            lifecycle_vk=raw_public(Ed25519PrivateKey.from_private_bytes(seed)),
            boot_phase=VmBootPhase.RUNNING,
            netbird_ip=f"100.64.3.{Vm.objects.count() + 1}",
            guest_signal_at=timezone.now() if alive else None,
            guest_signal_kind="live_attestation",
        )
        CdnNode.objects.filter(node_id=node_id).update(vm=vm)
        LaunchJob.objects.filter(pk=job.pk).update(state="succeeded", finished_at=timezone.now())
        return vm


@pytest.fixture
def fleet_fakes(fake_transit: FakeTransit, monkeypatch: pytest.MonkeyPatch) -> Fleet:
    from apps.network import service as network_service
    from apps.orchestration import launch_jobs

    f = Fleet(transit=fake_transit)
    # Autospecced: a fake whose signature drifts from the real one would
    # hide a call the real one refuses.
    monkeypatch.setattr(
        launch_jobs,
        "start_launch",
        mock.create_autospec(launch_jobs.start_launch, side_effect=f.start_launch),
    )
    monkeypatch.setattr(
        network_service,
        "attach_cdn",
        mock.create_autospec(network_service.attach_cdn, side_effect=f.attach_cdn),
    )
    ca.init_ca()
    return f


def _region(region: str = "FR", *, desired: int = 1, active: bool = True) -> CdnRegion:
    return CdnRegion.objects.create(region=region, desired_nodes=desired, active=active)


def _tick(at: dt.datetime | None = None) -> reconcile.ReconcileReport:
    """One pass at `at`. Guests that are answering keep answering: their
    signal moves with the clock (a test makes one go quiet explicitly)."""
    now = timezone.now()
    at = at or now
    Vm.objects.filter(guest_signal_at__gte=now - dt.timedelta(seconds=120)).update(
        guest_signal_at=at
    )
    return reconcile.reconcile(now=at)


def _later(**kw: float) -> dt.datetime:
    return timezone.now() + dt.timedelta(**kw)


def _nodes(**filters: Any) -> list[CdnNode]:
    return list(CdnNode.objects.filter(**filters).order_by("created_at"))


def _ready_node(f: Fleet, region: str = "FR", **finish: Any) -> CdnNode:
    """Launch, finish and ready one node in `region`'s current target."""
    _tick()
    node = _nodes(region=region, state=CdnNodeState.LAUNCHING)[-1]
    f.finish(node.node_id, **finish)
    _tick()  # → booting
    _tick()  # → ready
    node.refresh_from_db()
    assert node.state == CdnNodeState.READY, node.failure_reason
    return node


# ── inertness ──────────────────────────────────────────────────────────


@pytest.mark.parametrize("flag", ["VALI_CDN_ENABLED", "VALI_CDN_RECONCILE_ENABLED"])
def test_inert_while_off(fleet_fakes: Fleet, monkeypatch: pytest.MonkeyPatch, flag: str) -> None:
    _region(desired=2)
    monkeypatch.setattr(settings, flag, False)
    assert _tick() == reconcile.ReconcileReport()
    assert not CdnNode.objects.exists() and fleet_fakes.launches == []


def test_an_inactive_region_launches_nothing(fleet_fakes: Fleet) -> None:
    _region(desired=2, active=False)
    _tick()
    assert fleet_fakes.launches == []


# ── launch ─────────────────────────────────────────────────────────────


def test_launch_intent(fleet_fakes: Fleet) -> None:
    _region(desired=1)
    assert _tick().launched == 1
    [node] = _nodes()
    [launch] = fleet_fakes.launches
    assert launch["cdn_node"] is True
    assert launch["userdata"] == userdata.render(node.node_id, "FR")
    intent = launch["intent"]
    assert intent == {
        "tenant_id": CDN_TENANT,
        "user_id": CDN_TENANT,
        "vm_id": node.node_id,
        "lease_id": f"cdn-{node.node_id}",
        "flavor": "xlarge",
        "cmdline": settings.VALI_CDN_CMDLINE,
        "image": "cdn-node",
        "region": "FR",
        "platform_id": "",
        "enable_netbird": True,
        "auto_pin_allowlist": True,
    }
    assert node.node_id.startswith("cdn-fr-") and node.state == CdnNodeState.LAUNCHING
    assert node.bake_id == BAKE and node.launch_job_id == f"lj-{node.node_id}"


def test_launches_one_at_a_time_per_region(fleet_fakes: Fleet) -> None:
    _region(desired=3)
    _region("AU", desired=1)
    _tick()
    _tick()
    assert len(_nodes(region="FR")) == 1 and len(_nodes(region="AU")) == 1


def test_no_launch_without_a_fleet_key(fleet_fakes: Fleet) -> None:
    CdnFleetKey.objects.all().delete()
    _region(desired=1)
    _tick()
    assert fleet_fakes.launches == [] and not CdnNode.objects.exists()


def test_no_launch_without_a_blessed_image(fleet_fakes: Fleet) -> None:
    GoldenImage.objects.all().delete()
    _region(desired=1)
    _tick()
    assert fleet_fakes.launches == []


def test_the_happy_path(fleet_fakes: Fleet) -> None:
    _region(desired=1)
    before = CdnRevision.current()
    node = _ready_node(fleet_fakes)
    assert node.ready_at is not None and node.cert_pem and node.cert_generation == 1
    assert PublicIP.objects.get(vm__vm_id=node.node_id).pool == PublicIpPool.CDN
    assert CdnRevision.current() > before
    _tick()
    assert len(_nodes()) == 1, "the region is at its target"


@pytest.mark.parametrize("missing", ["liveness", "address", "cert"])
def test_not_ready_until_everything_is_there(fleet_fakes: Fleet, missing: str) -> None:
    _region(desired=1)
    _tick()
    [node] = _nodes()
    fleet_fakes.no_address = missing == "address"
    if missing == "cert":
        fleet_fakes.finish(node.node_id)
        fleet_fakes.transit.kv.clear()  # no lifecycle seed: no certificate
    else:
        fleet_fakes.finish(node.node_id, alive=missing != "liveness")
    _tick()
    _tick()
    node.refresh_from_db()
    assert node.state == CdnNodeState.BOOTING


def test_boot_timeout_fails_and_decommissions(fleet_fakes: Fleet) -> None:
    _region(desired=1)
    _tick()
    [node] = _nodes()
    fleet_fakes.finish(node.node_id, alive=False)
    _tick()
    _tick(_later(seconds=settings.VALI_CDN_BOOT_TIMEOUT_S + 5))
    node.refresh_from_db()
    assert node.state == CdnNodeState.FAILED and node.failure_reason == "boot-timeout"
    # Never ready, so never in DNS: decommissioned without an ack.
    _tick(_later(seconds=settings.VALI_CDN_BOOT_TIMEOUT_S + 10))
    node.refresh_from_db()
    assert node.state == CdnNodeState.DECOMMISSIONING
    assert DecommissionJob.objects.filter(vm__vm_id=node.node_id).exists()


def test_a_failed_launch_backs_off(fleet_fakes: Fleet) -> None:
    _region(desired=1)
    _tick()
    [node] = _nodes()
    fleet_fakes.finish(node.node_id, ok=False)
    _tick()
    node.refresh_from_db()
    assert node.state in (CdnNodeState.FAILED, CdnNodeState.DESTROYED)
    _tick()
    node.refresh_from_db()
    assert node.state == CdnNodeState.DESTROYED
    assert len(fleet_fakes.launches) == 1, "the backoff holds the next launch"
    _tick(_later(seconds=settings.VALI_CDN_LAUNCH_BACKOFF_S + 5))
    assert len(fleet_fakes.launches) == 2


def test_a_refused_launch_leaves_no_node_and_backs_off(fleet_fakes: Fleet) -> None:
    region = _region(desired=1)
    fleet_fakes.refuse_launch = "nope"
    _tick()
    assert _nodes() == []
    region.refresh_from_db()
    assert region.launch_failures == 1 and region.launch_failed_at is not None
    fleet_fakes.refuse_launch = ""
    _tick()
    assert _nodes() == []
    _tick(_later(seconds=settings.VALI_CDN_LAUNCH_BACKOFF_S + 5))
    assert len(_nodes()) == 1


def test_a_failure_after_launch_backs_off_too(fleet_fakes: Fleet) -> None:
    """A host that kills the guest after boot must not loop launches."""
    _region(desired=1)
    _tick()
    [node] = _nodes()
    fleet_fakes.finish(node.node_id)
    _tick()
    Vm.objects.filter(vm_id=node.node_id).update(power_state=VmPowerState.STOPPED)
    _tick()
    node.refresh_from_db()
    assert node.state in (CdnNodeState.FAILED, CdnNodeState.DECOMMISSIONING)
    assert len(fleet_fakes.launches) == 1
    _tick(_later(seconds=settings.VALI_CDN_LAUNCH_BACKOFF_S + 5))
    assert len(fleet_fakes.launches) == 2


def test_a_ready_node_resets_the_failure_count(fleet_fakes: Fleet) -> None:
    region = _region(desired=1)
    CdnRegion.objects.filter(pk=region.pk).update(launch_failures=4)
    _ready_node(fleet_fakes)
    region.refresh_from_db()
    assert region.launch_failures == 0


# ── drain: never decommission before dns-released ──────────────────────


def test_drain_never_decommissions_without_the_ack(
    fleet_fakes: Fleet, monkeypatch: pytest.MonkeyPatch
) -> None:
    region = _region(desired=1)
    node = _ready_node(fleet_fakes)
    region.desired_nodes = 0
    region.save()
    _tick()
    node.refresh_from_db()
    assert node.state == CdnNodeState.DRAINING and node.drain_reason == DrainReason.SCALE_DOWN

    errors: list[str] = []
    monkeypatch.setattr(reconcile.log, "error", lambda msg, *a, **k: errors.append(msg % a))
    for hours in (1, 5, 48):
        _tick(_later(hours=hours))
    node.refresh_from_db()
    assert node.state == CdnNodeState.DRAINING
    assert not DecommissionJob.objects.exists()
    alerts = [e for e in errors if "is NOT decommissioned without it" in e]
    assert len(alerts) == 1, "alerted once, never acted"

    CdnNode.objects.filter(pk=node.pk).update(dns_released_at=timezone.now())
    _tick(_later(seconds=settings.VALI_CDN_DRAIN_GRACE_S - 30))
    node.refresh_from_db()
    assert node.state == CdnNodeState.DRAINING, "the grace is not over"
    _tick(_later(seconds=settings.VALI_CDN_DRAIN_GRACE_S + 5))
    _tick(_later(seconds=settings.VALI_CDN_DRAIN_GRACE_S + 10))
    node.refresh_from_db()
    assert node.state == CdnNodeState.DECOMMISSIONING
    assert DecommissionJob.objects.filter(vm__vm_id=node.node_id).exists()


def test_the_decommission_refuses_a_ready_node_without_the_ack(fleet_fakes: Fleet) -> None:
    """The gate holds even if a node reached `drained` some other way."""
    from django.db import IntegrityError, transaction

    _region(desired=1)
    node = _ready_node(fleet_fakes)
    with pytest.raises(IntegrityError), transaction.atomic():
        CdnNode.objects.filter(pk=node.pk).update(state=CdnNodeState.DRAINED)
    reconcile._decommission(node, report=reconcile.ReconcileReport())
    assert not DecommissionJob.objects.exists()


def test_a_drained_node_whose_vm_is_destroyed_is_destroyed(fleet_fakes: Fleet) -> None:
    region = _region(desired=1)
    node = _ready_node(fleet_fakes)
    region.desired_nodes = 0
    region.save()
    _tick()
    CdnNode.objects.filter(pk=node.pk).update(dns_released_at=timezone.now())
    _tick(_later(seconds=300))
    _tick(_later(seconds=310))
    Vm.objects.filter(vm_id=node.node_id).update(state=VmState.DESTROYED)
    _tick(_later(seconds=400))
    node.refresh_from_db()
    assert node.state == CdnNodeState.DESTROYED


# ── replacement ────────────────────────────────────────────────────────


def test_replace_before_drain(fleet_fakes: Fleet) -> None:
    _region(desired=1)
    old = _ready_node(fleet_fakes)
    reconcile.request_drain(old.node_id, DrainReason.OPERATOR)
    _tick()
    old.refresh_from_db()
    assert old.state == CdnNodeState.READY, "keeps serving until replaced"
    [new] = _nodes(state=CdnNodeState.LAUNCHING)
    fleet_fakes.finish(new.node_id, host="miner-b")
    _tick()
    _tick()
    new.refresh_from_db()
    assert new.state == CdnNodeState.READY
    _tick()
    old.refresh_from_db()
    assert old.state == CdnNodeState.READY, "the replacement has not settled"
    _tick(_later(seconds=settings.VALI_CDN_READY_SETTLE_S + 5))
    old.refresh_from_db()
    assert old.state == CdnNodeState.DRAINING
    assert not DecommissionJob.objects.exists()


def test_without_a_spare_host_the_node_drains_first(fleet_fakes: Fleet) -> None:
    """One host, one node (AU): the replacement cannot be placed, so the old
    node drains and the region fails over while it is swapped."""
    _region("AU", desired=1)
    old = _ready_node(fleet_fakes, region="AU")
    reconcile.request_drain(old.node_id, DrainReason.UPGRADE)
    _tick()
    [new] = _nodes(state=CdnNodeState.LAUNCHING)
    fleet_fakes.finish(new.node_id, ok=False)
    _tick()
    _tick()
    old.refresh_from_db()
    assert old.state == CdnNodeState.DRAINING


def test_a_wedged_node_fails_and_is_replaced(fleet_fakes: Fleet) -> None:
    _region(desired=1)
    node = _ready_node(fleet_fakes)
    stale = timezone.now() - dt.timedelta(seconds=3600)
    Vm.objects.filter(vm_id=node.node_id).update(guest_signal_at=stale)
    _tick()
    node.refresh_from_db()
    assert node.state == CdnNodeState.FAILED and node.failure_reason.startswith("wedged")
    assert len(_nodes(state=CdnNodeState.LAUNCHING)) == 1, "replaced"
    # It was ready, so it waits for the ack like a drain.
    _tick(_later(hours=2))
    node.refresh_from_db()
    assert node.state == CdnNodeState.FAILED
    assert not DecommissionJob.objects.filter(vm__vm_id=node.node_id).exists()


@pytest.mark.parametrize("power", [VmPowerState.STOPPED, VmPowerState.STOPPING])
def test_a_stopped_node_fails(fleet_fakes: Fleet, power: str) -> None:
    _region(desired=1)
    node = _ready_node(fleet_fakes)
    Vm.objects.filter(vm_id=node.node_id).update(power_state=power)
    _tick()
    node.refresh_from_db()
    assert node.state == CdnNodeState.FAILED


def test_a_booting_node_asked_to_drain_goes_without_dns(fleet_fakes: Fleet) -> None:
    region = _region(desired=1)
    _tick()
    [node] = _nodes()
    region.desired_nodes = 0
    region.save()
    _tick()
    fleet_fakes.finish(node.node_id, alive=False)
    _tick()
    _tick()
    node.refresh_from_db()
    assert node.state == CdnNodeState.DECOMMISSIONING and node.ready_at is None


# ── upgrade and rotation ───────────────────────────────────────────────


def test_upgrade_one_node_at_a_time(fleet_fakes: Fleet) -> None:
    _region(desired=2)
    a = _ready_node(fleet_fakes)
    b = _ready_node(fleet_fakes, host="miner-b")
    GoldenImage.objects.filter(image_name="cdn-node").update(bake_id="gb-cdn-2")
    _tick(_later(seconds=settings.VALI_CDN_READY_SETTLE_S + 5))
    asked = _nodes(drain_requested_at__isnull=False)
    assert [n.node_id for n in asked] == [a.node_id]
    assert asked[0].drain_reason == DrainReason.UPGRADE
    _tick(_later(seconds=settings.VALI_CDN_READY_SETTLE_S + 10))
    assert len(_nodes(drain_requested_at__isnull=False)) == 1
    b.refresh_from_db()
    assert b.drain_requested_at is None
    new = _nodes(state=CdnNodeState.LAUNCHING)
    assert len(new) == 1 and new[0].bake_id == "gb-cdn-2"


def test_rotation_replaces_older_nodes_then_activates(fleet_fakes: Fleet) -> None:
    _region(desired=1)
    old = _ready_node(fleet_fakes)
    key = fleet.record(
        fleet.SignedFleetKey(
            version=2, x25519_public=b"\x03" * 32, kbs_kid_hex="ab", kbs_signature=b"\x02" * 64
        )
    )
    CdnFleetKey.objects.filter(pk=key.pk).update(created_at=timezone.now())
    later = _later(seconds=settings.VALI_CDN_READY_SETTLE_S + 5)
    _tick(later)
    old.refresh_from_db()
    assert old.drain_reason == DrainReason.ROTATE
    assert CdnFleetKey.objects.get(version=2).state == CdnFleetKeyState.PENDING
    [new] = _nodes(state=CdnNodeState.LAUNCHING)
    fleet_fakes.finish(new.node_id, host="miner-b")
    _tick(later)
    _tick(later)
    new.refresh_from_db()
    assert new.state == CdnNodeState.READY
    _tick(later + dt.timedelta(seconds=settings.VALI_CDN_READY_SETTLE_S + 5))
    old.refresh_from_db()
    assert old.state == CdnNodeState.DRAINING
    # The old node is still live (draining): the key waits for it to go.
    assert CdnFleetKey.objects.get(version=2).state == CdnFleetKeyState.PENDING
    CdnNode.objects.filter(pk=old.pk).update(state=CdnNodeState.DESTROYED)
    _tick(later + dt.timedelta(seconds=settings.VALI_CDN_READY_SETTLE_S + 10))
    assert CdnFleetKey.objects.get(version=2).state == CdnFleetKeyState.ACTIVE
    assert CdnFleetKey.objects.get(version=1).state == CdnFleetKeyState.RETIRING


# ── isolation ──────────────────────────────────────────────────────────


def test_one_node_failing_does_not_stop_the_others(
    fleet_fakes: Fleet, monkeypatch: pytest.MonkeyPatch
) -> None:
    _region(desired=1)
    _region("AU", desired=1)
    _tick()
    real = reconcile._advance_launching

    def boom(node: CdnNode, **kw: Any) -> None:
        if node.region == "FR":
            raise RuntimeError("boom")
        real(node, **kw)

    monkeypatch.setattr(reconcile, "_advance_launching", boom)
    au = _nodes(region="AU")[0]
    fleet_fakes.finish(au.node_id)
    _tick()
    au.refresh_from_db()
    assert au.state == CdnNodeState.BOOTING


def test_the_tick_runs_the_reconciler_and_survives_it(monkeypatch: pytest.MonkeyPatch) -> None:
    from apps.orchestration import service

    calls: list[int] = []
    monkeypatch.setattr(reconcile, "reconcile", lambda: calls.append(1))
    service.tick_once()
    assert calls == [1]

    def boom() -> None:
        raise RuntimeError("boom")

    monkeypatch.setattr(reconcile, "reconcile", boom)
    service.tick_once()


def test_reboot_recovery_never_relaunches_a_cdn_node(
    fleet_fakes: Fleet, monkeypatch: pytest.MonkeyPatch
) -> None:
    from apps.orchestration import effects, service

    _region(desired=1)
    node = _ready_node(fleet_fakes)

    def probed(*a: Any, **k: Any) -> bool:
        raise AssertionError("a CDN VM is never probed for a relaunch")

    monkeypatch.setattr(effects, "_bound_miner_id", probed)
    vm = Vm.objects.get(vm_id=node.node_id)
    assert service._reboot_recovery_step(vm, now=timezone.now(), cutoff=timezone.now()) is False


# ── liveness breaker, reboot, certificates, flavor, network revision ───


def test_a_fleet_wide_silence_fails_no_node(
    fleet_fakes: Fleet, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Telemetry stopping for every node at once is not a fleet of dead
    nodes: failing them would pull every DNS record."""
    _region(desired=2)
    a = _ready_node(fleet_fakes)
    b = _ready_node(fleet_fakes, host="miner-b")
    errors: list[str] = []
    monkeypatch.setattr(reconcile.log, "error", lambda msg, *a, **k: errors.append(msg % a))
    stale = timezone.now() - dt.timedelta(hours=1)
    _tenant_vm("tenant-vm-1", signal_at=stale)
    Vm.objects.filter(vm_id__in=[a.node_id, b.node_id]).update(guest_signal_at=stale)
    _tick()
    for n in (a, b):
        n.refresh_from_db()
        assert n.state == CdnNodeState.READY
    assert any("holding the CDN liveness replacement" in e for e in errors)


def _tenant_vm(vm_id: str, *, signal_at: dt.datetime) -> Vm:
    return Vm.objects.create(
        vm_id=vm_id,
        lease_id=f"lease-{vm_id}",
        tenant_id="tenant-a",
        state=VmState.ACTIVE,
        generation=1,
        host="miner-t",
        lifecycle_vk=bytes(32),
        boot_phase=VmBootPhase.RUNNING,
        guest_signal_at=signal_at,
        guest_signal_kind="served_receipt",
    )


def test_quiet_nodes_among_live_tenants_fail(fleet_fakes: Fleet) -> None:
    """Tenants still signal, so telemetry works: the quiet nodes are dead
    (one region's datacentre, say) and are replaced."""
    _region(desired=2)
    a = _ready_node(fleet_fakes)
    b = _ready_node(fleet_fakes, host="miner-b")
    for i in range(3):
        _tenant_vm(f"tenant-vm-{i}", signal_at=timezone.now())
    stale = timezone.now() - dt.timedelta(hours=1)
    Vm.objects.filter(vm_id__in=[a.node_id, b.node_id]).update(guest_signal_at=stale)
    _tick()
    for n in (a, b):
        n.refresh_from_db()
        assert n.state == CdnNodeState.FAILED


@pytest.mark.parametrize("gone", ["departing", "unseen"])
def test_a_node_whose_host_is_gone_fails_even_when_the_breaker_holds(
    fleet_fakes: Fleet, gone: str
) -> None:
    from apps.miners.models import MinerIdentity, MinerStatus

    _region(desired=2)
    a = _ready_node(fleet_fakes)
    b = _ready_node(fleet_fakes, host="miner-b")
    MinerIdentity.objects.create(
        miner_id="miner-a",
        pubkey_hex="aa" * 32,
        platform_id="cd" * 16,
        status=MinerStatus.QUARANTINED if gone == "departing" else MinerStatus.ACTIVE,
        last_seen_at=timezone.now() - dt.timedelta(hours=3 if gone == "unseen" else 0),
    )
    stale = timezone.now() - dt.timedelta(hours=1)
    _tenant_vm("tenant-vm-1", signal_at=stale)
    Vm.objects.filter(vm_id__in=[a.node_id, b.node_id]).update(guest_signal_at=stale)
    _tick()
    a.refresh_from_db()
    b.refresh_from_db()
    assert a.state == CdnNodeState.FAILED and a.failure_reason.startswith("host-")
    assert b.state == CdnNodeState.READY, "held: telemetry looks down"


def test_cdn_nodes_never_take_a_guest_upgrade(
    fleet_fakes: Fleet, monkeypatch: pytest.MonkeyPatch
) -> None:
    from apps.orchestration import guest_rollout, guest_upgrade

    monkeypatch.setattr(guest_upgrade, "_c2_enforced", lambda: True)

    _region(desired=1)
    node = _ready_node(fleet_fakes)
    _tenant_vm("tenant-vm-1", signal_at=timezone.now())
    vm_ids = [vm.vm_id for vm in guest_rollout.scope_vms({"tenant_ids": [CDN_TENANT, "tenant-a"]})]
    assert vm_ids == ["tenant-vm-1"]
    vm = Vm.objects.get(vm_id=node.node_id)
    refusal = guest_upgrade._refusal(vm, mock.Mock(), rollback=False)
    assert refusal is not None and refusal[0] == "cdn-node"


def _attest(vm_id: str, at: dt.datetime, report_id: str) -> None:
    import hashlib

    from apps.telemetry.models import VmLiveAttestation

    unix = int(at.timestamp())
    VmLiveAttestation.objects.create(
        vm_id=vm_id,
        node_id_hex="aa" * 32,
        attestation_seq=unix,
        epoch=1,
        observed_at_unix=unix,
        verified_at_unix=unix,
        expiry_unix=unix + 900,
        measurement="ab" * 48,
        snp_report_digest="11" * 32,
        body_digest=hashlib.sha256(f"{vm_id}/{unix}/{report_id}".encode()).hexdigest(),
        report_id=report_id,
    )


def test_a_rebooted_node_is_replaced(fleet_fakes: Fleet) -> None:
    _region(desired=1)
    node = _ready_node(fleet_fakes)
    _attest(node.node_id, node.ready_at - dt.timedelta(seconds=30), "aa" * 32)
    _attest(node.node_id, node.ready_at + dt.timedelta(seconds=60), "aa" * 32)
    _tick()
    node.refresh_from_db()
    assert node.state == CdnNodeState.READY, "same boot"
    _attest(node.node_id, node.ready_at + dt.timedelta(seconds=120), "bb" * 32)
    _tick()
    node.refresh_from_db()
    assert node.state == CdnNodeState.FAILED and node.failure_reason == "rebooted"
    assert len(_nodes(state=CdnNodeState.LAUNCHING)) == 1


def test_a_draining_node_keeps_a_valid_certificate(fleet_fakes: Fleet) -> None:
    region = _region(desired=1)
    node = _ready_node(fleet_fakes)
    region.desired_nodes = 0
    region.save()
    _tick()
    first = CdnNode.objects.get(pk=node.pk).cert_serial
    _tick(_later(days=6))
    node.refresh_from_db()
    assert node.state == CdnNodeState.DRAINING
    assert node.cert_serial != first and node.cert_not_after > _later(days=12)


def test_a_flavor_change_replaces_one_node(fleet_fakes: Fleet) -> None:
    region = _region(desired=1)
    node = _ready_node(fleet_fakes)
    CdnRegion.objects.filter(pk=region.pk).update(flavor="2xlarge")
    _tick(_later(seconds=settings.VALI_CDN_READY_SETTLE_S + 5))
    node.refresh_from_db()
    assert node.drain_reason == DrainReason.UPGRADE
    [new] = _nodes(state=CdnNodeState.LAUNCHING)
    assert new.flavor == "2xlarge"


def test_a_network_change_bumps_the_revision(fleet_fakes: Fleet) -> None:
    _region(desired=1)
    node = _ready_node(fleet_fakes)
    _tick()
    before = CdnRevision.current()
    _tick()
    assert CdnRevision.current() == before, "nothing changed"
    PublicIP.objects.filter(vm__vm_id=node.node_id).update(cap_mbps=500)
    _tick()
    assert CdnRevision.current() > before


def test_the_network_revision_syncs_with_the_reconciler_off(
    fleet_fakes: Fleet, monkeypatch: pytest.MonkeyPatch
) -> None:
    _region(desired=1)
    node = _ready_node(fleet_fakes)
    _tick()
    monkeypatch.setattr(settings, "VALI_CDN_RECONCILE_ENABLED", False)
    before = CdnRevision.current()
    PublicIP.objects.filter(vm__vm_id=node.node_id).update(state=PublicIpState.QUARANTINED)
    _tick()
    assert CdnRevision.current() > before


def _miner(miner_id: str, *, seen: dt.datetime, status: str = "active") -> None:
    from apps.miners.models import MinerIdentity

    n = MinerIdentity.objects.count() + 1
    MinerIdentity.objects.create(
        miner_id=miner_id,
        pubkey_hex=f"{n:064x}",
        platform_id=f"{n:02x}" + "cd" * 15,
        status=status,
        last_seen_at=seen,
    )


def test_an_ingest_outage_does_not_fail_every_node_as_host_unseen(fleet_fakes: Fleet) -> None:
    """Miners' last_seen_at moves with the same ingest as guest signals: all
    unseen at once is vali's outage, not dead hosts."""
    _region(desired=2)
    a = _ready_node(fleet_fakes)
    b = _ready_node(fleet_fakes, host="miner-b")
    old = timezone.now() - dt.timedelta(hours=1)
    for m in ("miner-a", "miner-b", "miner-t"):
        _miner(m, seen=old)
    _tick()
    for n in (a, b):
        n.refresh_from_db()
        assert n.state == CdnNodeState.READY


def test_one_dark_host_among_live_ones_fails_its_node(fleet_fakes: Fleet) -> None:
    _region(desired=2)
    a = _ready_node(fleet_fakes)
    b = _ready_node(fleet_fakes, host="miner-b")
    _miner("miner-a", seen=timezone.now() - dt.timedelta(hours=1))
    _miner("miner-b", seen=timezone.now())
    _miner("miner-t", seen=timezone.now())
    _tick()
    a.refresh_from_db()
    b.refresh_from_db()
    assert a.state == CdnNodeState.FAILED and a.failure_reason == "host-unseen"
    assert b.state == CdnNodeState.READY


def test_long_dead_agents_do_not_hold_the_breaker(fleet_fakes: Fleet) -> None:
    _region(desired=1)
    node = _ready_node(fleet_fakes)
    for i in range(5):
        _tenant_vm(f"tenant-dead-{i}", signal_at=timezone.now() - dt.timedelta(days=3))
    _tenant_vm("tenant-live", signal_at=timezone.now())
    Vm.objects.filter(vm_id=node.node_id).update(
        guest_signal_at=timezone.now() - dt.timedelta(hours=1)
    )
    _tick()
    node.refresh_from_db()
    assert node.state == CdnNodeState.FAILED


def _telemetry_outage(*node_ids: str) -> None:
    stale = timezone.now() - dt.timedelta(hours=1)
    _tenant_vm("tenant-vm-1", signal_at=stale)
    Vm.objects.filter(vm_id__in=node_ids).update(guest_signal_at=stale)


def test_the_liveness_hold_is_capped(fleet_fakes: Fleet) -> None:
    _region(desired=2)
    a = _ready_node(fleet_fakes)
    b = _ready_node(fleet_fakes, host="miner-b")
    _telemetry_outage(a.node_id, b.node_id)
    _tick()
    assert CdnRevision.objects.get().liveness_hold_since is not None
    _tick(_later(seconds=settings.VALI_CDN_BREAKER_MAX_HOLD_S - 60))
    for n in (a, b):
        n.refresh_from_db()
        assert n.state == CdnNodeState.READY, "still held"
    _tick(_later(seconds=settings.VALI_CDN_BREAKER_MAX_HOLD_S + 60))
    for n in (a, b):
        n.refresh_from_db()
        assert n.state == CdnNodeState.FAILED, "the hold ran out"


def test_the_hold_resets_after_two_quiet_free_passes(fleet_fakes: Fleet) -> None:
    _region(desired=2)
    a = _ready_node(fleet_fakes)
    b = _ready_node(fleet_fakes, host="miner-b")
    _telemetry_outage(a.node_id, b.node_id)
    _tick()
    since = CdnRevision.objects.get().liveness_hold_since
    Vm.objects.update(guest_signal_at=timezone.now())
    _tick()
    assert CdnRevision.objects.get().liveness_hold_since == since, "one pass is not enough"
    _tick()
    assert CdnRevision.objects.get().liveness_hold_since is None


def test_a_hovering_ratio_cannot_restart_the_cap(fleet_fakes: Fleet) -> None:
    """Outage, no outage, outage, ...: one quiet-free pass at a time never
    clears the start, so the cap counts from the first outage."""
    _region(desired=2)
    _ready_node(fleet_fakes)
    _ready_node(fleet_fakes, host="miner-b")
    tenants = [_tenant_vm(f"tenant-vm-{i}", signal_at=timezone.now()).pk for i in range(4)]
    starts = set()
    for k in range(6):
        at = _later(seconds=60 * k)
        quiet = at - dt.timedelta(hours=1)
        Vm.objects.filter(pk__in=tenants).update(guest_signal_at=quiet if k % 2 == 0 else at)
        _tick(at)
        starts.add(CdnRevision.objects.get().liveness_hold_since)
    assert len(starts) == 1 and None not in starts


def test_while_held_a_down_domain_still_fails_and_no_cert_is_renewed(
    fleet_fakes: Fleet, monkeypatch: pytest.MonkeyPatch
) -> None:
    from apps.orchestration import effects

    _region(desired=2)
    a = _ready_node(fleet_fakes)
    b = _ready_node(fleet_fakes, host="miner-b")
    _telemetry_outage(a.node_id, b.node_id)
    monkeypatch.setattr(
        effects, "poll_domain_running", lambda vm: False if vm.vm_id == a.node_id else None
    )
    # b's certificate is due for renewal (past 2/3 of its life).
    CdnNode.objects.filter(pk=b.pk).update(
        cert_not_before=timezone.now() - dt.timedelta(days=6),
        cert_not_after=timezone.now() + dt.timedelta(days=1),
    )
    serial = CdnNode.objects.get(pk=b.pk).cert_serial
    _tick()
    a.refresh_from_db()
    b.refresh_from_db()
    assert a.state == CdnNodeState.FAILED and a.failure_reason == "domain-down"
    assert b.state == CdnNodeState.READY and b.cert_serial == serial


def test_an_empty_control_group_is_a_critical_alert(
    fleet_fakes: Fleet, monkeypatch: pytest.MonkeyPatch
) -> None:
    _region(desired=1)
    node = _ready_node(fleet_fakes)
    criticals: list[str] = []
    monkeypatch.setattr(reconcile.log, "critical", lambda msg, *a, **k: criticals.append(msg))
    Vm.objects.filter(vm_id=node.node_id).update(
        guest_signal_at=timezone.now() - dt.timedelta(days=2)
    )
    _tick()
    assert any("control window" in c for c in criticals)


def test_the_control_window_is_a_setting(
    fleet_fakes: Fleet, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Shrunk below the tenants' quietness, they leave the comparison."""
    _region(desired=2)
    a = _ready_node(fleet_fakes)
    b = _ready_node(fleet_fakes, host="miner-b")
    _telemetry_outage(a.node_id, b.node_id)
    monkeypatch.setattr(settings, "VALI_CDN_BREAKER_CONTROL_WINDOW_S", 1800)
    _tick()
    a.refresh_from_db()
    assert a.state == CdnNodeState.FAILED


def test_a_20_minute_ingest_cut_fails_no_node(fleet_fakes: Fleet) -> None:
    """Guest signals AND miner sightings stop together (vali's ingest is
    down): neither the liveness nor the host-unseen rule fails a node."""
    _region(desired=2)
    a = _ready_node(fleet_fakes)
    b = _ready_node(fleet_fakes, host="miner-b")
    cut = timezone.now() - dt.timedelta(minutes=20)
    for m in ("miner-a", "miner-b", "miner-t"):
        _miner(m, seen=cut)
    _tenant_vm("tenant-vm-1", signal_at=cut)
    Vm.objects.filter(vm_id__in=[a.node_id, b.node_id]).update(guest_signal_at=cut)
    report = reconcile.reconcile(now=timezone.now())
    assert report.failed == 0
    for n in (a, b):
        n.refresh_from_db()
        assert n.state == CdnNodeState.READY


@pytest.mark.parametrize("regions", ["none", "inactive"])
def test_the_reconciler_with_no_active_region_does_nothing(
    fleet_fakes: Fleet, monkeypatch: pytest.MonkeyPatch, regions: str
) -> None:
    """Flags on before any region is active (the rollout order): no launch,
    no node, no alert — even with a quiet tenant fleet and unseen miners
    that would trip the breakers."""
    if regions == "inactive":
        _region(desired=2, active=False)
    stale = timezone.now() - dt.timedelta(hours=1)
    for i in range(4):
        _tenant_vm(f"tenant-vm-{i}", signal_at=stale)
    for m in ("miner-a", "miner-b", "miner-c"):
        _miner(m, seen=stale)
    logged: list[str] = []
    for level in ("warning", "error", "critical"):
        monkeypatch.setattr(
            reconcile.log, level, lambda msg, *a, _l=level, **k: logged.append(f"{_l}: {msg % a}")
        )
    for minutes in (0, 10, 60):
        assert reconcile.reconcile(now=_later(minutes=minutes)) == reconcile.ReconcileReport()
    assert fleet_fakes.launches == [] and not CdnNode.objects.exists()
    assert logged == []
    assert CdnRevision.objects.get().liveness_hold_since is None
