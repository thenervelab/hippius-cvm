"""Tests for `GET /v1/operator/fleet`."""

from __future__ import annotations

from datetime import timedelta
from typing import Any

import pytest
from django.db import connection
from django.test.utils import CaptureQueriesContext
from django.urls import reverse
from django.utils import timezone
from rest_framework.test import APIClient

from apps.backup import service as backup_service
from apps.backup.models import BackupChain, BackupKind, BackupPolicy, BackupRun, RunStatus
from apps.identity.models import PrincipalScope, ServiceClient
from apps.lifecycle.models import Vm, VmPowerState, VmState
from apps.miners.models import MinerIdentity, MinerStatus
from apps.network.models import IngressEdge, PublicIP, PublicIpState
from apps.operator import fleet
from apps.orchestration.models import LaunchJob, LaunchJobState
from apps.scheduler import chain
from apps.scheduler.chain import MinerView
from apps.scheduler.models import MinerCapacity, PlacementStatus, UsageAccrual
from apps.scheduler.tests.factories import (
    make_dispatchable_identity,
    make_placement,
    make_snapshot,
    make_vm,
    node_id,
)
from apps.telemetry.models import HostAttestor, HostAttestorRelease, HostAttestorStatus

pytestmark = pytest.mark.django_db

URL = reverse("operator_fleet")
MEAS = "a1" * 48


@pytest.fixture(autouse=True)
def _no_chain(monkeypatch: pytest.MonkeyPatch) -> None:
    """No test reaches a real RPC: the default is an unreachable chain."""

    def _down() -> chain.ChainSnapshot:
        raise chain.ChainReadUnavailable("rpc down (test)")

    monkeypatch.setattr(chain, "read_miner_status", _down)


def _chain_up(monkeypatch: pytest.MonkeyPatch, *views: MinerView, epoch: int = 10) -> None:
    snap = make_snapshot(epoch, views)
    monkeypatch.setattr(chain, "read_miner_status", lambda: snap)


def _mirror(seed: int, *, slots: int = 8, mem: int | None = None, cpus: int | None = None):
    return MinerCapacity.objects.create(
        miner_node_id=node_id(seed),
        status="active",
        capacity_slots=slots,
        total_memory_mb=mem,
        total_cpus=cpus,
        observed_epoch=10,
        data_epoch=10,
        refreshed_at=timezone.now(),
    )


def _attestor(seed: int, **overrides: Any) -> HostAttestor:
    fields: dict[str, Any] = {
        "chip_id": format(seed, "0128x"),
        "node_id": node_id(seed),
        "signer_pubkey": bytes(32),
        "measurement": MEAS,
        "cert_expiry_at": timezone.now() + timedelta(days=30),
        "status": HostAttestorStatus.ATTESTED.value,
        "last_seen_at": timezone.now(),
    }
    fields.update(overrides)
    return HostAttestor.objects.create(**fields)


def _vm(vm_id: str, seed: int, **fields: Any) -> Vm:
    """A VM hosted on `miner-{seed:02d}` (the id `make_dispatchable_identity`
    registers), as `Vm.host` records it."""
    vm = make_vm(vm_id, f"lease-{vm_id}")
    Vm.objects.filter(pk=vm.pk).update(host=f"miner-{seed:02d}", **fields)
    vm.refresh_from_db()
    return vm


def _fleet(client: APIClient, **params: str) -> dict[str, Any]:
    resp = client.get(URL, params)
    assert resp.status_code == 200, resp.content
    return resp.json()


def _row(body: dict[str, Any], seed: int) -> dict[str, Any]:
    (row,) = [r for r in body["miners"] if r["node_id"] == node_id(seed)]
    return row


# ─── auth / wire ─────────────────────────────────────────────────────


def test_anonymous_is_refused() -> None:
    assert APIClient().get(URL).status_code in (401, 403)


def test_tenant_principal_is_refused(tenant_client: APIClient) -> None:
    assert tenant_client.get(URL).status_code == 403


def test_malformed_chain_param_is_400(operator_client: APIClient) -> None:
    resp = operator_client.get(URL, {"chain": "maybe"})
    assert resp.status_code == 400
    assert resp.json()["category"] == "wire"


def test_empty_fleet(operator_client: APIClient) -> None:
    body = _fleet(operator_client)
    assert body["miners"] == []
    assert body["totals"]["miners"] == 0
    assert body["chain"]["available"] is False
    assert "rpc down" in body["chain"]["error"]
    assert set(body["policy"]["flavors"]) >= {"small", "4xlarge"}


# ─── one miner, fully populated ──────────────────────────────────────


def test_dispatchable_miner_with_vms(operator_client: APIClient) -> None:
    make_dispatchable_identity(1)
    # 64 GiB / 16 vCPU anchor; reserve defaults 8192 MiB + 2 vCPU.
    _mirror(1, slots=8, mem=65536, cpus=16)
    vm_a = _vm("vm-a", 1)
    vm_a.tenant_id = "tenant-a"
    vm_a.save(update_fields=["tenant_id"])
    make_placement(
        vm_a, node_id(1), status=PlacementStatus.BOUND.value, resource_class="large", owner="user-7"
    )
    make_placement(_vm("vm-b", 1), node_id(1), resource_class="small")
    # A FAILED placement is history, not load.
    make_placement(make_vm("vm-c", "lease-c"), node_id(1), status=PlacementStatus.FAILED.value)
    edge = IngressEdge.objects.create(name="edge-fr", region="FR")
    PublicIP.objects.create(
        address="203.0.113.7", edge=edge, vm=vm_a, state=PublicIpState.ATTACHED.value
    )
    _attestor(1)
    HostAttestorRelease.objects.create(measurement=MEAS, version="v1.4.2", is_active=True)

    row = _row(_fleet(operator_client), 1)
    assert row["miner_id"] == "miner-01"
    assert row["schedulable"] is True and row["schedulable_reason"] is None
    assert row["heartbeat_stale"] is False
    assert row["vm_count"] == 2
    assert row["vm_count_by_state"] == {"active:running": 2}
    vms = {v["vm_id"]: v for v in row["vms"]}
    assert vms["vm-a"]["tenant_id"] == "tenant-a"
    assert vms["vm-a"]["owner"] == "user-7"
    assert vms["vm-a"]["flavor"] == "large"
    assert vms["vm-a"]["public_ip"] == "203.0.113.7"
    assert vms["vm-b"]["public_ip"] is None

    cap = row["capacity"]
    assert cap["dynamic"] is True
    assert cap["used_slots"] == 2
    assert cap["committed_memory_mb"] == 16384 + 4096
    assert cap["committed_cpus"] == 4 + 1
    assert cap["budget_memory_mb"] == 65536 - 8192
    assert cap["free_memory_mb"] == 65536 - 8192 - 16384 - 4096
    assert cap["free_cpus"] == 16 - 2 - 5
    # 9 free vCPU bounds `large` (4 vCPU) at 2; `2xlarge` (16 vCPU) is
    # bigger than the 14-vCPU budget, so it never fits this hardware.
    no_disk_data = {"fits_now": None, "fits_hardware": None}
    assert cap["flavor_headroom"]["large"] == {
        "fits_now": 2,
        "fits_hardware": True,
        "offered": True,
        "disk": {"need_gb": 170, **no_disk_data},
    }
    assert cap["flavor_headroom"]["2xlarge"] == {
        "fits_now": 0,
        "fits_hardware": False,
        "offered": True,
        "disk": {"need_gb": 650, **no_disk_data},
    }

    att = row["attestor"]
    assert att["status"] == "attested"
    assert att["release_version"] == "v1.4.2"
    assert "cert_expiry_at_dt" not in att
    assert row["cvm_start"]["verdict"] == "unknown"
    assert row["alerts"] == []


def test_no_anchor_is_flat_cap_and_flagged(operator_client: APIClient) -> None:
    make_dispatchable_identity(1)
    _mirror(1, slots=6)
    row = _row(_fleet(operator_client), 1)
    assert row["capacity"]["effective_slots"] == 6
    assert row["capacity"]["dynamic"] is False
    assert row["capacity"]["flavor_headroom"]["small"] == {
        "fits_now": None,
        "fits_hardware": None,
        "offered": True,
        "disk": {"need_gb": 50, "fits_now": None, "fits_hardware": None},
    }
    assert "no-hardware-anchor" in row["alerts"]
    assert "attestor-missing" in row["alerts"]


def test_vcpu_model_from_chip_id_length(operator_client: APIClient) -> None:
    turin = make_dispatchable_identity(1)
    turin.platform_id = "ab" * 8
    turin.save(update_fields=["platform_id"])
    genoa = make_dispatchable_identity(2)
    genoa.platform_id = "cd" * 64
    genoa.save(update_fields=["platform_id"])
    body = _fleet(operator_client)
    assert _row(body, 1)["vcpu_model"] == "EpycTurin"
    assert _row(body, 2)["vcpu_model"] == "EpycGenoa"


def test_vcpu_model_honours_the_registered_generation(
    operator_client: APIClient,
) -> None:
    # Same 64-byte chip length: a Milan-registered host reads EpycMilan (what
    # vali measures it as), and a generation that contradicts the chip is
    # unresolvable (null) — vali refuses to launch there.
    milan = make_dispatchable_identity(1)
    milan.platform_id = "cd" * 64
    milan.snp_generation = "milan"
    milan.save(update_fields=["platform_id", "snp_generation"])
    bad = make_dispatchable_identity(2)
    bad.platform_id = "ef" * 64
    bad.snp_generation = "turin"
    bad.save(update_fields=["platform_id", "snp_generation"])
    body = _fleet(operator_client)
    assert _row(body, 1)["vcpu_model"] == "EpycMilan"
    assert _row(body, 1)["identity"]["snp_generation"] == "milan"
    assert _row(body, 2)["vcpu_model"] is None


def test_a_vm_attested_short_of_its_flavor_is_flagged(operator_client: APIClient) -> None:
    """The guest's KBS-signed live attestation said fewer vCPUs / less RAM
    than its flavor (`apps.telemetry.guest_resources`): the VM shows the
    finding and its miner carries the alert."""
    from apps.telemetry.models import GuestResourceShortfall

    make_dispatchable_identity(1)
    _mirror(1, slots=8, mem=65536, cpus=16)
    vm = _vm("vm-short", 1)
    make_placement(vm, node_id(1), status=PlacementStatus.BOUND.value, resource_class="large")
    make_placement(_vm("vm-fine", 1), node_id(1), resource_class="small")
    now = timezone.now()
    GuestResourceShortfall.objects.create(
        vm_id="vm-short",
        node_id_hex=node_id(1),
        flavor="large",
        want_vcpus=4,
        want_memory_mb=16384,
        vcpus_online=2,
        mem_firmware_kib=8 * 1024 * 1024,
        mem_total_kib=7_600_000,
        reason="vcpus+mem-firmware",
        samples=3,
        first_seen_at=now - timedelta(minutes=20),
        last_seen_at=now,
        last_body_digest="cc" * 32,
    )

    row = _row(_fleet(operator_client), 1)
    vms = {v["vm_id"]: v for v in row["vms"]}
    assert vms["vm-fine"]["resource_shortfall"] is None
    finding = vms["vm-short"]["resource_shortfall"]
    assert finding["reason"] == "vcpus+mem-firmware"
    assert (finding["want_vcpus"], finding["vcpus_online"], finding["samples"]) == (4, 2, 3)
    assert "guest-resource-shortfall" in row["alerts"]


# ─── the gates, as the scheduler sees them ───────────────────────────


def test_stale_heartbeat(operator_client: APIClient) -> None:
    m = make_dispatchable_identity(1)
    m.last_seen_at = timezone.now() - timedelta(hours=1)
    m.save(update_fields=["last_seen_at"])
    row = _row(_fleet(operator_client), 1)
    assert row["schedulable"] is False
    assert row["schedulable_reason"] == "heartbeat-stale"
    assert row["heartbeat_stale"] is True
    assert row["heartbeat_age_s"] >= 3600
    assert "heartbeat-stale" in row["alerts"]


def test_operator_quarantine(operator_client: APIClient) -> None:
    m = make_dispatchable_identity(1)
    m.status = MinerStatus.QUARANTINED
    m.save(update_fields=["status"])
    row = _row(_fleet(operator_client), 1)
    assert row["schedulable_reason"] == "quarantined"
    assert "quarantined" in row["alerts"]


def test_a_failover_quarantined_miner_is_not_schedulable(operator_client: APIClient) -> None:
    from apps.orchestration.models import FailoverQuarantine
    from apps.orchestration.tests.factories import make_migration_job

    make_dispatchable_identity(1)
    vm = make_vm()
    job = make_migration_job(vm, dest_node_id="miner-02")
    FailoverQuarantine.objects.create(job=job, miner_id="miner-01")
    row = _row(_fleet(operator_client), 1)
    assert row["schedulable"] is False
    assert row["schedulable_reason"] == "failover-quarantined"


def test_zombie_quarantine_overrides_dispatchable(
    operator_client: APIClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    make_dispatchable_identity(1)

    class _Obs:
        miner_node_id = node_id(1)
        vm_id = "vm-dead"
        last_seen_at = timezone.now()

    monkeypatch.setattr(fleet.zombie, "fresh_observations", lambda now=None, **_kw: [_Obs()])
    monkeypatch.setattr(
        fleet.zombie, "quarantined_node_ids", lambda now=None: frozenset({node_id(1)})
    )
    row = _row(_fleet(operator_client), 1)
    assert row["schedulable"] is False
    assert row["schedulable_reason"] == "zombie-quarantined"
    assert row["zombie"]["vm_ids"] == ["vm-dead"]
    assert "zombie-quarantined" in row["alerts"]


def test_attestor_expired_and_not_covered(operator_client: APIClient) -> None:
    make_dispatchable_identity(1)
    _attestor(
        1,
        status=HostAttestorStatus.PENDING.value,
        cert_expiry_at=timezone.now() - timedelta(minutes=5),
    )
    _mirror(1)
    row = _row(_fleet(operator_client), 1)
    assert row["attestor"]["gate_reason"] is not None
    assert "attestor-not-covered" in row["alerts"]
    assert "attestor-cert-expired" in row["alerts"]
    # The gate is off by default: coverage is reported, not enforced.
    assert row["dispatchable"] is True
    assert row["schedulable"] is True


def test_short_lived_valid_cert_is_not_an_alert(operator_client: APIClient) -> None:
    """Attestor certs live ~2 h and are renewed continuously."""
    make_dispatchable_identity(1)
    _attestor(1, cert_expiry_at=timezone.now() + timedelta(minutes=30))
    HostAttestorRelease.objects.create(measurement=MEAS, version="v1", is_active=True)
    assert "attestor-cert-expired" not in _row(_fleet(operator_client), 1)["alerts"]


def test_cvm_failure_streak_is_reported(operator_client: APIClient) -> None:
    make_dispatchable_identity(1)
    mirror = _mirror(1)
    MinerCapacity.objects.filter(pk=mirror.pk).update(
        cvm_last_fail_at=timezone.now(),
        cvm_fail_streak=5,
        cvm_last_fail_reason="launch-order-rejected",
    )
    row = _row(_fleet(operator_client), 1)
    assert row["cvm_start"]["fail_streak"] == 5
    assert row["cvm_start"]["verdict"] in ("degraded", "incapable")
    assert f"cvm-{row['cvm_start']['verdict']}" in row["alerts"]


# ─── chain ───────────────────────────────────────────────────────────


def test_chain_read_carries_status_and_price(
    operator_client: APIClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    make_dispatchable_identity(1)
    _mirror(1)
    _chain_up(
        monkeypatch,
        MinerView(node_id(1), "active", 9, 10, 42, price=5_000_000),
        MinerView(node_id(2), "quarantined", 9, 10, 0),
        epoch=12,
    )
    body = _fleet(operator_client)
    assert body["chain"] == {
        "available": True,
        "error": None,
        "current_epoch": 12,
        "pallet_live": True,
    }
    one = _row(body, 1)
    assert one["chain"]["source"] == "chain"
    assert one["chain"]["price"] == 5_000_000
    assert one["chain"]["quality"] == "42"
    # On chain but unknown to vali: listed, never schedulable.
    two = _row(body, 2)
    assert two["miner_id"] is None
    assert two["schedulable"] is False and two["schedulable_reason"] == "no-identity"
    assert {"no-identity", "chain-quarantined"} <= set(two["alerts"])
    assert body["totals"]["chain_active"] == 1


def test_leftover_mirror_row_is_flagged_and_not_counted(
    operator_client: APIClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A mirror row for a node the chain no longer lists (a testnet
    leftover) is shown, flagged, and never inflates the fleet totals."""
    make_dispatchable_identity(1)
    _mirror(1, slots=4)
    _mirror(9, slots=8)
    _chain_up(monkeypatch, MinerView(node_id(1), "active", 9, 10, 0))
    body = _fleet(operator_client)
    ghost = _row(body, 9)
    assert ghost["on_chain"] is False
    assert ghost["chain"]["source"] == "mirror-absent-from-chain"
    assert ghost["alerts"] == ["not-on-chain", "no-identity"]
    assert _row(body, 1)["on_chain"] is True
    totals = body["totals"]
    assert totals["rows"] == 2
    assert totals["miners"] == 1
    assert totals["chain_active"] == 1
    assert totals["effective_slots"] == 4


def test_chain_down_falls_back_to_mirror(operator_client: APIClient) -> None:
    make_dispatchable_identity(1)
    _mirror(1)
    row = _row(_fleet(operator_client), 1)
    assert row["chain"]["source"] == "mirror"
    assert row["chain"]["status"] == "active"
    assert row["chain"]["price"] is None
    assert row["chain"]["refreshed_at"] is not None
    assert row["on_chain"] is None


def test_chain_false_skips_the_read(
    operator_client: APIClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    def _boom() -> chain.ChainSnapshot:
        raise AssertionError("chain must not be read")

    monkeypatch.setattr(chain, "read_miner_status", _boom)
    body = _fleet(operator_client, chain="false")
    assert body["chain"]["available"] is False
    assert body["chain"]["error"] == "not-requested"


# ─── usage, identities, totals ───────────────────────────────────────


def test_current_epoch_usage(operator_client: APIClient) -> None:
    make_dispatchable_identity(1)
    _mirror(1)  # observed_epoch=10 ⇒ billing epoch 10
    for epoch, units in ((10, 1500), (9, 99999)):
        UsageAccrual.objects.create(
            epoch=epoch,
            miner_node_id=node_id(1),
            vm_id=f"vm-{epoch}",
            resource_class="small",
            unit_seconds=units,
            billable_seconds=units // 3,
        )
    body = _fleet(operator_client)
    assert body["billing_epoch"] == 10
    usage = _row(body, 1)["usage"]
    assert usage["epoch_unit_seconds"] == 1500
    assert usage["epoch_billable_seconds"] == 500


def test_unbridged_identity_is_listed(operator_client: APIClient) -> None:
    MinerIdentity.objects.create(
        miner_id="loose",
        pubkey_hex="ab" * 32,
        platform_id="cd" * 8,
        status=MinerStatus.ACTIVE,
    )
    body = _fleet(operator_client)
    (row,) = body["miners"]
    assert row["node_id"] is None
    assert row["miner_id"] == "loose"
    assert row["schedulable_reason"] == "not-bridged"
    assert body["totals"]["bridged"] == 0


def test_totals(operator_client: APIClient) -> None:
    make_dispatchable_identity(1)
    _mirror(1, slots=4)
    stale = make_dispatchable_identity(2)
    stale.last_seen_at = timezone.now() - timedelta(hours=2)
    stale.save(update_fields=["last_seen_at"])
    _mirror(2, slots=3)
    make_placement(_vm("vm-1", 1), node_id(1), status=PlacementStatus.BOUND.value)
    totals = _fleet(operator_client)["totals"]
    assert totals["miners"] == 2
    assert totals["schedulable"] == 1
    assert totals["heartbeat_fresh"] == 1
    assert totals["vms"] == 1
    assert totals["effective_slots"] == 7
    assert totals["used_slots"] == 1
    # Only the schedulable node's headroom is sellable.
    assert totals["schedulable_free_slots"] == 3
    assert totals["alerts"]["heartbeat-stale"] == 1


def test_query_count_does_not_grow_with_fleet_size(operator_client: APIClient) -> None:
    def _seed(seeds: range) -> None:
        for s in seeds:
            make_dispatchable_identity(s)
            _mirror(s, mem=131072, cpus=32)
            _attestor(s)
            for i in range(3):
                make_placement(
                    _vm(f"vm-{s}-{i}", s),
                    node_id(s),
                    status=PlacementStatus.BOUND.value,
                    resource_class="small",
                )
            _abandoned(f"vm-{s}-refused")

    _seed(range(1, 2))
    with CaptureQueriesContext(connection) as one:
        assert len(_fleet(operator_client)["miners"]) == 1
    _seed(range(2, 21))
    with CaptureQueriesContext(connection) as twenty:
        body = _fleet(operator_client)
    assert len(body["miners"]) == 20
    assert all(r["vm_count"] == 3 for r in body["miners"])
    assert len(twenty) == len(one), (len(one), len(twenty))


# ─── the placement gates beyond dispatchability ──────────────────────


def test_attestor_shown_is_the_row_the_gate_judged(operator_client: APIClient) -> None:
    """A fresher row on an old measurement must not hide the row that
    actually covers the node."""
    make_dispatchable_identity(1)
    HostAttestorRelease.objects.create(measurement=MEAS, version="v2", is_active=True)
    _attestor(1, last_seen_at=timezone.now() - timedelta(seconds=30))
    _attestor(1, chip_id="ee" * 64, measurement="b2" * 48, last_seen_at=timezone.now())
    att = _row(_fleet(operator_client), 1)["attestor"]
    assert att["measurement"] == MEAS
    assert att["gate_reason"] is None
    assert att["release_version"] == "v2"


def test_cvm_incapable_is_not_schedulable(operator_client: APIClient, settings) -> None:
    settings.VALI_SCHEDULER_CVM_FAIL_THRESHOLD = 2
    make_dispatchable_identity(1)
    mirror = _mirror(1)
    MinerCapacity.objects.filter(pk=mirror.pk).update(
        cvm_last_fail_at=timezone.now(), cvm_fail_streak=5
    )
    row = _row(_fleet(operator_client), 1)
    assert row["dispatchable"] is True
    assert row["cvm_start"]["verdict"] == "incapable"
    assert (row["schedulable"], row["schedulable_reason"]) == (False, "cvm-incapable")


def test_a_full_miner_is_not_schedulable_and_sells_nothing(operator_client: APIClient) -> None:
    make_dispatchable_identity(1)
    _mirror(1, slots=1)
    make_placement(_vm("vm-1", 1), node_id(1), status=PlacementStatus.BOUND.value)
    body = _fleet(operator_client)
    row = _row(body, 1)
    assert (row["schedulable"], row["schedulable_reason"]) == (False, "full")
    assert body["totals"]["schedulable_free_slots"] == 0


def test_chain_gates(operator_client: APIClient, monkeypatch: pytest.MonkeyPatch) -> None:
    for s in (1, 2, 3):
        make_dispatchable_identity(s)
        _mirror(s)
    _chain_up(
        monkeypatch,
        MinerView(node_id(1), "quarantined", 9, 20, 0),
        MinerView(node_id(2), "active", 9, 10, 0),  # data_epoch 10 vs current 20
        epoch=20,
    )
    body = _fleet(operator_client)
    assert _row(body, 1)["schedulable_reason"] == "chain-not-active"
    assert _row(body, 2)["schedulable_reason"] == "epoch-stale"
    assert _row(body, 3)["schedulable_reason"] == "not-on-chain"


def test_capacity_matches_scheduler_admission_on_a_mixed_case_node_id(
    operator_client: APIClient,
) -> None:
    """Admission matches `miner_node_id` by exact spelling; the fleet must
    report the numbers the scheduler admits with, and say that the
    differently-spelled placement is not counted."""
    from apps.scheduler import service as scheduler_service

    nid = "ab" * 32
    m = make_dispatchable_identity(1)
    MinerIdentity.objects.filter(pk=m.pk).update(chain_node_id=nid)
    MinerCapacity.objects.create(
        miner_node_id=nid,
        status="active",
        capacity_slots=4,
        total_memory_mb=65536,
        total_cpus=16,
        observed_epoch=10,
        data_epoch=10,
        refreshed_at=timezone.now(),
    )
    make_placement(
        _vm("vm-1", 1), nid.upper(), status=PlacementStatus.BOUND.value, resource_class="small"
    )
    capacity, load, _fam = scheduler_service.decision_inputs("")
    (row,) = [r for r in _fleet(operator_client)["miners"] if r["node_id"] == nid]
    assert row["capacity"]["effective_slots"] == capacity[nid]
    assert row["capacity"]["used_slots"] == load.get(nid, 0) == 0
    (vm,) = row["vms"]
    assert vm["admission_counted"] is False
    assert "vm-outside-admission" in row["alerts"]


# ─── the Vm ledger vs the Placement ledger ───────────────────────────


def test_a_running_vm_whose_placement_was_drained_is_still_listed(
    operator_client: APIClient,
) -> None:
    """The live 2026-09 case: a stale-miner drain FAILED the placement, the
    host rebooted and reboot-recovery relaunched the VM on the SAME miner —
    nothing re-bound a placement. The VM runs; admission no longer counts
    it. The page must show it, and say admission is short."""
    make_dispatchable_identity(1)
    _mirror(1, mem=65536, cpus=16)
    counted = _vm("vm-counted", 1)
    make_placement(counted, node_id(1), status=PlacementStatus.BOUND.value, resource_class="small")
    drained = _vm("vm-drained", 1)
    make_placement(
        drained,
        node_id(1),
        status=PlacementStatus.FAILED.value,
        reason="drain:miner-stale",
        failure_source="scheduler_drain",
        resource_class="large",
    )

    row = _row(_fleet(operator_client), 1)
    assert row["vm_count"] == 2
    vms = {v["vm_id"]: v for v in row["vms"]}
    assert vms["vm-counted"]["admission_counted"] is True
    assert vms["vm-drained"]["admission_counted"] is False
    assert vms["vm-drained"]["placement_status"] == "failed"
    assert vms["vm-drained"]["placement_reason"] == "drain:miner-stale"
    assert vms["vm-drained"]["flavor"] == "large"
    cap = row["capacity"]
    assert cap["used_slots"] == 1
    assert cap["uncounted_vms"] == 1
    assert (cap["uncounted_memory_mb"], cap["uncounted_cpus"]) == (16384, 4)
    assert "vm-outside-admission" in row["alerts"]


def test_decommissioning_and_destroyed_vms(operator_client: APIClient) -> None:
    """A decommissioning guest still runs (listed, not an alert: §24 drops
    it from admission on purpose); a destroyed one is gone — unless a live
    placement still points at it, which is a stale placement."""
    make_dispatchable_identity(1)
    _mirror(1)
    dying = _vm("vm-dying", 1, state=VmState.DECOMMISSIONING)
    make_placement(
        dying,
        node_id(1),
        status=PlacementStatus.FAILED.value,
        reason="drain:vm-terminal",
        failure_source="scheduler_drain",
    )
    _vm("vm-gone", 1, state=VmState.DESTROYED)
    ghost = _vm("vm-ghost", 1, state=VmState.DESTROYED)
    make_placement(ghost, node_id(1), status=PlacementStatus.BOUND.value)

    row = _row(_fleet(operator_client), 1)
    vms = {v["vm_id"]: v for v in row["vms"]}
    assert set(vms) == {"vm-dying", "vm-ghost"}
    assert vms["vm-dying"]["admission_counted"] is False
    assert vms["vm-ghost"]["role"] == "placement-only"
    assert row["vm_count"] == 1
    assert "vm-outside-admission" not in row["alerts"]
    assert "stale-placement" in row["alerts"]


def test_a_vm_on_an_unknown_host_is_reported_not_dropped(operator_client: APIClient) -> None:
    make_dispatchable_identity(1)
    _vm("vm-lost", 99)
    body = _fleet(operator_client)
    assert [v["vm_id"] for v in body["unresolved_vms"]] == ["vm-lost"]
    assert body["unresolved_vms"][0]["host"] == "miner-99"


def _abandoned(vm_id: str) -> Vm:
    """A launch that gave up without binding a host, as
    `launch._mark_launch_abandoned` leaves it."""
    vm = _vm(vm_id, 1)
    Vm.objects.filter(pk=vm.pk).update(
        host="",
        launch_abandoned_at=timezone.now(),
        launch_abandoned_outcome="no-eligible-miner",
    )
    vm.refresh_from_db()
    return vm


def test_a_launch_refused_at_placement_is_not_an_unresolved_host(
    operator_client: APIClient,
) -> None:
    """Refused before any miner was chosen, the row stays `active host=""`
    until `sweep_abandoned_launches` reaps it. It runs nowhere, so it is not
    a VM "on a host no miner matches". A host-less row with no abandoned
    marker (a launch still in flight) is still listed."""
    make_dispatchable_identity(1)
    _abandoned("vm-refused")
    _vm("vm-in-flight", 1)
    Vm.objects.filter(vm_id="vm-in-flight").update(host="")
    body = _fleet(operator_client)
    assert [v["vm_id"] for v in body["unresolved_vms"]] == ["vm-in-flight"]
    assert _row(body, 1)["vms"] == []


def test_an_abandoned_launch_that_reached_a_miner_stays_listed(
    operator_client: APIClient,
) -> None:
    """A dispatch that timed out also marks the row, and its guest may be up
    on the miner it was sent to: any record naming a miner keeps it listed."""
    make_dispatchable_identity(1)
    placed = _abandoned("vm-placed")
    make_placement(
        placed, node_id(1), status=PlacementStatus.FAILED.value, reason="edge-unreachable"
    )
    _abandoned("vm-dispatched")
    LaunchJob.objects.create(
        job_id="job-dispatched",
        vm_id="vm-dispatched",
        tenant_id="t",
        flavor="small",
        spec_json={},
        userdata_vault_path="p",
        userdata_vault_version=1,
        kek_vault_path="k",
        miner_id="miner-01",
        state=LaunchJobState.FAILED.value,
        phase_started_at=timezone.now(),
        finished_at=timezone.now(),
        decided_by=ServiceClient.objects.create(
            scope=PrincipalScope.OPERATOR.value, name="launcher"
        ),
    )
    _abandoned("vm-refused")
    body = _fleet(operator_client)
    assert sorted(v["vm_id"] for v in body["unresolved_vms"]) == ["vm-dispatched", "vm-placed"]


def test_an_abandoned_marker_never_hides_a_vm_with_an_unknown_host(
    operator_client: APIClient,
) -> None:
    make_dispatchable_identity(1)
    _vm("vm-lost", 99)
    Vm.objects.filter(vm_id="vm-lost").update(launch_abandoned_at=timezone.now())
    body = _fleet(operator_client)
    assert [v["vm_id"] for v in body["unresolved_vms"]] == ["vm-lost"]


def test_host_resolves_by_node_id_or_netbird_ip(operator_client: APIClient) -> None:
    m = make_dispatchable_identity(1)
    _vm("by-node", 1)
    Vm.objects.filter(vm_id="by-node").update(host=node_id(1))
    _vm("by-ip", 1)
    Vm.objects.filter(vm_id="by-ip").update(host=str(m.netbird_ip))
    row = _row(_fleet(operator_client), 1)
    assert {v["vm_id"] for v in row["vms"]} == {"by-node", "by-ip"}


def test_a_migrating_vm_counts_once_on_its_source(operator_client: APIClient) -> None:
    make_dispatchable_identity(1)
    make_dispatchable_identity(2)
    _mirror(1)
    _mirror(2)
    vm = _vm("vm-moving", 1)
    Vm.objects.filter(pk=vm.pk).update(
        state=VmState.MIGRATING, new_generation=2, migration_dest="miner-02"
    )
    make_placement(vm, node_id(1), status=PlacementStatus.BOUND.value)
    body = _fleet(operator_client)
    src, dst = _row(body, 1), _row(body, 2)
    assert (src["vm_count"], src["incoming_migrations"]) == (1, 0)
    assert src["vm_count_by_state"] == {"migrating": 1}
    assert (dst["vm_count"], dst["incoming_migrations"]) == (0, 1)
    assert dst["vm_count_by_state"] == {}
    assert [v["role"] for v in dst["vms"]] == ["migration-dest"]
    assert body["totals"]["vms"] == 1
    assert "vm-outside-admission" not in dst["alerts"]


def test_an_ambiguous_netbird_ip_resolves_to_nobody(operator_client: APIClient) -> None:
    a = make_dispatchable_identity(1)
    b = make_dispatchable_identity(2)
    MinerIdentity.objects.filter(pk=b.pk).update(netbird_ip=a.netbird_ip)
    _vm("vm-ip", 1)
    Vm.objects.filter(vm_id="vm-ip").update(host=str(a.netbird_ip))
    body = _fleet(operator_client)
    assert [v["vm_id"] for v in body["unresolved_vms"]] == ["vm-ip"]


def test_an_unbridged_identity_sharing_the_ip_makes_it_ambiguous(
    operator_client: APIClient,
) -> None:
    a = make_dispatchable_identity(1)
    MinerIdentity.objects.create(
        miner_id="loose",
        pubkey_hex="ef" * 32,
        platform_id="cd" * 8,
        netbird_ip=a.netbird_ip,
        status=MinerStatus.ACTIVE,
    )
    _vm("vm-ip", 1)
    Vm.objects.filter(vm_id="vm-ip").update(host=str(a.netbird_ip))
    assert [v["vm_id"] for v in _fleet(operator_client)["unresolved_vms"]] == ["vm-ip"]


def test_a_mirror_row_spelled_unlike_the_chain_is_no_capacity(
    operator_client: APIClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    make_dispatchable_identity(1)
    MinerCapacity.objects.create(
        miner_node_id=("ab" * 32).upper(),
        status="active",
        capacity_slots=4,
        observed_epoch=10,
        data_epoch=10,
        refreshed_at=timezone.now(),
    )
    m = MinerIdentity.objects.get(miner_id="miner-01")
    MinerIdentity.objects.filter(pk=m.pk).update(chain_node_id="ab" * 32)
    _chain_up(monkeypatch, MinerView("ab" * 32, "active", 9, 10, 0))
    (row,) = [r for r in _fleet(operator_client)["miners"] if r["node_id"] == "ab" * 32]
    assert row["schedulable_reason"] == "no-capacity-record"


# ─── backups ─────────────────────────────────────────────────────────

DAY = 86400


@pytest.fixture(autouse=True)
def _backups_on(settings: Any) -> None:
    settings.VALI_BACKUP_ENABLED = True


def _policy(vm: Vm, *, enabled: bool = True, age: timedelta = timedelta(days=3)) -> BackupPolicy:
    policy = BackupPolicy.objects.create(
        vm=vm, enabled=enabled, interval_s=DAY, full_required=False, observed_boot_counter=2
    )
    BackupPolicy.objects.filter(pk=policy.pk).update(created_at=timezone.now() - age)
    policy.refresh_from_db()
    return policy


def _run(vm: Vm, status: str, ago: timedelta, *, boot_counter: int = 2) -> BackupRun:
    """A full on a chain of its own, finished `ago`."""
    at = timezone.now() - ago
    chain = BackupChain.objects.create(vm=vm, boot_counter=boot_counter, next_seq=1)
    run = BackupRun.objects.create(
        vm=vm,
        chain=chain,
        seq=0,
        kind=BackupKind.FULL,
        status=status,
        miner_id=vm.host,
        disk_key="d",
        state_key=f"s-{chain.id.hex}",
        manifest_key="m",
        part_size=1,
        part_count=1,
        finished_at=at,
    )
    BackupRun.objects.filter(pk=run.pk).update(created_at=at)
    return run


def test_a_disabled_policy_never_raises_a_backup_alert(operator_client: APIClient) -> None:
    """Seen in production on 2026-09-26: a temporary policy, two failed fulls, a good
    one, then the policy disabled. The failures stay in the counts (they
    happened) but raise nothing."""
    make_dispatchable_identity(1)
    vm = _vm("vm-a", 1)
    _policy(vm, enabled=False)
    _run(vm, RunStatus.FAILED.value, timedelta(hours=12))
    _run(vm, RunStatus.FAILED.value, timedelta(hours=11))
    _run(vm, RunStatus.DONE.value, timedelta(hours=9))
    row = _row(_fleet(operator_client), 1)
    assert row["backups"]["failed_24h"] == 2
    assert row["backups"]["done_24h"] == 1
    assert row["backups"]["failing_vm_ids"] == []
    assert row["backups"]["overdue_vm_ids"] == []
    assert not {"backup-failures", "backup-overdue"} & set(row["alerts"])


def test_a_disabled_policy_whose_last_run_failed_raises_nothing(
    operator_client: APIClient,
) -> None:
    make_dispatchable_identity(1)
    vm = _vm("vm-a", 1)
    _policy(vm, enabled=False)
    _run(vm, RunStatus.FAILED.value, timedelta(hours=1))
    row = _row(_fleet(operator_client), 1)
    assert not {"backup-failures", "backup-overdue"} & set(row["alerts"])


def test_a_failure_a_later_success_superseded_is_not_an_alert(
    operator_client: APIClient,
) -> None:
    make_dispatchable_identity(1)
    vm = _vm("vm-a", 1)
    _policy(vm)
    _run(vm, RunStatus.FAILED.value, timedelta(hours=3))
    _run(vm, RunStatus.DONE.value, timedelta(hours=2))
    row = _row(_fleet(operator_client), 1)
    assert row["backups"]["failed_24h"] == 1
    assert row["backups"]["failing_vm_ids"] == []
    assert not {"backup-failures", "backup-overdue"} & set(row["alerts"])


def test_an_enabled_policy_whose_last_run_failed_is_failing(operator_client: APIClient) -> None:
    make_dispatchable_identity(1)
    vm = _vm("vm-a", 1)
    _policy(vm)
    _run(vm, RunStatus.DONE.value, timedelta(hours=3))
    _run(vm, RunStatus.FAILED.value, timedelta(hours=2))
    row = _row(_fleet(operator_client), 1)
    assert row["backups"]["failing_vm_ids"] == ["vm-a"]
    assert "backup-failures" in row["alerts"]


def test_a_late_daily_backup_is_overdue_even_outside_the_window(
    operator_client: APIClient,
) -> None:
    """Nothing ran in the last 24 h, so the window counts are empty — the
    late backup must still show."""
    make_dispatchable_identity(1)
    vm = _vm("vm-a", 1)
    _policy(vm)
    _run(vm, RunStatus.DONE.value, timedelta(hours=2 * 24 + 2))
    row = _row(_fleet(operator_client), 1)
    assert row["backups"]["done_24h"] == 0
    assert row["backups"]["overdue_vm_ids"] == ["vm-a"]
    assert "backup-overdue" in row["alerts"]


def test_a_daily_backup_within_its_window_is_not_overdue(operator_client: APIClient) -> None:
    make_dispatchable_identity(1)
    vm = _vm("vm-a", 1)
    _policy(vm)
    # Taken 25 h ago: past one interval but inside interval + 2 h.
    _run(vm, RunStatus.DONE.value, timedelta(hours=25))
    row = _row(_fleet(operator_client), 1)
    assert row["backups"] is None
    assert not {"backup-failures", "backup-overdue"} & set(row["alerts"])


def test_a_daily_backup_is_overdue_past_26_hours(operator_client: APIClient) -> None:
    make_dispatchable_identity(1)
    vm = _vm("vm-a", 1)
    _policy(vm)
    _run(vm, RunStatus.DONE.value, timedelta(hours=26, minutes=5))
    row = _row(_fleet(operator_client), 1)
    assert row["backups"]["overdue_vm_ids"] == ["vm-a"]
    assert "backup-overdue" in row["alerts"]


def test_a_reboot_is_not_lateness(operator_client: APIClient) -> None:
    """A reboot leaves no restore point (the VM shows `stale`) but the
    tick starts the new full at once: not overdue while it runs, nor
    until the window has passed since the last good backup."""
    make_dispatchable_identity(1)
    vm = _vm("vm-a", 1)
    _policy(vm)
    _run(vm, RunStatus.DONE.value, timedelta(hours=2), boot_counter=1)
    assert backup_service.backup_state(vm, vm.backup_policy) == backup_service.BackupState.STALE
    row = _row(_fleet(operator_client), 1)
    assert row["backups"]["overdue_vm_ids"] == []
    BackupRun.objects.update(finished_at=timezone.now() - timedelta(days=3))
    assert _row(_fleet(operator_client), 1)["backups"]["overdue_vm_ids"] == ["vm-a"]


def test_a_run_in_flight_is_not_overdue(operator_client: APIClient) -> None:
    make_dispatchable_identity(1)
    vm = _vm("vm-a", 1)
    _policy(vm)
    _run(vm, RunStatus.DONE.value, timedelta(days=3))
    _run(vm, RunStatus.RUNNING.value, timedelta(minutes=5))
    row = _row(_fleet(operator_client), 1)
    assert not {"backup-failures", "backup-overdue"} & set(row["alerts"])


def test_a_vm_just_powered_on_is_not_overdue(operator_client: APIClient) -> None:
    make_dispatchable_identity(1)
    vm = _vm("vm-a", 1, power_state_at=timezone.now() - timedelta(minutes=1))
    _policy(vm)
    _run(vm, RunStatus.DONE.value, timedelta(days=5))
    row = _row(_fleet(operator_client), 1)
    assert not {"backup-failures", "backup-overdue"} & set(row["alerts"])


def test_no_backup_alert_while_the_feature_is_off(
    operator_client: APIClient, settings: Any
) -> None:
    settings.VALI_BACKUP_ENABLED = False
    make_dispatchable_identity(1)
    _policy(_vm("vm-a", 1))
    assert _row(_fleet(operator_client), 1)["backups"] is None


def test_a_first_full_that_never_landed(operator_client: APIClient) -> None:
    make_dispatchable_identity(1)
    make_dispatchable_identity(2)
    _policy(_vm("vm-new", 1), age=timedelta(hours=1))
    _policy(_vm("vm-old", 2), age=timedelta(days=3))
    body = _fleet(operator_client)
    assert _row(body, 1)["backups"] is None
    assert _row(body, 2)["backups"]["overdue_vm_ids"] == ["vm-old"]
    assert "backup-overdue" in _row(body, 2)["alerts"]


def test_a_stopped_vm_owes_no_backup(operator_client: APIClient) -> None:
    """The tick only backs up running VMs (`_maybe_start`)."""
    make_dispatchable_identity(1)
    vm = _vm("vm-a", 1, power_state=VmPowerState.STOPPED)
    _policy(vm)
    _run(vm, RunStatus.DONE.value, timedelta(days=3))
    row = _row(_fleet(operator_client), 1)
    assert not {"backup-failures", "backup-overdue"} & set(row["alerts"])


def test_backup_alerts_land_on_the_vms_current_host(operator_client: APIClient) -> None:
    make_dispatchable_identity(1)
    make_dispatchable_identity(2)
    vm = _vm("vm-a", 2)
    _policy(vm)
    run = _run(vm, RunStatus.FAILED.value, timedelta(hours=1))
    BackupRun.objects.filter(pk=run.pk).update(miner_id="miner-01")
    body = _fleet(operator_client)
    assert "backup-failures" not in _row(body, 1)["alerts"]
    assert _row(body, 1)["backups"]["failed_24h"] == 1
    assert _row(body, 2)["backups"]["failing_vm_ids"] == ["vm-a"]


def test_a_stale_placement_elsewhere_does_not_carry_the_alert(operator_client: APIClient) -> None:
    make_dispatchable_identity(1)
    make_dispatchable_identity(2)
    vm = _vm("vm-a", 2)
    make_placement(vm, node_id(1), status=PlacementStatus.BOUND.value)
    _policy(vm)
    _run(vm, RunStatus.FAILED.value, timedelta(hours=1))
    body = _fleet(operator_client)
    assert "backup-failures" not in _row(body, 1)["alerts"]
    assert "backup-failures" in _row(body, 2)["alerts"]


def test_flavor_headroom_marks_the_sizes_that_are_not_offered(settings) -> None:
    from apps.operator import fleet

    assert fleet._flavor_headroom(None)["4xlarge"]["offered"] is True  # no cap by default
    settings.VALI_SCHEDULER_MAX_FLAVOR = "2xlarge"
    board = fleet._flavor_headroom(None)
    assert board["2xlarge"]["offered"] is True
    assert board["4xlarge"]["offered"] is False


# ─── the DATA-disk dimension (storage-aware placement) ───────────────


def test_disk_fields_policy_and_over_claim_alarm(operator_client: APIClient, settings) -> None:
    settings.VALI_SCHEDULER_DISK_GATE = "enforce"
    make_dispatchable_identity(1)
    _mirror(1, slots=8, mem=65536, cpus=16)
    MinerCapacity.objects.filter(miner_node_id=node_id(1)).update(
        total_disk_gb=4000,
        declared_disk_gb_budget=2000,
        reported_data_disk_total_gb=3500,
        reported_data_disk_available_gb=100,
        reported_staging_disk_available_gb=300,
        disk_reported_at=timezone.now(),
    )
    make_placement(
        _vm("vm-d1", 1), node_id(1), status=PlacementStatus.BOUND.value, resource_class="xlarge"
    )
    body = _fleet(operator_client, chain="false")
    disk = _row(body, 1)["capacity"]["disk"]
    assert disk == {
        "gate_mode": "enforce",
        "gate_state": "apply",
        "known": True,
        "anchor_total_gb": 4000,
        "declared_budget_gb": 2000,
        "reported_total_gb": 3500,
        "reported_free_gb": 100,
        "reported_staging_free_gb": 300,
        "reported_at": disk["reported_at"],
        "earned_disk_gb": None,
        "committed_gb": 330,
        "effective_gb": 2000,
        # budget − committed = 1670, clamped DOWN by the reported 100 −
        # the 100 GiB reserve.
        "free_gb": 0,
        "binding": "disk:declared",
        # 100 available < 330 committed − 50 slack.
        "over_claim": True,
    }
    assert disk["reported_at"] is not None
    assert "disk-over-claim" in _row(body, 1)["alerts"]
    headroom = _row(body, 1)["capacity"]["flavor_headroom"]
    assert headroom["small"]["disk"] == {"need_gb": 50, "fits_now": 0, "fits_hardware": True}
    assert headroom["4xlarge"]["disk"] == {"need_gb": 1290, "fits_now": 0, "fits_hardware": True}
    policy = body["policy"]
    assert policy["disk_gate"] == "enforce"
    assert policy["disk_unknown"] == "allow"
    assert policy["disk_reserve_gb"] == 100
    assert policy["flavors"]["large"]["disk_gb"] == 160
    assert policy["flavors"]["large"]["committed_disk_gb"] == 170


def test_a_host_without_disk_data_is_unknown_not_alarmed(operator_client: APIClient) -> None:
    make_dispatchable_identity(1)
    _mirror(1, slots=8, mem=65536, cpus=16)
    row = _row(_fleet(operator_client, chain="false"), 1)
    disk = row["capacity"]["disk"]
    assert (disk["gate_mode"], disk["gate_state"], disk["known"]) == ("record", "off", False)
    assert (disk["effective_gb"], disk["free_gb"], disk["over_claim"]) == (None, None, False)
    assert "disk-over-claim" not in row["alerts"]
