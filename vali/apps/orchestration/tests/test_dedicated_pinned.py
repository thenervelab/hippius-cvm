"""E4: a VM pinned by dedicated disks never leaves its host (contract §5:
409 `dedicated-pinned` for §25 migration, restore, failover; the failover
worker and the graceful-exit drain skip it), and §24 releases its disks to
`released`, from where only the agent's "wiped and free" report moves them
on — to `pending_probe`, never back to `free` (design §5.2)."""

from __future__ import annotations

from datetime import timedelta
from typing import Any

import pytest
from django.urls import reverse
from django.utils import timezone

from apps.disktier import dedicated
from apps.disktier.ingest import record_storage_report
from apps.disktier.models import DedicatedDisk, PlacementDisk
from apps.lifecycle.models import VmState
from apps.orchestration import failover_auto, restore, service
from apps.orchestration.models import DecommissionState
from apps.orchestration.service import StartError
from apps.scheduler.models import PlacementStatus
from apps.scheduler.tests.factories import make_placement, node_id
from apps.telemetry.verifier import DeclaredDedicatedDisk, DeclaredPool, DeclaredStorage

from .factories import make_launch_record, make_service_client, make_vm
from .test_cvm_capability_feedback import (  # noqa: F401 — autouse fixture
    SRC_NODE,
    _bridged_same_gen_miners,
    _departing_drain,
    _mirror,
)

pytestmark = pytest.mark.django_db

NODE = node_id(1)
DISK = "wwn-0x5000c500a1b2c3d4"


def _disk(vm=None, *, slot: str = "x0", disk_id: str = DISK, **kw: Any) -> DedicatedDisk:
    fields: dict[str, Any] = dict(
        miner_node_id=NODE,
        disk_id=disk_id,
        size_bytes=20000 * 2**30,
        verified_tier="hdd",
        reported_state="assigned" if vm is not None else "free",
        reported_vm_id=vm.vm_id if vm is not None else "",
        reported_at=timezone.now(),
    )
    if vm is not None:
        fields.update(state="assigned", assigned_vm=vm, assigned_slot=slot)
    else:
        fields.update(state="free")
    fields.update(kw)
    return DedicatedDisk.objects.create(**fields)


def _pinned_vm(vm_id: str = "vm-1", **vm_kw: Any):
    vm = make_vm(vm_id, **vm_kw)
    placement = make_placement(vm, NODE, status=PlacementStatus.BOUND.value)
    disk = _disk(vm)
    PlacementDisk.objects.create(
        placement=placement,
        slot="x0",
        kind="dedicated",
        dedicated_disk=disk,
        size_gb=20000,
        required_tier="hdd",
    )
    return vm


# ── what pins a VM ──────────────────────────────────────────────────


def test_what_pins_a_vm() -> None:
    plain = make_vm("vm-plain")
    assert dedicated.is_pinned(plain) is False
    rows = _pinned_vm("vm-rows")
    assert dedicated.is_pinned(rows) is True
    # Its disk failed (no longer assigned to it): its slot rows still pin it.
    DedicatedDisk.objects.filter(assigned_vm=rows).update(
        state="failed", assigned_vm=None, assigned_slot=""
    )
    assert dedicated.is_pinned(rows) is True
    held = make_vm("vm-held")
    _disk(held, disk_id="wwn-0x02")
    assert dedicated.is_pinned(held) is True
    sold = make_vm("vm-sold")
    job = make_launch_record(sold)
    job.spec_json = {
        **job.spec_json,
        "dedicated_disks": {"tier": "hdd", "count": 1, "min_size_gb": 1000},
    }
    job.save()
    assert dedicated.is_pinned(sold) is True
    job.spec_json = {**job.spec_json, "dedicated_disks": "garbage"}
    job.save()
    assert dedicated.is_pinned(sold) is True, "a malformed record fails closed"


# ── §25 migration ───────────────────────────────────────────────────


def test_a_pinned_vm_is_never_migrated() -> None:
    vm = _pinned_vm()
    with pytest.raises(StartError) as exc:
        service.start_migration(vm=vm, dest_node_id="node-dst", decided_by=make_service_client())
    assert exc.value.category == "dedicated-pinned"


def test_the_migrate_api_answers_409(root_client) -> None:
    _pinned_vm()
    resp = root_client.post(
        reverse("vm_migrate", args=["vm-1"]), {"dest_node_id": "node-dst"}, format="json"
    )
    assert resp.status_code == 409, resp.content
    assert resp.json()["category"] == "dedicated-pinned"


def test_an_unpinned_vm_is_refused_for_its_own_reasons_only() -> None:
    vm = make_vm("vm-plain")
    with pytest.raises(StartError) as exc:
        service.start_migration(vm=vm, dest_node_id="node-src", decided_by=make_service_client())
    assert exc.value.category == "same-node"


def _vm_on_departing_source():
    from .test_graceful_exit_region import _bound_vm_on_source, _locate

    vm = _bound_vm_on_source(region="FR")
    _locate("node-dst", "FR")
    return vm


def test_the_graceful_exit_drain_skips_a_pinned_vm(monkeypatch) -> None:
    vm = _vm_on_departing_source()
    _disk(vm, miner_node_id=SRC_NODE)
    report: dict[str, str] = {}
    real = service.enroll_departing_miner_migrations
    monkeypatch.setattr(
        service,
        "enroll_departing_miner_migrations",
        lambda **kw: real(report=report, **kw),
    )
    assert _departing_drain(monkeypatch) == []
    assert report == {vm.vm_id: "dedicated-pinned"}


def test_the_graceful_exit_drain_still_moves_an_unpinned_vm(monkeypatch) -> None:
    _vm_on_departing_source()
    assert len(_departing_drain(monkeypatch)) == 1


# ── restore and failover ────────────────────────────────────────────


def test_a_pinned_vm_is_never_restored(settings) -> None:
    settings.VALI_RESTORE_ENABLED = True
    vm = _pinned_vm()
    with pytest.raises(restore.RestoreError) as exc:
        restore.start_restore(
            vm=vm, run_id="a" * 32, request_id="r-1", decided_by=make_service_client()
        )
    assert exc.value.code == "dedicated-pinned"


def test_a_pinned_vm_is_never_failed_over(settings) -> None:
    settings.VALI_FAILOVER_MANUAL_ENABLED = True
    vm = _pinned_vm()
    with pytest.raises(restore.RestoreError) as exc:
        restore.start_failover(vm=vm, request_id="f-1", decided_by=make_service_client())
    assert exc.value.code == "dedicated-pinned"


def test_the_restore_and_failover_apis_answer_409(root_client, settings) -> None:
    settings.VALI_RESTORE_ENABLED = True
    settings.VALI_FAILOVER_MANUAL_ENABLED = True
    _pinned_vm()
    resp = root_client.post(
        reverse("vm_restore", args=["vm-1"]),
        {"run_id": "a" * 32, "request_id": "r-1"},
        format="json",
    )
    assert (resp.status_code, resp.json()["error"]) == (409, "dedicated-pinned"), resp.content
    resp = root_client.post(
        reverse("vm_failover", args=["vm-1"]), {"request_id": "f-1"}, format="json"
    )
    assert (resp.status_code, resp.json()["error"]) == (409, "dedicated-pinned"), resp.content


def test_the_failover_worker_skips_a_pinned_vm() -> None:
    from apps.backup.models import BackupPolicy, FailoverMode

    vm = _pinned_vm(host="node-dead")
    BackupPolicy.objects.create(vm=vm, interval_s=3600, failover_mode=FailoverMode.AUTO)
    failover_auto._skips.clear()
    verdict = failover_auto._try_one(vm.pk, "node-dead", None, None, timezone.now())
    assert verdict == "skipped"
    assert failover_auto._skips[vm.vm_id] == ("node-dead", "dedicated-pinned")


# ── §24 and the way back to sale ────────────────────────────────────


def test_decommission_releases_the_disks_and_keeps_the_rows(fx) -> None:
    vm = _pinned_vm(generation=5, host="node-src")
    job = service.start_decommission(vm=vm, decided_by=make_service_client())
    for _ in range(25):
        service.tick_once()
    job.refresh_from_db()
    vm.refresh_from_db()
    assert (job.state, vm.state) == (DecommissionState.DONE.value, VmState.DESTROYED)
    disk = DedicatedDisk.objects.get(disk_id=DISK)
    assert (disk.state, disk.assigned_vm_id, disk.assigned_slot) == ("released", None, "")
    assert disk.freed_at is not None
    assert PlacementDisk.objects.filter(dedicated_disk=disk).count() == 1
    assert [d["state"] for d in dedicated.read_back(vm, os_disk=(40, "nvme"))["disks"]] == [
        "attached",
        "released",
    ]


def test_release_is_idempotent_and_closes_a_failed_slot() -> None:
    vm = _pinned_vm()
    failed = _disk(None, disk_id="wwn-0x02", state="failed")
    placement = vm.placements.get()
    PlacementDisk.objects.create(
        placement=placement,
        slot="x1",
        kind="dedicated",
        dedicated_disk=failed,
        size_gb=20000,
        required_tier="hdd",
    )
    assert dedicated.release_for_destroyed_vm(vm) == 1
    assert dedicated.release_for_destroyed_vm(vm) == 0
    failed.refresh_from_db()
    assert failed.state == "failed" and failed.freed_at is not None


def test_the_lifecycle_transition_to_destroyed_releases_too(
    root_client, monkeypatch, settings, tmp_path
) -> None:
    from apps.lifecycle import validator

    binary = tmp_path / "hippius-ticket-validator"
    binary.write_text("# placeholder\n")
    binary.chmod(0o755)
    settings.VALI_TICKET_VALIDATOR_BIN = str(binary)
    monkeypatch.setattr(
        validator,
        "verify_stopped_ack",
        lambda **_kw: validator.VerifiedStoppedAck(now_unix=1_700_000_000),
    )
    vm = _pinned_vm(state=VmState.DECOMMISSIONING)
    resp = root_client.post(
        reverse("vm_transition", args=[vm.vm_id]),
        {"to_state": "destroyed", "if_version": vm.version, "signed_stopped_ack_hex": "00" * 8},
        format="json",
    )
    assert resp.status_code == 200, resp.content
    assert DedicatedDisk.objects.get(disk_id=DISK).state == "released"


def _report(state: str, *, vm: str = "", error: str = "") -> DeclaredStorage:
    return DeclaredStorage(
        pools=(
            DeclaredPool(
                pool_id="default",
                declared_class="nvme",
                total_gb=1000,
                available_gb=500,
                budget_gb=0,
                committed_gb=0,
                os_disks=True,
                state="active",
                error="",
            ),
        ),
        dedicated_disks=(
            DeclaredDedicatedDisk(
                disk_id=DISK, size_mb=20000 * 1024, state=state, vm=vm, error=error
            ),
        ),
        storage_config_revision=0,
    )


def _released() -> DedicatedDisk:
    vm = _pinned_vm()
    dedicated.release_for_destroyed_vm(vm)
    return DedicatedDisk.objects.get(disk_id=DISK)


@pytest.mark.parametrize(
    ("state", "vm", "error"),
    [
        ("assigned", "vm-1", ""),  # the agent still holds it (wipe pending)
        ("failed", "", ""),
        ("free", "", "disk-has-signature"),  # the wipe did not clear it
        ("unavailable", "", ""),
    ],
)
def test_a_released_disk_stays_released_until_reported_wiped_and_free(state, vm, error) -> None:
    disk = _released()
    record_storage_report(NODE, _report(state, vm=vm, error=error), timezone.now())
    disk.refresh_from_db()
    assert disk.state == "released"


def test_a_released_disk_reported_free_waits_for_a_probe_never_free() -> None:
    disk = _released()
    # A report older than the release says nothing about the wipe.
    record_storage_report(NODE, _report("free"), disk.freed_at - timedelta(seconds=1))
    disk.refresh_from_db()
    assert disk.state == "released"
    record_storage_report(NODE, _report("free"), timezone.now() + timedelta(seconds=1))
    disk.refresh_from_db()
    assert disk.state == "pending_probe"
    assert dedicated.free_counts(dedicated.DedicatedRequest("hdd", 1, 1000), [NODE]) == {}, (
        "a disk waiting for its probe is never placeable"
    )


def test_a_released_disk_the_agent_still_names_a_vm_on_stays_released() -> None:
    """Defence in depth: the heartbeat verifier never lets `free` carry a VM,
    but the reconcile does not rely on it."""
    disk = _released()
    DedicatedDisk.objects.filter(pk=disk.pk).update(
        reported_state="free", reported_vm_id="vm-1", reported_at=timezone.now()
    )
    assert dedicated.reconcile_released(NODE, timezone.now()) == 0
    disk.refresh_from_db()
    assert disk.state == "released"


# ── crash safety of the release ─────────────────────────────────────


def test_a_destroy_rerun_after_a_crash_still_releases(fx) -> None:
    vm = _pinned_vm(generation=5, host="node-src")
    job = service.start_decommission(vm=vm, decided_by=make_service_client())
    # The crash: the tombstone committed, the release never ran.
    type(vm).objects.filter(pk=vm.pk).update(state=VmState.DESTROYED)
    service._destroy_vm(job)
    assert DedicatedDisk.objects.get(disk_id=DISK).state == "released"


def test_the_heartbeat_releases_a_disk_its_destroyed_vm_still_holds() -> None:
    vm = _pinned_vm()
    type(vm).objects.filter(pk=vm.pk).update(state=VmState.DESTROYED)
    now = timezone.now()
    record_storage_report(NODE, _report("assigned", vm=vm.vm_id), now)
    disk = DedicatedDisk.objects.get(disk_id=DISK)
    assert disk.state == "released", "released by the safety net"
    # ...and not moved on by the very report that released it.
    record_storage_report(NODE, _report("free"), now)
    disk.refresh_from_db()
    assert disk.state == "released"
    record_storage_report(NODE, _report("free"), timezone.now() + timedelta(seconds=1))
    disk.refresh_from_db()
    assert disk.state == "pending_probe"


# ── the raw state machine and the guest release ─────────────────────


def test_the_raw_transition_to_migrating_refuses_a_pinned_vm(root_client) -> None:
    vm = _pinned_vm()
    resp = root_client.post(
        reverse("vm_transition", args=[vm.vm_id]),
        {
            "to_state": "migrating",
            "if_version": vm.version,
            "new_generation": vm.generation + 1,
            "migration_dest": "node-dst",
        },
        format="json",
    )
    assert (resp.status_code, resp.json()["category"]) == (409, "dedicated-pinned"), resp.content
    vm.refresh_from_db()
    assert vm.state == VmState.ACTIVE


@pytest.mark.parametrize(("release", "refused"), [(None, True), (5, True), (6, False), (7, False)])
def test_a_pinned_vm_never_boots_a_guest_below_the_release(
    settings, monkeypatch, release, refused
) -> None:
    from types import SimpleNamespace

    from apps.orchestration import guest_upgrade
    from apps.orchestration.services import launch_digest

    monkeypatch.setattr(launch_digest, "enforce", lambda: True)
    monkeypatch.setattr(launch_digest, "is_enabled", lambda: True)
    settings.VALI_DEDICATED_MIN_GUEST_RELEASE = 6
    pinned = _pinned_vm()
    plain = make_vm("vm-plain")
    assert bool(dedicated.guest_release_refusal(pinned, release)) is refused
    assert dedicated.guest_release_refusal(plain, release) == ""
    if release is None:
        return
    build = SimpleNamespace(
        withdrawn_at=None,
        release=SimpleNamespace(withdrawn_at=None),
        release_id=release,
        s3_key_prefix="p/",
    )
    refusal = guest_upgrade._refusal(pinned, build, rollback=False)
    if refused:
        assert refusal is not None and refusal[0] == "dedicated-needs-release"
    else:
        assert refusal is None or refusal[0] != "dedicated-needs-release"


def test_an_initrd_swap_of_a_pinned_vm_needs_a_known_release_at_the_minimum(settings) -> None:
    from apps.orchestration.management.commands import vali_swap_vm_initrd as swap

    settings.VALI_DEDICATED_MIN_GUEST_RELEASE = 6
    vm = _pinned_vm()
    make_launch_record(vm, disk_mode="golden_verity_overlay")
    rebuild = swap.Rebuild(
        s3_key_prefix="tenant/r/",
        s3_bucket="b",
        source_bake_id="bake",
        source_initrd_sha256="1" * 64,
        initrd_sha256="2" * 64,  # a rebuild of no known guest release
        kernel_sha256="3" * 64,
        rootfs_img_sha256="4" * 64,
        rootfs_verity_sha256="5" * 64,
        verity_root_hash="6" * 64,
        document={},
    )
    outcome, _detail = swap.verdict(vm, rebuild)
    assert outcome == "dedicated-needs-release"
