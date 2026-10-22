"""E4: a resize of a VM pinned by dedicated disks happens in place or not
at all (contract §5: `dedicated-pinned` for a resize that needs a
migration). The resize machinery: `test_resize.py`, whose rig this reuses."""

from __future__ import annotations

from typing import Any

import pytest
from django.test import override_settings

from apps.disktier.models import DedicatedDisk
from apps.orchestration import resize, service
from apps.orchestration.models import ResizeState
from apps.orchestration.service import StartError
from apps.scheduler.models import MinerCapacity

from .test_resize import (  # noqa: F401 — autouse fixtures and the fake miner
    HOST_NODE,
    OTHER,
    _catalogue,
    _hosts,
    _job,
    _settings,
    _start,
    _tick,
    _vm,
    miner,
)

pytestmark = pytest.mark.django_db


def _pin(vm) -> None:
    DedicatedDisk.objects.create(
        miner_node_id=HOST_NODE,
        disk_id="wwn-0x01",
        state="assigned",
        assigned_vm=vm,
        assigned_slot="x0",
        size_bytes=20000 * 2**30,
        verified_tier="hdd",
    )


def _no_room_here(monkeypatch) -> None:
    MinerCapacity.objects.filter(miner_node_id=HOST_NODE).update(total_memory_mb=13_000)
    monkeypatch.setattr(resize, "_pick_destination", lambda *a: (OTHER, ""))


def test_a_stopped_pinned_vm_that_does_not_fit_is_dedicated_pinned_too(monkeypatch) -> None:
    """The same category as the options read gives the same target."""
    from apps.lifecycle.models import VmPowerState

    vm = _vm(power_state=VmPowerState.STOPPED)
    _pin(vm)
    _no_room_here(monkeypatch)
    with pytest.raises(StartError) as exc:
        _start(vm, "compact-4")
    assert exc.value.category == "dedicated-pinned"
    options = {o.flavor: o for o in resize.compatible_flavors(vm).options}
    assert options["compact-4"].reason == "dedicated-pinned"


def test_a_resize_that_needs_a_migration_is_refused(monkeypatch) -> None:
    vm = _vm()
    _pin(vm)
    _no_room_here(monkeypatch)
    with pytest.raises(StartError) as exc:
        _start(vm, "compact-4")
    assert exc.value.category == "dedicated-pinned"
    assert _job(vm) is None


def test_the_same_resize_of_an_unpinned_vm_migrates(monkeypatch) -> None:
    vm = _vm()
    _no_room_here(monkeypatch)
    assert _start(vm, "compact-4").state == ResizeState.PENDING


def _real_relaunch_rig(monkeypatch) -> tuple[Any, list[dict[str, Any]], list[Any], list[dict]]:
    """A pinned VM (two disks assigned on its host) whose relaunches go
    through the REAL `launch_on_miner`, everything past it stubbed. Returns
    `(vm, payloads, outcomes, expected extra_disks)`."""
    from apps.disktier import dedicated
    from apps.disktier.tests.dedicated_helpers import ON, capable, make_disk
    from apps.orchestration import effects, order_dispatch
    from apps.orchestration.models import LaunchJob
    from apps.orchestration.services import launch, preflight, vault_kv
    from apps.orchestration.tests.test_launch_service import _fake_the_launch_choreography
    from apps.scheduler.models import Placement

    _fake_the_launch_choreography(monkeypatch, dispatch_ok=True)
    monkeypatch.setattr(
        preflight,
        "dispatch_preflight",
        lambda *a, **k: preflight.PreflightResult(
            launch_digest_hex="ab" * 48,
            luks_disk_path="/d.img",
            kernel_path="/k",
            initrd_path="/i",
            rootfs_data_path=f"/var/lib/hippius-miner/staging/{k['vm_id']}/rootfs.img",
            rootfs_hash_path=f"/var/lib/hippius-miner/staging/{k['vm_id']}/rootfs.verity",
        ),
    )
    payloads: list[dict[str, Any]] = []
    monkeypatch.setattr(
        order_dispatch, "build_launch_payload", lambda *a, **k: payloads.append(k) or {}
    )
    outcomes: list[dict[str, Any]] = []
    real_launch = launch.launch_on_miner

    def recording(*a: Any, **k: Any) -> Any:
        out = real_launch(*a, **k)
        outcomes.append(out.emit)
        return out

    monkeypatch.setattr(launch, "launch_on_miner", recording)
    running = {"up": True}
    monkeypatch.setattr(effects, "dispatch_graceful_stop", lambda *a, **k: running.update(up=False))
    monkeypatch.setattr(effects, "poll_domain_running", lambda *a, **k: running["up"])
    monkeypatch.setattr(vault_kv, "get_kv", lambda *a, **k: b"user-data")
    monkeypatch.setattr(vault_kv, "latest_version", lambda *a, **k: 1)
    # The §22 ledger a superseding relaunch marks is the pin's subject, not this.
    monkeypatch.setattr(launch, "_mark_superseded_at_register", lambda *a, **k: True)
    monkeypatch.setattr(
        launch,
        "open_userdata_intake_copy",
        lambda *a, **k: b"#cloud-config\n# {{NETBIRD_SETUP_KEY}}\n",
    )
    with override_settings(**ON):
        vm = _vm()
        job = LaunchJob.objects.get(vm_id=vm.vm_id)
        job.spec_json = {
            **job.spec_json,
            "dedicated_disks": {"tier": "hdd", "count": 2, "min_size_gb": 16000},
            "pinned_ack": True,
            # The §22 pin is not this test's subject (its own suite covers it).
            "auto_pin_allowlist": False,
        }
        job.save()
        capable(HOST_NODE)
        make_disk("wwn-0x01", node=HOST_NODE, size_gib=22354)
        make_disk("wwn-0x02", node=HOST_NODE, size_gib=16050)
        dedicated.assign(
            Placement.objects.get(vm=vm),
            vm,
            dedicated.DedicatedRequest("hdd", 2, 16000),
        )
    expected = [
        {"slot": d.slot, "kind": "dedicated", "disk_id": d.disk_id}
        for d in dedicated.extra_disks(vm.vm_id, HOST_NODE)
    ]
    assert len(expected) == 2
    return vm, payloads, outcomes, expected


def _assert_same_disks_and_token(payload: dict[str, Any], expected: list[dict]) -> None:
    assert payload["require_existing_disks"] is True
    assert payload["extra_disks"] == expected
    tokens = [t for t in payload["cmdline"].split() if t.startswith("hippius.dedicated=")]
    assert tokens == ["hippius.dedicated=x0:16000,x1:22300"]


def test_an_in_place_resize_relaunches_with_the_same_disks_and_token(monkeypatch) -> None:
    """End to end through the REAL `launch_on_miner`: a pinned VM's in-place
    resize stops it and relaunches it at the new size, and the relaunch
    order names the same disks, slots and measured token as before."""
    vm, payloads, outcomes, expected = _real_relaunch_rig(monkeypatch)
    resize_job = _start(vm, "compact-2")
    _tick(3)
    resize_job.refresh_from_db()
    assert resize_job.state in (ResizeState.RELAUNCHING, ResizeState.DONE), resize_job.reason
    assert len(payloads) == 1, outcomes
    _assert_same_disks_and_token(payloads[0], expected)
    assert "hippius.resource_class=compact-2" in payloads[0]["cmdline"].split()


def test_a_reboot_recovery_relaunch_sends_the_same_disks_and_token(monkeypatch) -> None:
    """The reboot-recovery / power-start relaunch rebuilds its spec from the
    launch record and still names the VM's disks and measures its token."""
    vm, payloads, outcomes, expected = _real_relaunch_rig(monkeypatch)
    assert service._reboot_recovery_relaunch(vm, vm.host) is True, outcomes
    (relaunch,) = payloads
    _assert_same_disks_and_token(relaunch, expected)
    assert "hippius.resource_class=small" in relaunch["cmdline"].split()


def test_a_resize_that_stops_fitting_before_its_tick_fails_rather_than_migrates(
    miner,  # noqa: F811
    monkeypatch,
) -> None:
    vm = _vm()
    job = _start(vm, "compact-4")
    _pin(vm)
    _no_room_here(monkeypatch)
    started: list[Any] = []
    monkeypatch.setattr(service, "start_migration", lambda **kw: started.append(kw))
    _tick()
    job.refresh_from_db()
    assert job.state == ResizeState.FAILED
    assert job.reason.startswith("dedicated-pinned")
    assert started == []


def test_the_options_read_offers_no_migrating_target(monkeypatch) -> None:
    vm = _vm()
    _pin(vm)
    _no_room_here(monkeypatch)
    options = {o.flavor: o for o in resize.compatible_flavors(vm).options}
    assert options["compact-4"].reason == "dedicated-pinned"
    assert not options["compact-4"].needs_migration and not options["compact-4"].available
