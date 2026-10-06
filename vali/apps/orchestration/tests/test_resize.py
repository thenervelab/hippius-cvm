"""VM resize — vCPU/RAM change, data disk unchanged (`apps.orchestration.resize`).

Each test pins one CLAIM the resize makes, against a fake miner that sits
where the real one does: `effects.dispatch_graceful_stop` (the power stop)
and `launch.launch_on_miner` (the relaunch the power start runs through
`_reboot_recovery_relaunch`, whose spec/record/placement logic runs for
real here):

1. the data disk never changes — a different-disk flavor is refused before
   anything moves, and the relaunch boots the same `disk_gb`;
2. the relaunch goes through the launch choreography (auto-pin, existing
   disks, current generation) at the NEW flavor, and the launch record
   moves with the measurement;
3. a failure before the new-size relaunch is accepted puts the VM back;
4. capacity is reserved once — never twice, never zero times, never below
   what runs;
5. a stopped VM is resized on the books and stays stopped;
6. no other actor can power or move the VM while it is resized.

The catalogue has no two flavors with the same data disk today, so these
tests extend it with two (`compact-*`, 40 GB like `small`).
"""

from __future__ import annotations

from datetime import timedelta
from types import SimpleNamespace
from typing import Any

import pytest
from django.test import override_settings
from django.utils import timezone

from apps.lifecycle.models import Vm, VmPowerState, VmState
from apps.miners.models import MinerIdentity, MinerStatus
from apps.orchestration import effects, resize, service
from apps.orchestration.models import (
    LaunchJob,
    LaunchJobState,
    MigrationState,
    ResizeJob,
    ResizeState,
)
from apps.orchestration.service import StartError
from apps.orchestration.services import flavors, launch, launch_record, power
from apps.scheduler import service as sched
from apps.scheduler.models import (
    ACTIVE_PLACEMENT_STATES,
    MinerCapacity,
    Placement,
    PlacementFailureSource,
    PlacementStatus,
)

from .factories import make_service_client, make_vm

pytestmark = [
    pytest.mark.django_db,
]

HOST = "miner-a"
HOST_NODE = "a1" * 32
OTHER = "miner-b"
OTHER_NODE = "b2" * 32

#: Two flavors sharing `small`'s 40 GB data disk: a grow and a bigger grow.
EXTRA_FLAVORS = {
    "compact-2": {"cpu_count": 2, "memory_mb": 8192, "disk_gb": 40},
    "compact-4": {"cpu_count": 4, "memory_mb": 16384, "disk_gb": 40},
    # Neither bigger nor smaller than each other: more RAM, or more vCPU.
    "compact-mem": {"cpu_count": 2, "memory_mb": 16384, "disk_gb": 40},
    "compact-wide": {"cpu_count": 4, "memory_mb": 8192, "disk_gb": 40},
}

SETTINGS = override_settings(
    VALI_SCHEDULER_RESOURCE_ADMISSION="true",
    VALI_RESIZE_DISPATCH_PACING_S=0,
    VALI_SCHEDULER_MAX_FLAVOR="",
)


@pytest.fixture(autouse=True)
def _settings():
    with SETTINGS:
        yield


_REAL_CATALOGUE = dict(flavors._CATALOGUE)
_REAL_NAMES = flavors.FLAVOR_NAMES


@pytest.fixture(autouse=True)
def _catalogue(monkeypatch: pytest.MonkeyPatch) -> None:
    catalogue = {**flavors._CATALOGUE, **EXTRA_FLAVORS}
    monkeypatch.setattr(flavors, "_CATALOGUE", catalogue)
    monkeypatch.setattr(flavors, "FLAVOR_NAMES", tuple(catalogue))


def _miner(miner_id: str, node: str, *, memory_mb: int = 125_000, cpus: int = 24) -> None:
    MinerIdentity.objects.create(
        miner_id=miner_id,
        pubkey_hex=node[:2] * 32,
        platform_id=node[:2] * 64,
        chain_node_id=node,
        netbird_ip="100.64.0.9",
        last_seen_at=timezone.now(),
        status=MinerStatus.ACTIVE,
    )
    MinerCapacity.objects.create(
        miner_node_id=node,
        status="active",
        capacity_slots=16,
        observed_epoch=10,
        data_epoch=10,
        refreshed_at=timezone.now(),
        total_memory_mb=memory_mb,
        total_cpus=cpus,
    )


@pytest.fixture(autouse=True)
def _hosts() -> None:
    _miner(HOST, HOST_NODE)
    _miner(OTHER, OTHER_NODE)


SPEC = {
    "tenant_id": "tenant-1",
    "user_id": "user-1",
    "s3_bucket": "hippius-compute-images",
    "s3_key_prefix": "golden/ubuntu/abc",
    "luks_disk_sha256_hex": "",
    "kernel_sha256_hex": "11" * 32,
    "initrd_sha256_hex": "22" * 32,
    "luks_header_sha256_hex": "",
    "cmdline": "console=ttyS0",
    "disk_mode": "golden_verity_overlay",
    "verity_root_hash_hex": "33" * 32,
    "rootfs_img_sha256_hex": "44" * 32,
    "rootfs_verity_sha256_hex": "55" * 32,
    "bake_id": "bake-1",
    "auto_pin_allowlist": True,
}


def _measurement(flavor: str) -> str:
    return (flavor.encode().hex() * 48)[:96]


def _vm(
    vm_id: str = "vm-r",
    *,
    flavor: str = "small",
    power_state: str = VmPowerState.RUNNING,
    host: str = HOST,
    node: str = HOST_NODE,
) -> Vm:
    vm = make_vm(vm_id, host=host, generation=1)
    Vm.objects.filter(pk=vm.pk).update(power_state=power_state, power_state_at=timezone.now())
    vm.refresh_from_db()
    now = timezone.now()
    LaunchJob.objects.create(
        job_id=f"job-{vm_id}",
        vm_id=vm_id,
        tenant_id="tenant-1",
        flavor=flavor,
        spec_json={**SPEC, "vm_id": vm_id, "lease_id": vm.lease_id, "flavor": flavor},
        userdata_vault_path=f"x/{vm_id}/userdata",
        userdata_vault_version=1,
        kek_vault_path=f"x/{vm_id}/luks-kek",
        state=LaunchJobState.SUCCEEDED.value,
        phase_started_at=now,
        finished_at=now,
        result_json={"emit": {"measurement_hex": _measurement(flavor)}},
        decided_by=make_service_client(),
    )
    Placement.objects.create(
        vm=vm,
        vm_family="tenant-1",
        owner="user-1",
        resource_class=flavor,
        miner_node_id=node,
        status=PlacementStatus.BOUND.value,
        chain_epoch=10,
        bound_at=now,
        decided_by=make_service_client(),
    )
    return vm


class FakeMiner:
    """The miner side of a stop and a relaunch. Records what it was handed
    and what vali's books said at that instant."""

    def __init__(self) -> None:
        self.stops: list[dict[str, Any]] = []
        self.launches: list[dict[str, Any]] = []
        self.launch_disposition = launch.ACCEPTED
        self.launch_emit: dict[str, Any] = {}
        self.stop_error: Exception | None = None
        #: What the miner answers a domain-state probe.
        self.domain_running = True
        #: A refused launch that boots anyway (an Edge timeout that landed).
        self.boot_on_reject = False
        #: Whether a launch got as far as its KBS register before the
        #: outcome above (a superseding one then marks its pin, as
        #: `launch._mark_superseded_at_register` does).
        self.registers = True

    def stop(self, vm: Vm, **_kw: Any) -> None:
        self.stops.append({"vm_id": vm.vm_id, "placement": _active_classes(vm)})
        if self.stop_error is not None:
            raise self.stop_error
        self.domain_running = False

    def poll_domain_running(self, vm: Vm) -> bool:
        return self.domain_running

    def launch_on_miner(self, spec: Any, miner: Any, **kw: Any) -> SimpleNamespace:
        vm = Vm.objects.get(vm_id=spec.vm_id)
        self.launches.append(
            {
                "flavor": spec.flavor,
                "disk_gb": launch.data_disk_gb(spec),
                "auto_pin": spec.auto_pin_allowlist,
                "miner": miner.miner_id,
                "placement": _active_classes(vm),
                **kw,
            }
        )
        emit = self.launch_emit or (
            {
                "measurement_hex": _measurement(spec.flavor),
                "measured_cmdline": f"console=ttyS0 hippius.resource_class={spec.flavor}",
            }
            if self.launch_disposition == launch.ACCEPTED
            else {"outcome": "preflight-failure"}
        )
        if kw.get("supersede") and self.registers:
            from apps.orchestration.models import MeasurementLedger

            MeasurementLedger.objects.create(
                vm_id=spec.vm_id,
                launch_digest_hex=f"{len(self.launches):096x}",
                allowlist_epoch=1,
                superseded_at_register=timezone.now(),
            )
        if self.launch_disposition == launch.ACCEPTED or self.boot_on_reject:
            self.domain_running = True
        return SimpleNamespace(disposition=self.launch_disposition, emit=emit)


@pytest.fixture
def miner(monkeypatch: pytest.MonkeyPatch) -> FakeMiner:
    from apps.orchestration.services import vault_kv

    fake = FakeMiner()
    monkeypatch.setattr(effects, "dispatch_graceful_stop", fake.stop)
    monkeypatch.setattr(effects, "poll_domain_running", fake.poll_domain_running)
    monkeypatch.setattr(launch, "launch_on_miner", fake.launch_on_miner)
    monkeypatch.setattr(vault_kv, "get_kv", lambda mount, path, version=None: b"user-data")
    return fake


def _active_classes(vm: Vm) -> list[tuple[str, str]]:
    return list(
        Placement.objects.filter(vm=vm, status__in=ACTIVE_PLACEMENT_STATES).values_list(
            "miner_node_id", "resource_class"
        )
    )


def _committed(node: str = HOST_NODE) -> tuple[int, int, int]:
    """(vCPU, MiB, VMs) admission counts on `node`."""
    c = sched._committed_by_node().get(node, sched._Committed())
    return c.vcpus, c.memory_mb, c.vms


def _job(vm: Vm) -> ResizeJob:
    return ResizeJob.objects.filter(vm=vm).order_by("-started_at").first()


def _start(vm: Vm, to: str = "compact-2") -> ResizeJob:
    return resize.start_resize(vm=vm, to_flavor=to, decided_by=make_service_client())


def _tick(n: int = 1) -> None:
    for _ in range(n):
        resize.tick_resizes()


def _guest_signals(vm: Vm) -> None:
    Vm.objects.filter(pk=vm.pk).update(guest_signal_at=timezone.now() + timedelta(seconds=1))


def _run_to_relaunched(vm: Vm, to: str = "compact-2") -> ResizeJob:
    job = _start(vm, to)
    _tick(3)  # pending → stopping → relaunching → relaunched
    job.refresh_from_db()
    return job


# ─── claim 1: the data disk never changes ───────────────────────────


class TestDiskUnchanged:
    def test_every_other_offered_flavor_is_offered_with_the_vm_disk(self) -> None:
        vm = _vm()
        options = resize.compatible_flavors(vm)
        assert options.current_flavor == "small"
        assert [o.flavor for o in options.options] == [
            n for n in flavors.FLAVOR_NAMES if n != "small"
        ]
        assert {o.data_disk_size_gb for o in options.options} == {40}, "the disk stays"

    def test_the_real_catalogue_offers_every_other_flavor(self, monkeypatch) -> None:
        monkeypatch.setattr(flavors, "_CATALOGUE", _REAL_CATALOGUE)
        monkeypatch.setattr(flavors, "FLAVOR_NAMES", _REAL_NAMES)
        vm = _vm()
        assert [o.flavor for o in resize.compatible_flavors(vm).options] == [
            n for n in _REAL_NAMES if n != "small"
        ]

    def test_the_relaunch_boots_the_same_disk(self, miner) -> None:
        vm = _vm()
        _run_to_relaunched(vm)
        (handed,) = miner.launches
        assert handed["flavor"] == "compact-2"
        assert handed["disk_gb"] == flavors.resolve_flavor("small").data_disk_size_gb

    def test_a_large_keeps_its_40_gb_disk(self, miner) -> None:
        """small (40 GB) → large (160 GB flavor): vCPU/RAM of a large, the
        VM's own 40 GB disk — measured, ordered, recorded and accounted."""
        vm = _vm()
        _run_to_relaunched(vm, "large")
        (handed,) = miner.launches
        assert handed["flavor"] == "large" and handed["disk_gb"] == 40
        record = LaunchJob.objects.get(vm_id=vm.vm_id)
        assert record.spec_json["flavor"] == "large"
        assert record.spec_json["data_disk_size_gb"] == 40
        assert launch_record.data_disk_gb(record) == 40
        placement = Placement.objects.get(vm=vm, status__in=ACTIVE_PLACEMENT_STATES)
        assert (placement.resource_class, placement.data_disk_gb) == ("large", 40)
        cpus, mem, vms = _committed()
        assert (cpus, mem, vms) == (4, 16384, 1)
        disk = sched._committed_by_node()[HOST_NODE].disk_gb
        assert disk == 40 + flavors.ROOTFS_DISK_GB, "the real disk, not the large's 160"

    def test_the_measured_cmdline_and_order_carry_the_launch_disk(self) -> None:
        """What the miner sizes from: the measured `hippius.disk_gb` and the
        LaunchOrder's `data_disk_size_gb` — both the pinned launch disk."""
        vm = _vm()
        record = LaunchJob.objects.get(vm_id=vm.vm_id)
        spec = launch.LaunchSpec(
            **{**record.spec_json, "flavor": "large", "data_disk_size_gb": 40},
            kek_bytes=None,
            userdata=b"",
        )
        assert launch.data_disk_gb(spec) == 40
        cmdline = launch._derive_measured_cmdline(
            spec,
            None,
            disk_gb=launch.data_disk_gb(spec),
            node_id_hex="ab" * 32,
            validator_nonce_hex="cd" * 32,
            telemetry_epoch=1,
            eol_nonce_hex="ef" * 32,
        )
        assert "hippius.disk_gb=40" in cmdline
        assert "hippius.resource_class=large" in cmdline

    def test_a_downsize_keeps_the_bigger_disk(self, miner) -> None:
        vm = _vm(flavor="large")
        _run_to_relaunched(vm, "small")
        (handed,) = miner.launches
        assert handed["flavor"] == "small" and handed["disk_gb"] == 160
        placement = Placement.objects.get(vm=vm, status__in=ACTIVE_PLACEMENT_STATES)
        assert (placement.resource_class, placement.data_disk_gb) == ("small", 160)

    def test_the_miner_preflight_reads_the_target_flavor_memory(self) -> None:
        """The miner recovers RAM from the preflight's vCPU count
        (`Flavor::from_vcpus`): vCPU counts stay unique, so the target
        flavor's vCPU maps back to the target's RAM."""
        counts = [flavors.resolve_flavor(n).cpu_count for n in _REAL_NAMES]
        assert len(counts) == len(set(counts))


# ─── claim 2: the relaunch path, at the new flavor ──────────────────


class TestGrowInPlace:
    def test_end_to_end(self, miner) -> None:
        vm = _vm()
        job = _start(vm)
        assert job.state == ResizeState.PENDING
        assert job.from_flavor == "small" and job.to_flavor == "compact-2"

        _tick()
        assert _job(vm).state == ResizeState.STOPPING
        _tick()
        assert _job(vm).state == ResizeState.RELAUNCHING
        assert len(miner.stops) == 1
        _tick()
        job = _job(vm)
        assert job.relaunched_at is not None and job.state == ResizeState.RELAUNCHING
        _tick()
        assert _job(vm).state == ResizeState.RELAUNCHING, "no guest signal yet"
        _guest_signals(vm)
        _tick()
        job = _job(vm)
        assert job.state == ResizeState.DONE and job.finished_at is not None

        vm.refresh_from_db()
        assert vm.power_state == VmPowerState.RUNNING and vm.state == VmState.ACTIVE

    def test_an_already_launched_relaunch_settles_only_on_the_attested_boot(self, miner) -> None:
        """The relaunch is answered `already-launched` (an earlier dispatch
        of this job is up, its answer lost): the books wait for the guest
        to attest which boot runs, then follow it."""
        from apps.orchestration import service

        from .test_already_launched_record import _attests

        vm = _vm()
        _start(vm)
        _tick(2)
        running = "e" * 96
        launch_record.add_dispatched_boot(
            vm.vm_id,
            launch_record.dispatched_boot_candidate(
                {"measurement_hex": running, "measured_cmdline": "booted earlier"},
                booted=None,
                flavor="compact-2",
            ),
        )
        miner.launch_emit = {
            "classifier": "already-launched",
            "measurement_hex": "f" * 96,
            "measured_cmdline": "this retry",
        }
        _tick()
        _guest_signals(vm)
        _tick()
        assert _job(vm).state == ResizeState.RELAUNCHING
        assert launch_record.recorded_flavor(vm.vm_id) == "small", "not before it attests"
        assert launch_record.recorded_measurement(vm.vm_id) == _measurement("small")

        _attests(vm.vm_id, running)
        assert service.sweep_unverified_boots() == 1
        _tick()
        assert _job(vm).state == ResizeState.DONE
        assert launch_record.recorded_flavor(vm.vm_id) == "compact-2"
        assert launch_record.recorded_measurement(vm.vm_id) == running

    def test_the_pre_resize_boot_attesting_never_moves_the_books(self, miner) -> None:
        """`already-launched`, and the guest attests the PRE-resize boot: the
        record keeps the old flavor next to the old measurement."""
        from apps.orchestration import service

        from .test_already_launched_record import _attests

        vm = _vm()
        _start(vm)
        _tick(2)
        miner.launch_emit = {
            "classifier": "already-launched",
            "measurement_hex": "f" * 96,
            "measured_cmdline": "this retry",
        }
        _tick()
        _attests(vm.vm_id, _measurement("small"))
        assert service.sweep_unverified_boots() == 1
        _guest_signals(vm)
        _tick()
        assert _job(vm).state == ResizeState.RELAUNCHING
        assert launch_record.recorded_flavor(vm.vm_id) == "small"
        assert launch_record.recorded_measurement(vm.vm_id) == _measurement("small")

    def test_the_relaunch_is_the_launch_choreography(self, miner) -> None:
        vm = _vm()
        _run_to_relaunched(vm)
        (handed,) = miner.launches
        assert handed["miner"] == HOST
        assert handed["require_existing_disks"] is True, "never blank disks"
        assert handed["generation"] == vm.generation
        assert handed["auto_pin"] is True, "the new measurement is pinned by the launch"

    def test_the_launch_record_moves_with_the_measurement(self, miner) -> None:
        vm = _vm()
        _run_to_relaunched(vm)
        record = LaunchJob.objects.get(vm_id=vm.vm_id)
        assert record.flavor == "compact-2"
        assert record.spec_json["flavor"] == "compact-2"
        assert record.result_json["emit"]["measurement_hex"] == _measurement("compact-2")

    def test_a_later_start_boots_the_new_size(self, miner) -> None:
        vm = _vm()
        _run_to_relaunched(vm)
        _guest_signals(vm)
        _tick()
        vm.refresh_from_db()
        power.stop_vm(vm)
        power.start_vm(vm)
        assert [launch["flavor"] for launch in miner.launches] == ["compact-2", "compact-2"]


# ─── claim 3: rollback before the point of no return ────────────────


class TestRollback:
    def test_rejected_relaunches_put_the_vm_back(self, miner) -> None:
        vm = _vm()
        miner.launch_disposition = launch.RETRIABLE
        _start(vm)
        _tick(2)  # reserved + stopped
        _tick(resize.MAX_RELAUNCH_REJECTIONS)
        assert _job(vm).state == ResizeState.ROLLING_BACK

        miner.launch_disposition = launch.ACCEPTED
        _tick()
        job = _job(vm)
        assert job.state == ResizeState.FAILED and job.rolled_back is True
        assert job.reason.startswith("relaunch-rejected")
        assert miner.launches[-1]["flavor"] == "small", "restarted at the OLD size"
        assert _active_classes(vm) == [(HOST_NODE, "small")]
        assert launch_record.recorded_flavor(vm.vm_id) == "small"
        vm.refresh_from_db()
        assert vm.power_state == VmPowerState.RUNNING

    def test_relaunches_supersede_until_one_registered(self, miner) -> None:
        """A relaunch that registered made the KBS refuse the pre-resize
        ticket; after it a retry — that attempt was dispatched and may still
        come up — and the rollback relaunch do not supersede (current at
        their first release)."""
        vm = _vm()
        miner.launch_disposition = launch.RETRIABLE
        _start(vm)
        _tick(2)
        _tick(resize.MAX_RELAUNCH_REJECTIONS)
        miner.launch_disposition = launch.ACCEPTED
        _tick()
        assert [x.get("supersede", False) for x in miner.launches] == [True] + [False] * (
            len(miner.launches) - 1
        )
        assert miner.launches[-1]["flavor"] == "small", "the rollback, at the old size"

    def test_an_attempt_that_failed_before_its_register_does_not_spend_the_supersede(
        self, miner
    ) -> None:
        """An attempt refused before its register dispatched nothing: the
        next one still supersedes, so the pre-resize ticket is refused from
        the first register that lands."""
        vm = _vm()
        miner.launch_disposition = launch.RETRIABLE
        miner.registers = False
        _start(vm)
        _tick(2)
        _tick(resize.MAX_RELAUNCH_REJECTIONS)
        target = [x for x in miner.launches if x["flavor"] == "compact-2"]
        assert len(target) >= 2 and all(x.get("supersede") for x in target)

    def _stop_fails_then_times_out(self, miner) -> Vm:
        vm = _vm()
        miner.stop_error = effects.EffectError("edge 502")
        _start(vm)
        _tick(2)
        assert _job(vm).state == ResizeState.STOPPING
        ResizeJob.objects.filter(vm=vm).update(phase_started_at=timezone.now() - timedelta(hours=1))
        _tick()
        assert _job(vm).state == ResizeState.ROLLING_BACK
        # The stop marker goes stale: it is settled to what the miner runs.
        Vm.objects.filter(pk=vm.pk).update(
            power_state_at=timezone.now() - power.STALE_POWER_MARKER - timedelta(seconds=1)
        )
        return vm

    def test_a_stop_that_never_landed_rolls_back(self, miner) -> None:
        vm = self._stop_fails_then_times_out(miner)
        _tick()
        job = _job(vm)
        assert job.state == ResizeState.FAILED and job.rolled_back is True
        assert _active_classes(vm) == [(HOST_NODE, "small")]
        assert miner.launches == [], "the guest never went down"
        vm.refresh_from_db()
        assert vm.power_state == VmPowerState.RUNNING

    def test_a_stop_that_landed_unconfirmed_restarts_the_old_size(self, miner) -> None:
        miner.domain_running = True
        vm = self._stop_fails_then_times_out(miner)
        miner.domain_running = False  # the order had landed after all
        _tick()
        job = _job(vm)
        assert job.state == ResizeState.FAILED and job.rolled_back is True
        assert miner.launches[-1]["flavor"] == "small"

    def test_after_the_relaunch_a_silent_guest_is_reported_not_undone(self, miner) -> None:
        vm = _vm()
        _run_to_relaunched(vm)
        ResizeJob.objects.filter(vm=vm).update(phase_started_at=timezone.now() - timedelta(hours=2))
        _tick()
        job = _job(vm)
        assert job.state == ResizeState.FAILED and job.rolled_back is False
        assert job.reason.startswith("guest-signal-timeout")
        assert len(miner.launches) == 1, "no second reboot"
        assert launch_record.recorded_flavor(vm.vm_id) == "compact-2"
        assert _active_classes(vm) == [(HOST_NODE, "compact-2")]

    def test_missing_disks_release_the_reservation_and_stop(self, miner) -> None:
        vm = _vm()
        miner.launch_disposition = launch.RETRIABLE
        miner.launch_emit = {"classifier": service.RELAUNCH_DISKS_MISSING_CLASS}
        _start(vm)
        _tick(3)
        job = _job(vm)
        assert job.state == ResizeState.FAILED and job.reason.startswith("disks-missing")
        assert _active_classes(vm) == [(HOST_NODE, "small")]


# ─── claim 4: capacity is reserved exactly once ─────────────────────


class TestCapacity:
    def test_a_grow_reserves_before_the_stop_and_never_twice(self, miner) -> None:
        vm = _vm()
        small = _committed()
        _start(vm)
        _tick()
        grown = _committed()
        assert grown[2] == small[2] == 1, "one VM counted, never two"
        assert grown[:2] == (2, 8192), "the new size, reserved"
        _tick()
        (stop,) = miner.stops
        assert stop["placement"] == [(HOST_NODE, "compact-2")], "reserved BEFORE the stop"
        _tick()
        assert _committed() == grown
        closed = Placement.objects.get(vm=vm, resource_class="small")
        assert closed.status == PlacementStatus.RESIZED
        assert closed.failure_source == PlacementFailureSource.RESIZE
        assert sched.recent_failures_by_node().get(HOST_NODE, 0) == 0, "not a failure"

    def test_a_shrink_keeps_the_larger_reservation_until_the_new_size_runs(self, miner) -> None:
        vm = _vm(flavor="compact-4")
        _start(vm, "compact-2")
        _tick(2)
        assert _active_classes(vm) == [(HOST_NODE, "compact-4")], "old guest still counted"
        _tick()
        (handed,) = miner.launches
        assert handed["placement"] == [(HOST_NODE, "compact-4")]
        assert _active_classes(vm) == [(HOST_NODE, "compact-2")]
        assert _committed()[2] == 1

    def test_no_room_anywhere_is_refused_up_front(self, miner, monkeypatch) -> None:
        vm = _vm()
        MinerCapacity.objects.filter(miner_node_id=HOST_NODE).update(total_memory_mb=13_000)
        monkeypatch.setattr(resize, "_pick_destination", lambda *a: (None, "no-eligible-miner"))
        with pytest.raises(StartError) as exc:
            _start(vm, "compact-4")
        assert exc.value.category == resize.NO_CAPACITY
        assert _active_classes(vm) == [(HOST_NODE, "small")]
        assert not ResizeJob.objects.exists()

    def test_the_fit_is_checked_again_at_the_reservation(self, miner, monkeypatch) -> None:
        """Admitted, then the host filled up before the tick reserved: the
        resize does not over-book it — it looks elsewhere."""
        vm = _vm()
        _start(vm, "compact-4")
        MinerCapacity.objects.filter(miner_node_id=HOST_NODE).update(total_memory_mb=13_000)
        monkeypatch.setattr(resize, "_pick_destination", lambda *a: (None, "no-eligible-miner"))
        _tick()
        job = _job(vm)
        assert job.state == ResizeState.FAILED and job.reason.startswith(resize.NO_CAPACITY)
        assert job.rolled_back is True
        assert _active_classes(vm) == [(HOST_NODE, "small")]
        assert miner.stops == []

    def test_the_vm_own_reservation_is_released_in_the_fit(self) -> None:
        """A host exactly full with this VM: growing it by the room left is
        a fit — the VM is not counted against itself."""
        vm = _vm()
        # 24 threads − 2 reserve, ×1 = 22 vCPU; RAM budget = total − 8192.
        MinerCapacity.objects.filter(miner_node_id=HOST_NODE).update(
            total_memory_mb=8192 + 8192 + sched.capacity_config.per_vm_overhead_mb(),
            cpu_ratio=1,
        )
        assert not resize._in_place_shortfall(vm, HOST_NODE, "small", "compact-2")


# ─── claim 5: a stopped VM ──────────────────────────────────────────


class TestStoppedVm:
    def test_resized_on_the_books_and_left_stopped(self, miner) -> None:
        vm = _vm(power_state=VmPowerState.STOPPED)
        _start(vm)
        _tick()
        job = _job(vm)
        assert job.state == ResizeState.DONE
        vm.refresh_from_db()
        assert vm.power_state == VmPowerState.STOPPED
        assert miner.stops == [] and miner.launches == []
        assert _active_classes(vm) == [(HOST_NODE, "compact-2")]
        assert launch_record.recorded_flavor(vm.vm_id) == "compact-2"

    def test_its_next_start_boots_the_new_size(self, miner) -> None:
        vm = _vm(power_state=VmPowerState.STOPPED)
        _start(vm)
        _tick()
        vm.refresh_from_db()
        power.start_vm(vm)
        assert [launch["flavor"] for launch in miner.launches] == ["compact-2"]

    def test_its_next_start_supersedes_until_one_registered(self, miner) -> None:
        """The pre-resize ticket is refused from the new size's register on,
        not only from its first release; a start refused before its register
        leaves the next one superseding, and once one registered the others
        do not (it may be the domain coming up)."""
        vm = _vm(power_state=VmPowerState.STOPPED)
        _start(vm)
        _tick()
        miner.domain_running = False
        miner.launch_disposition = launch.TERMINAL
        for registers in (False, True):
            miner.registers = registers
            vm.refresh_from_db()
            with pytest.raises(power.PowerOpRefused):
                power.start_vm(vm)
        miner.launch_disposition = launch.ACCEPTED
        vm.refresh_from_db()
        power.start_vm(vm)
        assert [launch.get("supersede", False) for launch in miner.launches] == [
            True,
            True,
            False,
        ]
        assert resize.next_start_supersedes(vm) is False

    def test_a_domain_that_may_be_up_is_not_superseded(self, miner) -> None:
        """An earlier start that timed out may have booted the old size: a
        superseding register would strand it. Its start becomes current at
        its first release instead."""
        vm = _vm(power_state=VmPowerState.STOPPED)
        _start(vm)
        _tick()
        vm.refresh_from_db()
        for running in (True, None):
            miner.domain_running = running
            assert resize.next_start_supersedes(vm) is False
        miner.domain_running = False
        assert resize.next_start_supersedes(vm) is True

    def test_a_start_at_the_booted_size_does_not_supersede(self, miner) -> None:
        vm = _vm(power_state=VmPowerState.STOPPED)
        assert resize.next_start_supersedes(vm) is False
        power.start_vm(vm)
        assert [launch.get("supersede", False) for launch in miner.launches] == [False]

    def test_no_room_on_its_own_miner_is_refused(self, miner) -> None:
        vm = _vm(power_state=VmPowerState.STOPPED)
        MinerCapacity.objects.filter(miner_node_id=HOST_NODE).update(total_memory_mb=13_000)
        with pytest.raises(StartError) as exc:
            _start(vm, "compact-4")
        assert exc.value.category == resize.NO_CAPACITY


# ─── migration when the new size does not fit here ──────────────────


class TestMigrate:
    def test_migrates_then_resizes_on_the_destination(self, miner, monkeypatch) -> None:
        vm = _vm()
        MinerCapacity.objects.filter(miner_node_id=HOST_NODE).update(total_memory_mb=13_000)
        monkeypatch.setattr(resize, "_pick_destination", lambda *a: (OTHER, ""))
        started: list[dict[str, Any]] = []

        def fake_start_migration(**kw: Any) -> Any:
            started.append(kw)
            from .factories import make_migration_job

            return make_migration_job(kw["vm"], dest_node_id=kw["dest_node_id"])

        monkeypatch.setattr(service, "start_migration", fake_start_migration)
        _start(vm, "compact-4")
        _tick()
        job = _job(vm)
        assert job.state == ResizeState.MIGRATING
        (kw,) = started
        assert kw["resize_to_flavor"] == "compact-4" and kw["dest_node_id"] == OTHER

        # The migration lands: the activation moves the VM and its
        # placement — opened at the NEW size — to the destination.
        migration = job.migration_job
        sched.move_placement_to_node(
            vm,
            node_id=OTHER_NODE,
            decided_by=job.decided_by,
            reason=f"migrated:{migration.job_id}",
            resource_class="compact-4",
        )
        Vm.objects.filter(pk=vm.pk).update(host=OTHER, generation=2)
        migration.state = MigrationState.DONE
        migration.finished_at = timezone.now()
        migration.save()
        assert _active_classes(vm) == [(OTHER_NODE, "compact-4")]

        _tick()
        job = _job(vm)
        assert job.state == ResizeState.STOPPING and job.node_id == OTHER and job.reserved
        _tick(2)
        (handed,) = miner.launches
        assert handed["miner"] == OTHER and handed["flavor"] == "compact-4"
        assert handed["generation"] == 2
        assert _committed(HOST_NODE)[2] == 0 and _committed(OTHER_NODE)[2] == 1

    def test_a_failed_migration_leaves_the_vm_where_it_was(self, miner, monkeypatch) -> None:
        vm = _vm()
        MinerCapacity.objects.filter(miner_node_id=HOST_NODE).update(total_memory_mb=13_000)
        monkeypatch.setattr(resize, "_pick_destination", lambda *a: (OTHER, ""))
        from .factories import make_migration_job

        monkeypatch.setattr(
            service,
            "start_migration",
            lambda **kw: make_migration_job(kw["vm"], dest_node_id=kw["dest_node_id"]),
        )
        _start(vm, "compact-4")
        _tick()
        migration = _job(vm).migration_job
        migration.state = MigrationState.FAILED
        migration.reason = "cancelled by operator"
        migration.finished_at = timezone.now()
        migration.save()
        _tick()
        job = _job(vm)
        assert job.state == ResizeState.FAILED and job.rolled_back is True
        assert _active_classes(vm) == [(HOST_NODE, "small")]

    def test_the_destination_placement_opens_at_the_new_size(self) -> None:
        vm = _vm()
        sched.move_placement_to_node(
            vm,
            node_id=OTHER_NODE,
            decided_by=make_service_client(),
            reason="migrated:x",
            resource_class="compact-4",
        )
        assert _active_classes(vm) == [(OTHER_NODE, "compact-4")]

    def test_a_plain_migration_keeps_the_size(self) -> None:
        vm = _vm()
        sched.move_placement_to_node(
            vm, node_id=OTHER_NODE, decided_by=make_service_client(), reason="migrated:x"
        )
        assert _active_classes(vm) == [(OTHER_NODE, "small")]


# ─── claim 6: the resize owns the VM while it runs ──────────────────


class TestExclusivity:
    def test_the_power_api_refuses_while_a_resize_runs(self, miner) -> None:
        vm = _vm()
        _start(vm)
        with pytest.raises(power.PowerOpRefused) as exc:
            power.stop_vm(vm)
        assert exc.value.reason == "resize-in-flight"

    def test_no_migration_or_second_resize_while_one_runs(self, miner) -> None:
        vm = _vm()
        _start(vm)
        with pytest.raises(StartError) as exc:
            service.start_migration(vm=vm, dest_node_id=OTHER, decided_by=make_service_client())
        assert exc.value.category == "job-in-flight"
        with pytest.raises(StartError) as exc:
            _start(vm, "compact-4")
        assert exc.value.category == "job-in-flight"

    def test_the_options_say_why_nothing_can_start(self, miner) -> None:
        vm = _vm()
        _start(vm)
        options = resize.compatible_flavors(vm)
        assert options.blocked == "job-in-flight"
        assert not any(o.available for o in options.options)

    @pytest.mark.parametrize(
        ("to", "category"),
        [
            ("small", "same-flavor"),
            ("nope", "unknown-flavor"),
            # Launch-only: a runner flavor is never a resize target.
            ("runner-medium", "flavor-not-offered"),
        ],
    )
    def test_request_refusals(self, to: str, category: str) -> None:
        vm = _vm()
        with pytest.raises(StartError) as exc:
            _start(vm, to)
        assert exc.value.category == category

    def test_a_runner_vm_is_not_resized(self) -> None:
        vm = _vm(flavor="runner-small")
        with pytest.raises(StartError) as exc:
            _start(vm, "medium")
        assert exc.value.category == "unknown-current-flavor"
        assert resize.compatible_flavors(vm).blocked == "unknown-current-flavor"

    def test_a_vm_mid_power_op_is_refused(self) -> None:
        vm = _vm(power_state=VmPowerState.STARTING)
        with pytest.raises(StartError) as exc:
            _start(vm)
        assert exc.value.category == "power-op-in-flight"


# ─── the tick and the API ───────────────────────────────────────────


def test_the_orchestration_tick_drives_it(miner) -> None:
    vm = _vm()
    _start(vm)
    for _ in range(3):
        report = service.tick_once()
    assert report.resize_jobs == 1
    _guest_signals(vm)
    service.tick_once()
    assert _job(vm).state == ResizeState.DONE


class TestViews:
    @pytest.fixture
    def client(self):
        from rest_framework.test import APIClient

        from apps.identity.models import ServiceClient

        c = APIClient()
        root = ServiceClient.objects.create(name="orchestration-root", scope="operator")
        c.force_authenticate(user=root)
        return c

    @pytest.fixture(autouse=True)
    def _root(self, monkeypatch):
        from apps.orchestration import permissions

        monkeypatch.setattr(permissions.IsOrchestrationRoot, "has_permission", lambda *a: True)

    def test_start_poll_and_options(self, client, miner) -> None:
        vm = _vm()
        r = client.get(f"/v1/vm/{vm.vm_id}/resize/flavors")
        assert r.status_code == 200, r.content
        assert r.json()["current_flavor"] == "small"
        options = r.json()["options"]
        assert "compact-2" in [o["flavor"] for o in options] and "small" not in [
            o["flavor"] for o in options
        ]
        assert {o["data_disk_size_gb"] for o in options} == {40}

        r = client.post(f"/v1/vm/{vm.vm_id}/resize", {"flavor": "compact-2"}, format="json")
        assert r.status_code == 202, r.content
        job_id = r.json()["job_id"]
        assert r.json()["state"] == "pending"

        r = client.get(f"/v1/vm/{vm.vm_id}/resize/{job_id}")
        assert r.status_code == 200 and r.json()["to_flavor"] == "compact-2"
        r = client.get(f"/v1/vm/{vm.vm_id}/resize")
        assert r.status_code == 200 and r.json()["job_id"] == job_id

    def test_refusals(self, client) -> None:
        vm = _vm()
        r = client.post(f"/v1/vm/{vm.vm_id}/resize", {"flavor": "small"}, format="json")
        assert r.status_code == 400
        assert r.json()["category"] == "same-flavor"
        r = client.post(f"/v1/vm/{vm.vm_id}/resize", {}, format="json")
        assert r.status_code == 400 and r.json()["category"] == "wire"
        r = client.post("/v1/vm/nope/resize", {"flavor": "compact-2"}, format="json")
        assert r.status_code == 404
        r = client.get(f"/v1/vm/{vm.vm_id}/resize")
        assert r.status_code == 404


class TestLaunchRecord:
    def test_a_relaunch_records_its_flavor_with_its_measurement(self) -> None:
        """One write: the record never pairs a new-size measurement with the
        old size (a §25 hop would boot the wrong vCPU count against it)."""
        vm = _vm()
        launch_record.record_relaunch(
            vm.vm_id,
            {"measurement_hex": _measurement("compact-2")},
            reason="reboot-recovery-relaunch",
            flavor="compact-2",
        )
        record = LaunchJob.objects.get(vm_id=vm.vm_id)
        assert record.flavor == record.spec_json["flavor"] == "compact-2"
        assert record.result_json["emit"]["measurement_hex"] == _measurement("compact-2")
        history = record.result_json["emit"]["superseded"]
        assert {"flavor": "small"} in [entry["previous"] for entry in history]

    def test_a_plain_relaunch_keeps_the_flavor(self) -> None:
        vm = _vm()
        launch_record.record_relaunch(
            vm.vm_id, {"measurement_hex": "ab" * 48}, reason="reboot-recovery-relaunch"
        )
        assert launch_record.recorded_flavor(vm.vm_id) == "small"

    def test_record_flavor_is_compare_and_set(self) -> None:
        vm = _vm()
        with pytest.raises(ValueError):
            launch_record.record_flavor(vm.vm_id, "compact-4", reason="x", expected="compact-2")
        assert launch_record.recorded_flavor(vm.vm_id) == "small"


def test_a_running_vm_is_not_counted_against_itself_in_the_ram_report() -> None:
    """The miner's fresh free-RAM report excludes the running guest's memory;
    the fit credits it back, or the down-only clamp would refuse a grow the
    host can hold once the guest stops."""
    vm = _vm()
    overhead = sched.capacity_config.per_vm_overhead_mb()
    # The host reports exactly the room the bigger size needs ONCE the
    # small guest (4096 MiB + overhead) is gone.
    MinerCapacity.objects.filter(miner_node_id=HOST_NODE).update(
        reported_memory_available_mib=8192 + overhead - (4096 + overhead),
        reported_at=timezone.now(),
    )
    assert not resize._in_place_shortfall(vm, HOST_NODE, "small", "compact-2")


class TestSettleAfterTheRelaunch:
    def test_a_failed_shrink_swap_is_retried_never_rolled_back(self, miner, monkeypatch) -> None:
        """The relaunch is accepted, the reservation write fails once: the job
        keeps the point of no return and retries — it must not "roll back" a
        VM that already runs at the new size."""
        vm = _vm(flavor="compact-4")
        real = sched.swap_placement_class
        # Both writers of the shrink in the accepting tick fail: the
        # relaunch's own follow-the-boot swap and the resize's settle.
        failures = [sched.PlacementSwapConflict("raced"), sched.PlacementSwapConflict("raced")]

        def flaky(*a: Any, **kw: Any) -> Any:
            if failures:
                raise failures.pop()
            return real(*a, **kw)

        monkeypatch.setattr(sched, "swap_placement_class", flaky)
        _start(vm, "compact-2")
        _tick(3)
        job = _job(vm)
        assert job.relaunched_at is not None and not job.reserved
        _guest_signals(vm)
        _tick()
        job = _job(vm)
        assert job.state == ResizeState.DONE and job.reserved
        assert _active_classes(vm) == [(HOST_NODE, "compact-2")]

    def test_a_lost_record_write_is_repaired(self, miner, monkeypatch) -> None:
        def broken(*a: Any, **kw: Any) -> bool:
            raise RuntimeError("db hiccup")

        monkeypatch.setattr(launch_record, "record_relaunch", broken)
        vm = _vm()
        _run_to_relaunched(vm)
        assert launch_record.recorded_flavor(vm.vm_id) == "compact-2"

    def test_an_unsettled_record_fails_loudly_at_the_deadline(self, miner, monkeypatch) -> None:
        vm = _vm()
        _run_to_relaunched(vm)
        LaunchJob.objects.filter(vm_id=vm.vm_id).update(flavor="small")
        job = LaunchJob.objects.get(vm_id=vm.vm_id)
        LaunchJob.objects.filter(pk=job.pk).update(spec_json={**job.spec_json, "flavor": "small"})

        def refused(*a: Any, **kw: Any) -> bool:
            raise ValueError("record moved")

        monkeypatch.setattr(launch_record, "record_flavor", refused)
        ResizeJob.objects.filter(vm=vm).update(phase_started_at=timezone.now() - timedelta(hours=2))
        _tick()
        job = _job(vm)
        assert job.state == ResizeState.FAILED and job.rolled_back is False
        assert job.reason.startswith("record-failed")


class TestReviewFixes:
    def test_a_mixed_change_is_reserved_once_the_old_guest_is_stopped(self, miner) -> None:
        """More vCPU, less RAM: checked like a grow, reserved only after the
        stop — the RAM it gives back is never under-counted while the old
        guest still holds it."""
        vm = _vm(flavor="compact-mem")
        _start(vm, "compact-wide")
        _tick()
        assert _active_classes(vm) == [(HOST_NODE, "compact-mem")], "not before the stop"
        _tick()
        (stop,) = miner.stops
        assert stop["placement"] == [(HOST_NODE, "compact-mem")]
        assert _active_classes(vm) == [(HOST_NODE, "compact-wide")]
        assert _job(vm).reserved
        _tick()
        (handed,) = miner.launches
        assert handed["flavor"] == "compact-wide"
        assert handed["placement"] == [(HOST_NODE, "compact-wide")]

    def test_a_mixed_change_that_no_longer_fits_after_the_stop_rolls_back(self, miner) -> None:
        vm = _vm(flavor="compact-mem")
        _start(vm, "compact-wide")
        _tick()
        # The host's CPU fills up while the job waited for the stop.
        MinerCapacity.objects.filter(miner_node_id=HOST_NODE).update(total_cpus=4)
        _tick()
        job = _job(vm)
        assert job.state == ResizeState.ROLLING_BACK and job.reason.startswith(resize.NO_CAPACITY)
        _tick()
        job = _job(vm)
        assert job.state == ResizeState.FAILED and job.rolled_back is True
        assert _active_classes(vm) == [(HOST_NODE, "compact-mem")]
        assert miner.launches[-1]["flavor"] == "compact-mem"

    def test_the_mixed_fit_is_checked_at_admission(self) -> None:
        vm = _vm(flavor="compact-mem")
        MinerCapacity.objects.filter(miner_node_id=HOST_NODE).update(total_cpus=4)
        assert resize._in_place_shortfall(vm, HOST_NODE, "compact-mem", "compact-wide")

    def test_a_pinned_measurement_is_refused(self) -> None:
        vm = _vm()
        job = LaunchJob.objects.get(vm_id=vm.vm_id)
        LaunchJob.objects.filter(pk=job.pk).update(
            spec_json={**job.spec_json, "measurement_hex": "ab" * 48}
        )
        with pytest.raises(StartError) as exc:
            _start(vm)
        assert exc.value.category == "resize-measurement-pinned"

    def test_a_relaunch_whose_tick_died_is_finished_not_rolled_back(
        self, miner, monkeypatch
    ) -> None:
        """The relaunch was accepted and recorded, then the worker died before
        `start_vm` wrote `running`: the stale `starting` marker is settled to
        what the miner runs, and the job finishes at the new size."""
        vm = _vm()
        _start(vm)
        _tick(2)  # reserved, stopped
        real_start = power.start_vm

        def dies_after_the_relaunch(vm: Vm, **kw: Any) -> Vm:
            from apps.orchestration.service import _reboot_recovery_relaunch

            Vm.objects.filter(pk=vm.pk).update(
                power_state=VmPowerState.STARTING,
                power_state_at=timezone.now() - power.STALE_POWER_MARKER - timedelta(seconds=1),
            )
            _reboot_recovery_relaunch(vm, vm.host, flavor=kw["flavor"])
            raise SystemExit("worker killed")

        monkeypatch.setattr(power, "start_vm", dies_after_the_relaunch)
        with pytest.raises(SystemExit):
            resize.tick_resizes()
        monkeypatch.setattr(power, "start_vm", real_start)
        _tick()
        job = _job(vm)
        assert job.state == ResizeState.RELAUNCHING and job.relaunched_at is not None
        _guest_signals(vm)
        _tick()
        assert _job(vm).state == ResizeState.DONE
        assert len(miner.launches) == 1, "relaunched once"
        assert _active_classes(vm) == [(HOST_NODE, "compact-2")]

    def test_a_rollback_that_finds_the_new_size_running_finishes_it(self, miner) -> None:
        vm = _vm()
        _run_to_relaunched(vm)
        ResizeJob.objects.filter(vm=vm).update(
            state=ResizeState.ROLLING_BACK, relaunched_at=None, reason="relaunching-timeout"
        )
        _tick()
        job = _job(vm)
        assert job.state == ResizeState.RELAUNCHING and job.relaunched_at is not None
        assert job.reason == ""

    def test_a_resize_waits_for_its_migration_past_the_deadline(self, miner, monkeypatch) -> None:
        from .factories import make_migration_job

        vm = _vm()
        migration = make_migration_job(vm, dest_node_id=OTHER)
        ResizeJob.objects.create(
            job_id="rz-mig",
            vm=vm,
            from_flavor="small",
            to_flavor="compact-4",
            node_id=HOST,
            prior_power_state=VmPowerState.RUNNING,
            state=ResizeState.MIGRATING,
            migration_job=migration,
            phase_started_at=timezone.now() - timedelta(days=1),
            decided_by=make_service_client(),
        )
        _tick()
        assert _job(vm).state == ResizeState.MIGRATING

    def test_a_vm_moved_under_the_job_is_not_powered(self, miner) -> None:
        vm = _vm()
        _start(vm)
        _tick()
        Vm.objects.filter(pk=vm.pk).update(host=OTHER)
        _tick()
        job = _job(vm)
        assert job.state == ResizeState.FAILED and job.reason.startswith("vm-moved")
        assert miner.stops == []

    def test_migration_intake_rechecks_under_the_vm_lock(self, monkeypatch) -> None:
        """A resize recorded between the migration's first check and its
        insert is seen by the re-check under the VM's row lock."""
        vm = _vm()
        answers = iter([False, True])
        monkeypatch.setattr(service, "_has_active_job", lambda *a, **kw: next(answers))
        monkeypatch.setattr(service, "_snp_generation", lambda node: "genoa")
        monkeypatch.setattr(service, "_is_golden", lambda vm: False)
        monkeypatch.setattr(
            "apps.orchestration.services.migration_ticket.assert_userdata_rebindable",
            lambda vm: None,
        )
        with pytest.raises(StartError) as exc:
            service.start_migration(vm=vm, dest_node_id=OTHER, decided_by=make_service_client())
        assert exc.value.category == "job-in-flight"


class TestReviewFixes2:
    def test_a_migration_whose_recording_was_lost_is_adopted(self, miner, monkeypatch) -> None:
        from .factories import make_migration_job

        vm = _vm()
        job = _start(vm, "compact-4")
        orphan = make_migration_job(vm, dest_node_id=OTHER)
        orphan.resize_to_flavor = "compact-4"
        orphan.save(update_fields=["resize_to_flavor"])
        _tick()
        job = _job(vm)
        assert job.state == ResizeState.MIGRATING and job.migration_job_id == orphan.id

    def test_a_mixed_change_that_does_not_fit_here_never_migrates(self, miner, monkeypatch) -> None:
        """§25 would boot the OLD size on a destination chosen and reserved
        for the NEW one: for a mixed change that under-counts the dimension
        it shrinks. Refused — at admission, and again at the first tick."""
        vm = _vm(flavor="compact-mem")
        monkeypatch.setattr(resize, "_pick_destination", lambda *a: (OTHER, ""))
        monkeypatch.setattr(
            service, "start_migration", lambda **kw: pytest.fail("a mixed change migrated")
        )
        MinerCapacity.objects.filter(miner_node_id=HOST_NODE).update(total_cpus=4)
        with pytest.raises(StartError) as exc:
            _start(vm, "compact-wide")
        assert exc.value.category == resize.NO_CAPACITY
        option = {o.flavor: o for o in resize.compatible_flavors(vm).options}["compact-wide"]
        assert not option.available and not option.needs_migration

        MinerCapacity.objects.filter(miner_node_id=HOST_NODE).update(total_cpus=24)
        _start(vm, "compact-wide")
        MinerCapacity.objects.filter(miner_node_id=HOST_NODE).update(total_cpus=4)
        _tick()
        job = _job(vm)
        assert job.state == ResizeState.FAILED and job.rolled_back is True
        assert miner.stops == []

    def test_a_ram_report_from_after_the_stop_is_not_credited_twice(
        self, miner, monkeypatch
    ) -> None:
        vm = _vm(flavor="compact-mem")
        _start(vm, "compact-wide")
        _tick()  # → stopping
        # The stop lands, then a fresh report shows the old guest already
        # gone — and still not enough room for the new size.
        miner_stop = miner.stop

        def stop_then_report(vm: Vm, **kw: Any) -> None:
            miner_stop(vm, **kw)
            MinerCapacity.objects.filter(miner_node_id=HOST_NODE).update(
                reported_memory_available_mib=1024,
                reported_at=timezone.now() + timedelta(seconds=5),
            )

        monkeypatch.setattr(effects, "dispatch_graceful_stop", stop_then_report)
        _tick()
        job = _job(vm)
        assert job.state == ResizeState.ROLLING_BACK and job.reason.startswith(resize.NO_CAPACITY)

    def test_a_mixed_change_is_not_refused_by_a_ram_report_from_before_the_stop(
        self, miner
    ) -> None:
        vm = _vm(flavor="compact-mem")
        # A fresh report taken while the old guest (16 GiB) still ran: less
        # than the new 8 GiB free beside it — enough once the old guest is
        # counted back, not without.
        MinerCapacity.objects.filter(miner_node_id=HOST_NODE).update(
            reported_memory_available_mib=8192 - 1, reported_at=timezone.now()
        )
        _start(vm, "compact-wide")
        _tick(2)
        job = _job(vm)
        assert job.state == ResizeState.RELAUNCHING and job.reserved

    def test_the_options_say_a_pinned_measurement_blocks(self) -> None:
        vm = _vm()
        job = LaunchJob.objects.get(vm_id=vm.vm_id)
        LaunchJob.objects.filter(pk=job.pk).update(
            spec_json={**job.spec_json, "measurement_hex": "ab" * 48}
        )
        options = resize.compatible_flavors(vm)
        assert options.blocked == "resize-measurement-pinned"
        assert not any(o.available for o in options.options)

    def test_a_flavor_that_changed_while_admitted_is_refused(self, monkeypatch) -> None:
        vm = _vm()
        real = launch_record.recorded_flavor
        reads = iter(["small", "compact-2"])
        monkeypatch.setattr(launch_record, "recorded_flavor", lambda vm_id: next(reads))
        with pytest.raises(StartError) as exc:
            _start(vm, "compact-4")
        assert exc.value.category == "job-in-flight"
        monkeypatch.setattr(launch_record, "recorded_flavor", real)

    def test_a_vm_that_changed_while_admitted_is_refused(self) -> None:
        vm = _vm()
        Vm.objects.filter(pk=vm.pk).update(power_state=VmPowerState.STOPPED)
        with pytest.raises(StartError) as exc:
            _start(vm)  # the caller's instance still says running
        assert exc.value.category == "job-in-flight"
        assert not ResizeJob.objects.exists()


class TestReviewFixes3:
    @pytest.mark.parametrize(("report_age_s", "credited"), [(-60, True), (60, False)])
    def test_the_post_stop_ram_credit_follows_the_report_read_under_the_lock(
        self, report_age_s: int, credited: bool
    ) -> None:
        """A report taken before the stop still counts the old guest (credit
        it); one taken after already shows it freed (do not credit twice)."""
        _vm()
        stopped_at = timezone.now()
        MinerCapacity.objects.filter(miner_node_id=HOST_NODE).update(
            reported_memory_available_mib=1024,
            reported_at=stopped_at + timedelta(seconds=report_age_s),
        )
        b = sched.resize_budget(
            node_id=HOST_NODE, old_class="small", vm_running=False, stopped_at=stopped_at
        )
        overhead = sched.capacity_config.per_vm_overhead_mb()
        assert (b.free_memory_mb == 1024 + 4096 + overhead) is credited

    def test_restore_intake_rechecks_under_the_vm_lock(self, monkeypatch) -> None:
        from apps.orchestration import restore

        vm = _vm()
        answers = iter([True])
        monkeypatch.setattr(service, "_has_active_job", lambda *a, **kw: next(answers))
        with pytest.raises(restore.RestoreError) as exc:
            restore._recheck_no_active_job(vm)
        assert exc.value.code == "job-in-flight"


class TestReviewFixes4:
    def test_a_migration_another_tick_just_started_is_adopted(self, miner, monkeypatch) -> None:
        from .factories import make_migration_job

        vm = _vm()
        MinerCapacity.objects.filter(miner_node_id=HOST_NODE).update(total_memory_mb=13_000)
        monkeypatch.setattr(resize, "_pick_destination", lambda *a: (OTHER, ""))
        made: list[Any] = []

        def raced(**kw: Any) -> Any:
            m = make_migration_job(kw["vm"], dest_node_id=kw["dest_node_id"])
            m.resize_to_flavor = kw["resize_to_flavor"]
            m.save(update_fields=["resize_to_flavor"])
            made.append(m)
            raise StartError("vm already has an in-flight orchestration job", "job-in-flight")

        monkeypatch.setattr(service, "start_migration", raced)
        _start(vm, "compact-4")
        _tick()
        job = _job(vm)
        assert job.state == ResizeState.MIGRATING and job.migration_job_id == made[0].id

    def test_the_destination_is_read_after_the_migration_is_seen_done(self, miner) -> None:
        from .factories import make_migration_job

        vm = _vm()
        migration = make_migration_job(vm, dest_node_id=OTHER, state=MigrationState.DONE.value)
        job = ResizeJob.objects.create(
            job_id="rz-dst",
            vm=vm,
            from_flavor="small",
            to_flavor="compact-4",
            node_id=HOST,
            prior_power_state=VmPowerState.RUNNING,
            state=ResizeState.MIGRATING,
            migration_job=migration,
            phase_started_at=timezone.now(),
            decided_by=make_service_client(),
        )
        stale = Vm.objects.get(pk=vm.pk)
        Vm.objects.filter(pk=vm.pk).update(host=OTHER, generation=2)
        job.vm = stale
        resize._h_migrating(job, stale)
        job.refresh_from_db()
        assert job.state == ResizeState.STOPPING and job.node_id == OTHER

    def test_a_report_from_between_two_stop_attempts_is_not_credited(self, miner) -> None:
        """The first stop landed but answered 502; a heartbeat showing the
        guest gone arrived; a retried stop then succeeded. That heartbeat is
        younger than the job's first stop, so the old guest is not credited
        twice."""
        vm = _vm(flavor="compact-mem")
        now = timezone.now()
        Vm.objects.filter(pk=vm.pk).update(power_state=VmPowerState.STOPPED, power_state_at=now)
        ResizeJob.objects.create(
            job_id="rz-retry",
            vm=vm,
            from_flavor="compact-mem",
            to_flavor="compact-wide",
            node_id=HOST,
            prior_power_state=VmPowerState.RUNNING,
            state=ResizeState.STOPPING,
            attempts=2,
            attempted_at=now,
            phase_started_at=now - timedelta(seconds=60),
            decided_by=make_service_client(),
        )
        MinerCapacity.objects.filter(miner_node_id=HOST_NODE).update(
            reported_memory_available_mib=8192 - 1, reported_at=now - timedelta(seconds=30)
        )
        _tick()
        job = _job(vm)
        assert job.state == ResizeState.ROLLING_BACK and job.reason.startswith(resize.NO_CAPACITY)


class TestReviewFixes5:
    def test_a_refused_relaunch_whose_domain_runs_is_not_rolled_back(self, miner) -> None:
        """An Edge timeout reads as a refusal, yet the miner booted the guest:
        neither retried nor rolled back over it, recorded running (so no later
        start boots it again), and left to an operator."""
        vm = _vm()
        miner.launch_disposition = launch.RETRIABLE
        miner.boot_on_reject = True
        _start(vm)
        _tick(3)
        job = _job(vm)
        assert job.state == ResizeState.FAILED and job.rolled_back is False
        assert job.reason.startswith("relaunch-outcome-unknown")
        assert len(miner.launches) == 1, "no second boot on top of it"
        vm.refresh_from_db()
        assert vm.power_state == VmPowerState.RUNNING
        assert _active_classes(vm) == [(HOST_NODE, "compact-2")], "the larger size stays held"
        _tick()
        assert len(miner.launches) == 1

    def test_no_relaunch_is_sent_while_the_domain_state_is_unknown(
        self, miner, monkeypatch
    ) -> None:
        vm = _vm()
        _start(vm)
        _tick(2)
        monkeypatch.setattr(effects, "poll_domain_running", lambda vm: None)
        _tick(2)
        assert miner.launches == []
        assert _job(vm).state == ResizeState.RELAUNCHING

    def test_a_rollback_never_starts_the_old_size_over_a_running_domain(self, miner) -> None:
        vm = _vm()
        miner.launch_disposition = launch.RETRIABLE
        _start(vm)
        _tick(2)
        _tick(resize.MAX_RELAUNCH_REJECTIONS)
        assert _job(vm).state == ResizeState.ROLLING_BACK
        miner.domain_running = True
        _tick()
        job = _job(vm)
        assert job.state == ResizeState.FAILED and job.reason.startswith("rollback-outcome-unknown")
        # Not given back over a live domain.
        assert _active_classes(vm) == [(HOST_NODE, "compact-2")]
        assert [launch["flavor"] for launch in miner.launches] == ["compact-2"] * 3

    def test_pin_busy_is_not_a_rejection(self, miner, monkeypatch) -> None:
        vm = _vm()
        _start(vm)
        _tick(2)
        real = power.start_vm
        busy = [True, True]

        def pin_busy_twice(vm: Vm, **kw: Any) -> Vm:
            if busy:
                busy.pop()
                raise power.PowerOpRefused(power.PIN_BUSY_REASON, "busy")
            return real(vm, **kw)

        monkeypatch.setattr(power, "start_vm", pin_busy_twice)
        miner.launch_disposition = launch.RETRIABLE
        _tick(3)  # busy, busy, one real rejection
        job = _job(vm)
        assert job.state == ResizeState.RELAUNCHING and job.attempts == 1


class TestReviewFixes6:
    def test_a_same_disk_resize_asks_nothing_of_the_disk_gate(self) -> None:
        """The VM's disk stays where it is: an enforced gate with no disk data
        (`deny`), or a nearly full disk, must not refuse a CPU/RAM resize."""
        vm = _vm()
        with override_settings(
            VALI_SCHEDULER_DISK_GATE="enforce", VALI_SCHEDULER_DISK_UNKNOWN="deny"
        ):
            assert not resize._in_place_shortfall(vm, HOST_NODE, "small", "compact-2")
            MinerCapacity.objects.filter(miner_node_id=HOST_NODE).update(
                total_disk_gb=60, disk_reported_at=timezone.now()
            )
            assert not resize._in_place_shortfall(vm, HOST_NODE, "small", "compact-2")

    def test_the_migration_and_the_move_to_migrating_commit_together(
        self, miner, monkeypatch
    ) -> None:
        """Another tick failed the job while this one was starting its
        migration: no migration is left behind without its resize."""
        from apps.orchestration.models import MigrationJob

        vm = _vm()
        MinerCapacity.objects.filter(miner_node_id=HOST_NODE).update(total_memory_mb=13_000)
        monkeypatch.setattr(resize, "_pick_destination", lambda *a: (OTHER, ""))
        job = _start(vm, "compact-4")

        def failed_meanwhile(*a: Any, **kw: Any) -> tuple[str, str]:
            ResizeJob.objects.filter(pk=job.pk).update(
                state=ResizeState.FAILED, version=job.version + 1, finished_at=timezone.now()
            )
            return OTHER, ""

        monkeypatch.setattr(resize, "_pick_destination", failed_meanwhile)
        monkeypatch.setattr(
            service, "start_migration", lambda **kw: pytest.fail("migration started for a dead job")
        )
        _tick()
        assert not MigrationJob.objects.filter(vm=vm).exists()


class TestReviewFixes7:
    def test_a_lost_measurement_record_never_reads_done(self, miner, monkeypatch) -> None:
        """The relaunch's measurement did not reach the launch record: the
        flavor is repaired, but the job is not `done` — a §25 hop would
        re-mint the old measurement — and fails loudly at its deadline."""

        def broken(*a: Any, **kw: Any) -> bool:
            raise RuntimeError("db hiccup")

        monkeypatch.setattr(launch_record, "record_relaunch", broken)
        vm = _vm()
        _run_to_relaunched(vm)
        _guest_signals(vm)
        _tick()
        assert _job(vm).state == ResizeState.RELAUNCHING, "not done on a stale measurement"
        ResizeJob.objects.filter(vm=vm).update(phase_started_at=timezone.now() - timedelta(hours=2))
        _tick()
        job = _job(vm)
        assert job.state == ResizeState.FAILED and job.reason.startswith("record-failed")
        assert job.rolled_back is False

    def test_the_relaunch_measurement_must_differ_from_the_one_before(self, miner) -> None:
        vm = _vm()
        _run_to_relaunched(vm)
        job = _job(vm)
        assert job.measurement_before == _measurement("small")

    def test_the_destination_is_chosen_with_the_new_size_fit_enforced(self, monkeypatch) -> None:
        """Under capacity v1 the v2 fit only shadows `decide_placement`: a
        resize asks it with the fit enforced (so a fitting lower-ranked host
        wins over a higher-ranked one that cannot fit), through the same
        argument assembly a launch uses (family cap included)."""
        vm = _vm()
        placement = Placement.objects.get(vm=vm)
        monkeypatch.setattr(
            "apps.scheduler.chain.read_miner_status", lambda: SimpleNamespace(miners=[])
        )
        monkeypatch.setattr(sched, "refresh_miner_capacity", lambda snap: None)
        monkeypatch.setattr(sched, "price_by_node", lambda snap: {})
        seen: dict[str, Any] = {}

        def decide(**kw: Any) -> str:
            seen.update(kw)
            return OTHER_NODE

        monkeypatch.setattr("apps.scheduler.placement.decide_placement", decide)
        with override_settings(VALI_SCHEDULER_RESOURCE_ADMISSION="false"):
            dest, why = resize._pick_destination(vm, placement, "large")
        assert dest == OTHER and why == ""
        assert seen["resource_fit"].enforce is True
        assert seen["resource_fit"].resource_class == "large"
        # The destination must hold the VM's real (launch) disk.
        assert seen["resource_fit"].disk_gb == 40 + flavors.ROOTFS_DISK_GB
        assert "max_family_per_node" in seen
        assert HOST_NODE in seen["excluded"]

    def test_a_vm_without_a_recorded_measurement_must_get_one(self, miner, monkeypatch) -> None:
        """A legacy record with no measurement: `done` still waits for the
        relaunch's own."""

        def broken(*a: Any, **kw: Any) -> bool:
            raise RuntimeError("db hiccup")

        vm = _vm()
        record = LaunchJob.objects.get(vm_id=vm.vm_id)
        LaunchJob.objects.filter(pk=record.pk).update(result_json={"emit": {}})
        monkeypatch.setattr(launch_record, "record_relaunch", broken)
        _run_to_relaunched(vm)
        _guest_signals(vm)
        _tick()
        assert _job(vm).state == ResizeState.RELAUNCHING


class TestReviewFixes8:
    def test_a_stopped_resize_keeps_the_boot_it_measured_for_a_hop(self, miner) -> None:
        """Resized on the books while stopped: a §25 hop / restore / failover
        before its next start still replays the OLD boot (its measurement
        and vCPU count) — only a relaunch moves the booted flavor."""
        vm = _vm(power_state=VmPowerState.STOPPED)
        _start(vm)
        _tick()
        record = LaunchJob.objects.get(vm_id=vm.vm_id)
        assert record.spec_json["flavor"] == "compact-2"
        assert launch_record.booted_flavor(record) == "small"
        vm.refresh_from_db()
        power.start_vm(vm)
        record.refresh_from_db()
        assert launch_record.booted_flavor(record) == "compact-2"
        assert launch_record.BOOTED_FLAVOR_KEY not in record.result_json["emit"]

    def test_the_dest_sizes_from_the_booted_flavor(self, miner) -> None:
        vm = _vm(power_state=VmPowerState.STOPPED)
        _start(vm)
        _tick()
        record = LaunchJob.objects.get(vm_id=vm.vm_id)
        LaunchJob.objects.filter(pk=record.pk).update(
            result_json={
                "emit": {
                    **record.result_json["emit"],
                    "measured_cmdline": "console=ttyS0 dm-verity.root=x",
                }
            }
        )
        paths = effects._launch_paths(vm)
        assert paths["cpu_count"] == flavors.resolve_flavor("small").cpu_count

    def test_a_cmdline_that_pins_the_resource_class_is_refused(self) -> None:
        vm = _vm()
        job = LaunchJob.objects.get(vm_id=vm.vm_id)
        LaunchJob.objects.filter(pk=job.pk).update(
            spec_json={**job.spec_json, "cmdline": "console=ttyS0 hippius.resource_class=small"}
        )
        with pytest.raises(StartError) as exc:
            _start(vm)
        assert exc.value.category == "resize-resource-class-pinned"
        assert resize.compatible_flavors(vm).blocked == "resize-resource-class-pinned"


class TestReviewFixes9:
    def test_a_stopped_shrink_keeps_the_larger_reservation_until_it_boots(self, miner) -> None:
        """Its current boot — what a restore or §25 hop before the next start
        replays — is the larger size; the next start releases the rest."""
        vm = _vm(flavor="compact-4", power_state=VmPowerState.STOPPED)
        _start(vm, "compact-2")
        _tick()
        assert _job(vm).state == ResizeState.DONE
        assert _active_classes(vm) == [(HOST_NODE, "compact-4")]
        assert launch_record.recorded_flavor(vm.vm_id) == "compact-2"
        vm.refresh_from_db()
        power.start_vm(vm)
        assert miner.launches[-1]["flavor"] == "compact-2"
        assert _active_classes(vm) == [(HOST_NODE, "compact-2")]

    def test_a_lost_relaunch_record_repaired_leaves_no_booted_marker(
        self, miner, monkeypatch
    ) -> None:
        def broken(*a: Any, **kw: Any) -> bool:
            raise RuntimeError("db hiccup")

        monkeypatch.setattr(launch_record, "record_relaunch", broken)
        vm = _vm()
        _run_to_relaunched(vm)
        record = LaunchJob.objects.get(vm_id=vm.vm_id)
        assert launch_record.booted_flavor(record) == "compact-2"

    def test_settle_observed_running_is_a_cas(self) -> None:
        vm = _vm(power_state=VmPowerState.STOPPED)
        assert power.settle_observed_running(vm) is True
        vm.refresh_from_db()
        assert vm.power_state == VmPowerState.RUNNING
        assert power.settle_observed_running(vm) is False


class TestReviewFixes10:
    def test_a_stopped_mixed_change_is_refused(self) -> None:
        vm = _vm(flavor="compact-mem", power_state=VmPowerState.STOPPED)
        with pytest.raises(StartError) as exc:
            _start(vm, "compact-wide")
        assert exc.value.category == "resize-mixed-needs-running"
        option = {o.flavor: o for o in resize.compatible_flavors(vm).options}["compact-wide"]
        assert not option.available

    def test_a_second_resize_before_the_first_boots_is_refused(self, miner) -> None:
        vm = _vm(flavor="compact-4", power_state=VmPowerState.STOPPED)
        _start(vm, "compact-2")
        _tick()
        with pytest.raises(StartError) as exc:
            _start(vm, "small")
        assert exc.value.category == "resize-pending-boot"


class TestOptionBReview:
    def test_a_legacy_vm_never_migrates_for_a_resize(self, monkeypatch) -> None:
        """§25 carries a golden VM's overlay, not a legacy VM's /dev/vde."""
        vm = _vm()
        job = LaunchJob.objects.get(vm_id=vm.vm_id)
        LaunchJob.objects.filter(pk=job.pk).update(
            spec_json={**job.spec_json, "disk_mode": "legacy_luks"}
        )
        MinerCapacity.objects.filter(miner_node_id=HOST_NODE).update(total_memory_mb=13_000)
        monkeypatch.setattr(resize, "_pick_destination", lambda *a: (OTHER, ""))
        with pytest.raises(StartError) as exc:
            _start(vm, "compact-4")
        assert exc.value.category == resize.NO_CAPACITY

    def test_a_re_placement_carries_the_real_disk(self, miner) -> None:
        vm = _vm()
        _run_to_relaunched(vm, "large")
        assert sched.carried_data_disk_gb(vm) == 40

    def test_a_stopped_shrink_re_placed_carries_its_launch_disk(self, miner) -> None:
        """large (160 GB) shrunk while stopped keeps a NULL-disk `large`
        placement; a re-placement as `small` must still carry 160 GB."""
        vm = _vm(flavor="large", power_state=VmPowerState.STOPPED)
        _start(vm, "small")
        _tick()
        assert sched.carried_data_disk_gb(vm) == 160
