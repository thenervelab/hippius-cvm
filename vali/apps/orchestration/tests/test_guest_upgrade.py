"""Guest upgrade — move one VM onto a guest components build
(`apps.orchestration.guest_upgrade`, docs/design/guest-component-rollout.md).

A fake miner sits where the real one does (`effects.dispatch_graceful_stop`,
`effects.poll_domain_running`, `launch.launch_on_miner`); the power API, the
relaunch path and the launch record run for real. Like the real launch, the
fake PINS each launch's measurement (a `MeasurementLedger` row) before it
dispatches, stamps `launched_at` when accepted, and marks a superseding
register. Each test pins one claim:

1. a done upgrade went stop → swap → superseding relaunch → a live
   attestation of the measurement vali PINNED for that attempt → soak, and
   raised the floor before anything moved;
2. nothing else passes the gate — not an older guest, not a forged record;
3. it waits for its window, a stopped VM, any other operation, and decides
   on the LOCKED row;
4. a target that never attests is rolled back by a NEW forward launch of
   the previous set — unless the floor forbids it: then the VM is parked
   (domain DOWN) before the job releases it;
5. a tick that dies after the dispatch resumes from the pin, without
   dispatching twice; a miner reboot gets ONE recover, claimed first;
6. admission refuses what it cannot do, before anything moves.
"""

from __future__ import annotations

from datetime import timedelta
from types import SimpleNamespace
from typing import Any

import pytest
from django.test import override_settings
from django.utils import timezone

from apps.backup.models import BackupChain, BackupRun
from apps.lifecycle.models import Vm, VmPowerState
from apps.orchestration import guest_upgrade
from apps.orchestration.models import (
    GuestComponentRelease,
    GuestInitrdBuild,
    GuestUpgradeJob,
    GuestUpgradeState,
    LaunchJob,
    MeasurementLedger,
    VmGuestComponents,
)
from apps.orchestration.service import StartError
from apps.orchestration.services import guest_components, launch, launch_record

from . import test_resize as rz
from .factories import make_service_client

pytestmark = [pytest.mark.django_db]

S = GuestUpgradeState
BASE_INITRD = rz.SPEC["initrd_sha256_hex"]
BASE_PREFIX = rz.SPEC["s3_key_prefix"]

SETTINGS = override_settings(
    VALI_GUEST_UPGRADE_ENABLED=True,
    VALI_GUEST_UPGRADE_DISPATCH_PACING_S=0,
    VALI_GUEST_UPGRADE_SOAK_S=0,
    VALI_GUEST_UPGRADE_DISPATCH_SETTLE_S=0,
    VALI_SCHEDULER_RESOURCE_ADMISSION="true",
    VALI_SCHEDULER_MAX_FLAVOR="",
)


@pytest.fixture(autouse=True)
def _settings(monkeypatch: pytest.MonkeyPatch):
    # The gate leans on C2 ENFORCE (vali pins its own recompute).
    monkeypatch.setattr(guest_upgrade, "_c2_enforced", lambda: True)
    with SETTINGS:
        yield


@pytest.fixture(autouse=True)
def _hosts() -> None:
    rz._miner(rz.HOST, rz.HOST_NODE)


class UpgradeMiner:
    """The miner side of a stop and a relaunch, and the part of the launch
    that pins: every launch pins a fresh measurement (its initrd + a
    counter — a real relaunch's measured cmdline carries fresh nonces)."""

    def __init__(self) -> None:
        self.stops: list[dict[str, Any]] = []
        self.launches: list[dict[str, Any]] = []
        self.disposition = launch.ACCEPTED
        self.domain_running = True
        self.stop_error: Exception | None = None
        #: Raise out of the launch AFTER it was accepted (an Edge timeout
        #: on the answer, a tick killed mid-call).
        self.raise_after_accept = False
        #: The launch pins vali's own recompute (C2 ENFORCE) — False is a
        #: WARN-mode launch pinning the miner's digest.
        self.recomputed = True
        #: The miner answers `already-launched`: it started nothing.
        self.already_launched = False

    def stop(self, vm: Vm, **_kw: Any) -> None:
        self.stops.append({"vm_id": vm.vm_id})
        if self.stop_error is not None:
            raise self.stop_error
        self.domain_running = False

    def poll_domain_running(self, vm: Vm) -> bool:
        return self.domain_running

    def launch_on_miner(self, spec: Any, miner: Any, **kw: Any) -> SimpleNamespace:
        n = len(self.launches) + 1
        measurement = f"{spec.initrd_sha256_hex[:8]}{n:088x}"
        self.launches.append({"initrd": spec.initrd_sha256_hex, "measurement": measurement, **kw})
        pin = MeasurementLedger.objects.create(
            vm_id=spec.vm_id,
            launch_digest_hex=measurement,
            allowlist_epoch=n,
            superseded_at_register=timezone.now() if kw.get("supersede") else None,
            recomputed=self.recomputed,
            launch_ref=kw.get("launch_ref", ""),
        )
        if self.disposition != launch.ACCEPTED:
            return SimpleNamespace(
                disposition=self.disposition, emit={"outcome": "preflight-failure"}
            )
        if self.already_launched:
            self.domain_running = True
            return SimpleNamespace(
                disposition=launch.ACCEPTED,
                emit={"classifier": "already-launched", "measurement_hex": measurement},
            )
        pin.launched_at = timezone.now()
        pin.save(update_fields=["launched_at"])
        self.domain_running = True
        if self.raise_after_accept:
            self.raise_after_accept = False
            raise RuntimeError("edge timeout after the launch landed")
        return SimpleNamespace(
            disposition=launch.ACCEPTED,
            emit={"measurement_hex": measurement, "measured_cmdline": "console=ttyS0"},
        )


@pytest.fixture
def miner(monkeypatch: pytest.MonkeyPatch) -> UpgradeMiner:
    from apps.orchestration import effects
    from apps.orchestration.services import vault_kv

    fake = UpgradeMiner()
    monkeypatch.setattr(effects, "dispatch_graceful_stop", fake.stop)
    monkeypatch.setattr(effects, "poll_domain_running", fake.poll_domain_running)
    monkeypatch.setattr(launch, "launch_on_miner", fake.launch_on_miner)
    monkeypatch.setattr(vault_kv, "get_kv", lambda mount, path, version=None: b"user-data")
    return fake


def _build(
    version: int = 1,
    epoch: int = 1,
    initrd: str = "77" * 32,
    health_mask: int = 0,
    base_initrd: str = BASE_INITRD,
    prefix: str | None = None,
) -> GuestInitrdBuild:
    release, _ = GuestComponentRelease.objects.get_or_create(
        version=version,
        defaults={
            "commit": "c" * 40,
            "security_epoch": epoch,
            "squashfs_sha256": "d" * 64,
            "health_mask": health_mask,
        },
    )
    return GuestInitrdBuild.objects.create(
        release=release,
        source_bake_id="bake-1",
        family="initramfs-tools",
        kernel_sha256=rz.SPEC["kernel_sha256_hex"],
        rootfs_img_sha256=rz.SPEC["rootfs_img_sha256_hex"],
        rootfs_verity_sha256=rz.SPEC["rootfs_verity_sha256_hex"],
        verity_root_hash=rz.SPEC["verity_root_hash_hex"],
        base_initrd_sha256=base_initrd,
        release_cpio_sha256="e" * 64,
        initrd_sha256=initrd,
        s3_bucket=rz.SPEC["s3_bucket"],
        s3_key_prefix=prefix or f"{BASE_PREFIX}-gr{version}",
        measurement={},
    )


def _start(vm: Vm, build: GuestInitrdBuild, **kw: Any) -> GuestUpgradeJob:
    return guest_upgrade.start_guest_upgrade(
        vm=vm, build=build, decided_by=make_service_client(), **kw
    )


def _tick(n: int = 1) -> None:
    for _ in range(n):
        guest_upgrade.tick_guest_upgrades()


def _job(vm: Vm) -> GuestUpgradeJob:
    return GuestUpgradeJob.objects.filter(vm=vm).order_by("-started_at").first()


def _attest_measurement(
    vm: Vm,
    measurement: str,
    *,
    at: int | None = None,
    observed: int | None = None,
    **components: int,
) -> None:
    """A KBS-verified live attestation of `measurement` (what the keepalive
    ingest writes), verified at `at` (now by default); `components` are
    the v4 `components_*` columns (without the prefix)."""
    from apps.telemetry.models import VmLiveAttestation

    now = at if at is not None else int(timezone.now().timestamp()) + 1
    n = VmLiveAttestation.objects.count()
    VmLiveAttestation.objects.create(
        vm_id=vm.vm_id,
        node_id_hex=rz.HOST_NODE,
        attestation_seq=n + 1,
        epoch=1,
        observed_at_unix=observed if observed is not None else now,
        verified_at_unix=now,
        expiry_unix=now + 600,
        measurement=measurement,
        snp_report_digest=f"{n:064x}",
        body_digest=f"{n + 1:064x}",
        **{f"components_{k}": v for k, v in components.items()},
    )


def _attest_latest_launch(vm: Vm, miner: UpgradeMiner) -> str:
    """The guest the miner booted LAST attests."""
    measurement = miner.launches[-1]["measurement"]
    _attest_measurement(vm, measurement)
    return measurement


def _record(vm: Vm) -> tuple[str, str]:
    spec = launch_record.latest_record(vm.vm_id).spec_json
    return spec["s3_key_prefix"], spec["initrd_sha256_hex"]


def _expire(job: GuestUpgradeJob) -> None:
    GuestUpgradeJob.objects.filter(pk=job.pk).update(
        phase_started_at=timezone.now() - timedelta(hours=3)
    )


def _to_verifying(vm: Vm, build: GuestInitrdBuild) -> GuestUpgradeJob:
    _start(vm, build)
    _tick(4)  # pending → stopping → (stopped) → launching → verifying
    job = _job(vm)
    assert job.state == S.VERIFYING, job.reason
    return job


# ─── claim 1: the happy path ─────────────────────────────────────────


def test_an_upgrade_stops_swaps_relaunches_superseding_attests_and_soaks(miner) -> None:
    vm = rz._vm()
    build = _build(epoch=2)
    job = _start(vm, build)
    assert job.state == S.PENDING
    assert guest_components.required_epoch(vm.vm_id) == 0, "nothing raised before it leaves"

    _tick()  # pending → stopping (floor raised under the VM lock)
    assert _job(vm).state == S.STOPPING
    assert guest_components.required_epoch(vm.vm_id) == 2
    assert miner.stops == [] and miner.launches == []

    _tick(3)  # stop → domain DOWN → launching → relaunch → verifying
    assert len(miner.stops) == 1
    job = _job(vm)
    assert job.state == S.VERIFYING, job.reason
    (handed,) = miner.launches
    assert handed["initrd"] == build.initrd_sha256
    assert handed["supersede"] is True
    assert handed["require_existing_disks"] is True
    assert _record(vm) == (build.s3_key_prefix, build.initrd_sha256)
    (attempt,) = job.attempt_rows.all()
    assert attempt.measurement == handed["measurement"], "the attempt names the PINNED measurement"

    _tick()  # no attestation of it yet
    assert _job(vm).state == S.VERIFYING
    _attest_latest_launch(vm, miner)
    _tick()  # verifying → soaking
    assert _job(vm).state == S.SOAKING
    _tick()  # soak 0 → done
    job = _job(vm)
    assert job.state == S.DONE, job.reason
    assert VmGuestComponents.objects.get(vm=vm).attested_epoch == 2


# ─── claim 2: nothing else passes the gate ──────────────────────────


def test_an_older_guest_attesting_does_not_pass_the_gate(miner) -> None:
    vm = rz._vm()
    old = launch_record.recorded_measurement(vm.vm_id)
    _to_verifying(vm, _build())
    _attest_measurement(vm, old)
    _tick(2)
    assert _job(vm).state == S.VERIFYING


def test_a_record_naming_an_attested_measurement_does_not_pass_the_gate(miner) -> None:
    """The gate reads the attempt's PIN, never the mutable launch record."""
    vm = rz._vm()
    job = _to_verifying(vm, _build())
    forged = "f" * 96
    record = launch_record.latest_record(vm.vm_id)
    emit = dict(record.result_json["emit"])
    emit["measurement_hex"] = forged
    record.result_json = {**record.result_json, "emit": emit}
    record.save(update_fields=["result_json"])
    _attest_measurement(vm, forged)
    _tick(2)
    assert _job(vm).state == S.VERIFYING
    assert job.attempt_rows.get().measurement != forged


def test_admission_requires_c2_enforce(miner, monkeypatch) -> None:
    monkeypatch.setattr(guest_upgrade, "_c2_enforced", lambda: False)
    vm = rz._vm()
    with pytest.raises(StartError) as refused:
        _start(vm, _build())
    assert refused.value.category == "c2-not-enforced"


# ─── claim 3: it waits, and decides on the locked row ────────────────


def test_it_waits_for_its_window(miner) -> None:
    vm = rz._vm()
    _start(vm, _build(), not_before=timezone.now() + timedelta(hours=1))
    _tick(3)
    assert _job(vm).state == S.PENDING
    assert miner.stops == []


def test_a_stopped_vm_stays_pending(miner) -> None:
    vm = rz._vm(power_state=VmPowerState.STOPPED)
    _start(vm, _build())
    _tick(3)
    assert _job(vm).state == S.PENDING
    assert miner.stops == [] and miner.launches == []


def test_a_stop_landing_before_the_lock_keeps_it_pending(miner) -> None:
    """The decision reads the LOCKED row: a tenant stop that committed after
    the tick read the VM must not be undone by the upgrade."""
    vm = rz._vm()
    job = _start(vm, _build(epoch=2))
    stale = Vm.objects.get(pk=vm.pk)  # read as running
    Vm.objects.filter(pk=vm.pk).update(power_state=VmPowerState.STOPPED)
    job.vm = stale
    with pytest.raises(guest_upgrade._Retry):
        guest_upgrade._h_pending(job, stale)
    assert _job(vm).state == S.PENDING
    assert guest_components.required_epoch(vm.vm_id) == 0, "no floor raised"


def test_it_never_interrupts_a_backup(miner) -> None:
    vm = rz._vm()
    _start(vm, _build())
    chain = BackupChain.objects.create(vm=vm)
    BackupRun.objects.create(
        vm=vm,
        chain=chain,
        seq=1,
        kind="full",
        miner_id=vm.host,
        disk_key="d",
        state_key="s",
        manifest_key="m",
        part_size=1,
        part_count=1,
    )
    _tick(3)
    assert _job(vm).state == S.PENDING
    assert guest_components.required_epoch(vm.vm_id) == 0


# ─── claim 4: rollback within the floor, parking otherwise ───────────


def test_a_target_that_never_attests_is_rolled_back_by_a_new_launch(miner) -> None:
    vm = rz._vm()
    job = _to_verifying(vm, _build(epoch=0))  # same epoch as the base
    _expire(job)
    _tick()  # verifying timeout → rolling_back
    assert _job(vm).state == S.ROLLING_BACK
    _tick(3)  # stop the target → domain DOWN → swap back → superseding relaunch
    assert _record(vm) == (BASE_PREFIX, BASE_INITRD)
    assert miner.launches[-1]["initrd"] == BASE_INITRD
    assert miner.launches[-1]["supersede"] is True, "the failed launch is refused from now on"
    _tick()
    assert _job(vm).state == S.ROLLING_BACK, "waits for THIS launch to attest"
    _attest_latest_launch(vm, miner)
    _tick()
    job = _job(vm)
    assert job.state == S.ROLLED_BACK, job.reason
    assert job.outcome == guest_upgrade.NO_SAMPLE
    assert job.reason.startswith("no-sample: verifying-timeout")
    kinds = list(job.attempt_rows.order_by("started_at").values_list("kind", "outcome"))
    assert kinds == [("upgrade", "accepted"), ("rollback", "accepted")]


def test_an_epoch_raise_never_rolls_back_and_parks_the_vm_down(miner) -> None:
    vm = rz._vm()
    job = _to_verifying(vm, _build(epoch=3))
    _expire(job)
    _tick()  # timeout → parking (rollback forbidden)
    assert _job(vm).state == S.PARKING
    _tick(3)  # stop the unverified boot → domain DOWN → released
    job = _job(vm)
    assert job.state == S.UPGRADE_BLOCKED, job.reason
    assert "rollback forbidden" in job.reason
    assert len(miner.launches) == 1, "the previous set is never launched again"
    vm.refresh_from_db()
    assert vm.power_state == VmPowerState.STOPPED
    assert miner.domain_running is False


def test_three_rejected_relaunches_roll_back(miner) -> None:
    vm = rz._vm()
    _start(vm, _build(epoch=0))
    miner.disposition = launch.RETRIABLE
    for _ in range(8):
        _tick()
        if _job(vm).state == S.ROLLING_BACK:
            break
    job = _job(vm)
    assert job.state == S.ROLLING_BACK, job.reason
    assert "relaunch-rejected" in job.reason


def test_a_stop_that_never_takes_leaves_the_vm_as_it_was(miner) -> None:
    vm = rz._vm()
    _start(vm, _build(epoch=0))
    miner.stop_error = RuntimeError("edge 502")
    _tick(3)
    job = _job(vm)
    assert job.state == S.STOPPING
    _expire(job)
    _tick()  # timeout → rolling_back
    assert _job(vm).state == S.ROLLING_BACK
    # The abandoned stop settles to what the miner runs: the old guest.
    Vm.objects.filter(pk=vm.pk).update(power_state=VmPowerState.RUNNING)
    _tick()  # nothing of the target was dispatched: rolled back as it was
    job = _job(vm)
    assert job.state == S.ROLLED_BACK, job.reason
    assert miner.launches == []
    assert _record(vm) == (BASE_PREFIX, BASE_INITRD)


# ─── claim 5: restart-safety, one recover ───────────────────────────


def test_a_launch_answered_as_failed_but_landed_is_taken_from_the_pin(miner) -> None:
    """The relaunch path reports a refusal (an Edge timeout on the answer)
    but the launch landed: the miner runs the domain, the pin says what it
    measures — accepted, never dispatched again."""
    vm = rz._vm()
    _start(vm, _build())
    miner.raise_after_accept = True
    _tick(4)
    job = _job(vm)
    assert job.state == S.VERIFYING, job.reason
    (attempt,) = job.attempt_rows.all()
    assert (attempt.outcome, attempt.measurement) == ("accepted", miner.launches[-1]["measurement"])
    assert len(miner.launches) == 1, "never dispatched twice"
    vm.refresh_from_db()
    assert vm.power_state == VmPowerState.RUNNING, "the books follow the miner"
    _attest_latest_launch(vm, miner)
    _tick(2)
    assert _job(vm).state == S.DONE


def test_a_tick_dying_inside_the_start_resumes_from_the_pin(miner, monkeypatch) -> None:
    """The process dies after the launch was dispatched and accepted, before
    anything was recorded: the next tick reconciles the open attempt from
    its pin instead of dispatching again."""
    from apps.orchestration.services import power

    real = power.start_vm
    died = {"n": 0}

    def dying_start(vm: Vm, **kw: Any) -> Vm:
        out = real(vm, **kw)
        if not died["n"]:
            died["n"] = 1
            raise SystemError("worker killed")
        return out

    monkeypatch.setattr(power, "start_vm", dying_start)
    vm = rz._vm()
    _start(vm, _build())
    _tick(4)
    job = _job(vm)
    (attempt,) = job.attempt_rows.all()
    assert attempt.outcome == "", "the dying call recorded nothing"
    _tick()
    job = _job(vm)
    assert job.state == S.VERIFYING, job.reason
    attempt.refresh_from_db()
    assert (attempt.outcome, attempt.measurement) == ("accepted", miner.launches[-1]["measurement"])
    assert len(miner.launches) == 1, "never dispatched twice"


def test_a_miner_reboot_while_verifying_gets_one_claimed_recover(miner) -> None:
    vm = rz._vm()
    before = launch_record.recorded_measurement(vm.vm_id)
    _to_verifying(vm, _build())
    miner.domain_running = False  # the host rebooted
    _tick()
    job = _job(vm)
    assert job.recover_used is True
    assert len(miner.launches) == 2
    assert miner.launches[-1]["supersede"] is False
    assert miner.launches[-1]["initrd"] == job.target.initrd_sha256
    # The previous set's guest attesting proves nothing.
    _attest_measurement(vm, before)
    _tick()
    assert _job(vm).state == S.VERIFYING
    _attest_latest_launch(vm, miner)
    _tick()
    assert _job(vm).state == S.SOAKING


def test_a_rejected_recover_is_not_retried(miner) -> None:
    vm = rz._vm()
    _to_verifying(vm, _build(epoch=0))
    miner.domain_running = False
    miner.disposition = launch.RETRIABLE
    _tick()
    job = _job(vm)
    assert job.recover_used is True
    assert job.state == S.ROLLING_BACK, job.reason
    assert len(miner.launches) == 2


# ─── claim 6: admission ──────────────────────────────────────────────


def test_admission_refuses_what_it_cannot_do(miner) -> None:
    vm = rz._vm()
    other_base = _build(version=9, initrd="99" * 32)
    GuestInitrdBuild.objects.filter(pk=other_base.pk).update(kernel_sha256="ab" * 32)
    other_base.refresh_from_db()
    with pytest.raises(StartError) as refused:
        _start(vm, other_base)
    assert refused.value.category == "other-base"
    build = _build(version=2, epoch=1, initrd="88" * 32)
    _start(vm, build)
    with pytest.raises(StartError) as refused:
        _start(vm, build)
    assert refused.value.category == "job-in-flight"


# An initrd-only rebuild of the base (`scripts/tenant-initrd-rebuild.sh`):
# same kernel and dm-verity base, another initrd — another base.
HARDENED_INITRD = "4e" * 32
HARDENED_PREFIX = f"{BASE_PREFIX}-initrd-4e4e4e4e"


def _hardened_vm(vm_id: str = "vm-h") -> Vm:
    vm = rz._vm(vm_id)
    job = LaunchJob.objects.get(vm_id=vm_id)
    job.spec_json = {
        **job.spec_json,
        "s3_key_prefix": HARDENED_PREFIX,
        "initrd_sha256_hex": HARDENED_INITRD,
    }
    job.save(update_fields=["spec_json"])
    return vm


def _two_bases(version: int = 2, epoch: int = 1) -> tuple[GuestInitrdBuild, GuestInitrdBuild]:
    """Release `version` built on the base and on its initrd-only rebuild."""
    original = _build(version=version, epoch=epoch, initrd=f"{version:02x}" * 31 + "0a")
    hardened = _build(
        version=version,
        epoch=epoch,
        initrd=f"{version:02x}" * 31 + "0b",
        base_initrd=HARDENED_INITRD,
        prefix=f"{HARDENED_PREFIX}-gr{version}",
    )
    return original, hardened


def test_each_vm_resolves_to_the_build_of_its_own_base_initrd(miner) -> None:
    original, hardened = _two_bases(version=2)
    vm = rz._vm()
    hvm = _hardened_vm()
    assert guest_upgrade.build_for_vm(vm, 2) == original
    assert guest_upgrade.build_for_vm(hvm, 2) == hardened
    # On a build, a VM resolves through the build's base initrd: to its
    # own build of that release, to its base's build of the next one, and
    # to nothing when only the other base has one.
    _to_verifying(hvm, hardened)
    _attest_latest_launch(hvm, miner)
    _tick(2)
    assert _job(hvm).state == S.DONE
    assert _record(hvm) == (hardened.s3_key_prefix, hardened.initrd_sha256)
    assert guest_upgrade.build_for_vm(hvm, 2) == hardened
    original3 = _build(version=3, epoch=1, initrd="03" * 31 + "0a")
    assert guest_upgrade.build_for_vm(vm, 3) == original3
    assert guest_upgrade.build_for_vm(hvm, 3) is None
    hardened3 = _build(
        version=3,
        epoch=1,
        initrd="03" * 31 + "0b",
        base_initrd=HARDENED_INITRD,
        prefix=f"{HARDENED_PREFIX}-gr3",
    )
    assert guest_upgrade.build_for_vm(hvm, 3) == hardened3
    assert guest_upgrade.components_of(hvm)["newest_release"] == 3
    # An initrd no build was made on has none.
    other = _hardened_vm("vm-x")
    LaunchJob.objects.filter(vm_id="vm-x").update(
        spec_json={**rz.SPEC, "vm_id": "vm-x", "initrd_sha256_hex": "5f" * 32}
    )
    assert guest_upgrade.build_for_vm(other, 2) is None


def test_admission_never_moves_a_vm_across_base_initrds(miner) -> None:
    original, hardened = _two_bases(version=2)
    vm = rz._vm()
    hvm = _hardened_vm()
    for who, build in ((hvm, original), (vm, hardened)):
        with pytest.raises(StartError) as refused:
            _start(who, build)
        assert refused.value.category == "unknown-initrd"
    # Nor from a build of one base onto the next release's build of the other.
    _to_verifying(hvm, hardened)
    _attest_latest_launch(hvm, miner)
    _tick(2)
    assert _job(hvm).state == S.DONE
    original3 = _build(version=3, epoch=1, initrd="03" * 31 + "0a")
    with pytest.raises(StartError) as refused:
        _start(hvm, original3)
    assert refused.value.category == "unknown-initrd"
    assert _start(vm, original).state == S.PENDING


def test_a_downgrade_needs_an_explicit_rollback(miner) -> None:
    vm = rz._vm()
    newer = _build(version=3, epoch=1, initrd="33" * 31 + "34")
    _to_verifying(vm, newer)
    _attest_latest_launch(vm, miner)
    _tick(2)
    assert _job(vm).state == S.DONE
    older = _build(version=2, epoch=1, initrd="66" * 32)
    with pytest.raises(StartError) as refused:
        _start(vm, older)
    assert refused.value.category == "downgrade"
    assert _start(vm, older, rollback=True).state == S.PENDING


def test_the_tick_is_off_without_the_flag(miner) -> None:
    vm = rz._vm()
    _start(vm, _build())
    with override_settings(VALI_GUEST_UPGRADE_ENABLED=False):
        assert guest_upgrade.tick_guest_upgrades() == 0
    assert _job(vm).state == S.PENDING


def test_the_orchestration_tick_drives_it(miner) -> None:
    from apps.orchestration import service

    vm = rz._vm()
    _start(vm, _build())
    service.tick_once()
    assert _job(vm).state == S.STOPPING


def test_the_command_is_a_dry_run_until_applied(miner) -> None:
    import io

    from django.core.management import call_command

    vm = rz._vm()
    build = _build(version=4, initrd="44" * 31 + "45")
    out = io.StringIO()
    call_command("vali_guest_upgrade", f"--vm-id={vm.vm_id}", "--release=4", stdout=out)
    assert "dry-run" in out.getvalue()
    assert not GuestUpgradeJob.objects.filter(vm=vm).exists()
    call_command("vali_guest_upgrade", f"--vm-id={vm.vm_id}", "--release=4", "--apply", stdout=out)
    assert _job(vm).target == build
    out = io.StringIO()
    call_command("vali_guest_upgrade", f"--vm-id={vm.vm_id}", "--status", stdout=out)
    assert "pending" in out.getvalue()


# ─── round 2: C2 per launch, the attempt↔pin link, parking ──────────


def test_no_upgrade_launch_without_c2_enforce(miner, monkeypatch) -> None:
    """ENFORCE is required per launch, not only at admission: a job resumed
    with it off dispatches nothing and its deadline fails it closed."""
    vm = rz._vm()
    _start(vm, _build(epoch=3))
    _tick(2)  # pending → stopping → (stopped)
    monkeypatch.setattr(guest_upgrade, "_c2_enforced", lambda: False)
    _tick(3)
    job = _job(vm)
    assert job.state == S.LAUNCHING, job.reason
    assert miner.launches == []
    _expire(job)
    _tick()  # launching timeout → parking (rollback forbidden by the floor)
    _tick(2)
    job = _job(vm)
    assert job.state == S.UPGRADE_BLOCKED, job.reason
    assert miner.launches == [], "nothing launched without ENFORCE"


def test_a_pin_of_the_miners_digest_never_passes_the_gate(miner) -> None:
    """A pin that is not vali's own recompute (WARN mode) proves nothing."""
    vm = rz._vm()
    miner.recomputed = False
    _to_verifying(vm, _build())
    _attest_latest_launch(vm, miner)
    _tick(2)
    assert _job(vm).state == S.VERIFYING


def test_the_gate_reads_the_attempts_own_pin(miner) -> None:
    """A ledger row of the VM that is not linked to an attempt — another
    launch's pin, however recent — never passes the gate."""
    vm = rz._vm()
    _to_verifying(vm, _build())
    MeasurementLedger.objects.create(
        vm_id=vm.vm_id, launch_digest_hex="ab" * 48, allowlist_epoch=99, recomputed=True
    )
    _attest_measurement(vm, "ab" * 48)
    _tick(2)
    assert _job(vm).state == S.VERIFYING


def test_a_refused_dispatch_with_the_domain_down_stays_open_until_it_settled(miner) -> None:
    """A refusal may be an answer lost on the way back: while the dispatch
    can still land, the attempt stays open and nothing is dispatched again."""
    vm = rz._vm()
    _start(vm, _build(epoch=0))
    miner.disposition = launch.RETRIABLE
    with override_settings(VALI_GUEST_UPGRADE_DISPATCH_SETTLE_S=600):
        _tick(6)
        job = _job(vm)
        (attempt,) = job.attempt_rows.all()
        assert (attempt.outcome, attempt.answer) == ("", "relaunch-rejected")
        assert len(miner.launches) == 1, "never re-dispatched while it may land"
        # A slow launch choreography (preflight) does not eat the window: it
        # runs from the answer, not from the attempt's creation.
        long_ago = timezone.now() - timedelta(seconds=3600)
        type(attempt).objects.filter(pk=attempt.pk).update(started_at=long_ago)
        MeasurementLedger.objects.filter(launch_ref=str(attempt.id)).update(pinned_at=long_ago)
        _tick()
        attempt.refresh_from_db()
        assert attempt.outcome == "", "answered moments ago: still settling"
        _expire(_job(vm))
        _tick()
        assert _job(vm).state == S.LAUNCHING, "no fail-over while the dispatch may land"
        assert len(miner.launches) == 1
        type(attempt).objects.filter(pk=attempt.pk).update(answered_at=long_ago)
        Vm.objects.filter(pk=vm.pk).update(power_state_at=long_ago)
        _tick()
    attempt.refresh_from_db()
    assert attempt.outcome == "refused:relaunch-rejected"


def test_an_already_launched_answer_is_judged_on_the_earlier_attempts_pin(miner) -> None:
    """The first dispatch was answered as refused and settled DOWN, then came
    up; the retry is answered `already-launched` (the miner started nothing).
    The boot that runs is the FIRST attempt's — its pin passes the gate."""
    vm = rz._vm()
    _start(vm, _build(epoch=0))
    miner.disposition = launch.RETRIABLE
    _tick(4)  # → launching, first attempt refused (settle 0, domain down)
    job = _job(vm)
    assert job.attempt_rows.get().outcome == "refused:relaunch-rejected"
    first = miner.launches[0]["measurement"]
    miner.disposition = launch.ACCEPTED
    miner.already_launched = True
    _tick()
    job = _job(vm)
    assert job.state == S.VERIFYING, job.reason
    assert len(miner.launches) == 2
    _attest_measurement(vm, first)
    _tick(2)
    assert _job(vm).state == S.DONE, _job(vm).reason


def test_parking_past_its_deadline_keeps_holding_the_vm(miner, monkeypatch) -> None:
    """Never released on time alone: a domain the miner never reports DOWN
    keeps the job parking (and stopping) until an operator releases it."""
    from io import StringIO

    from django.core.management import CommandError, call_command

    from apps.orchestration import effects

    vm = rz._vm()
    job = _to_verifying(vm, _build(epoch=3))
    _expire(job)
    _tick()  # → parking
    assert _job(vm).state == S.PARKING
    monkeypatch.setattr(effects, "dispatch_graceful_stop", lambda vm, **_kw: None)
    _expire(_job(vm))
    _tick(3)
    job = _job(vm)
    assert job.state == S.PARKING
    assert guest_upgrade.PARKING_OVERDUE in job.reason
    with pytest.raises(CommandError):
        call_command("vali_guest_upgrade", f"--vm-id={vm.vm_id}", f"--release-parked={job.job_id}")
    out = StringIO()
    call_command(
        "vali_guest_upgrade",
        f"--vm-id={vm.vm_id}",
        f"--release-parked={job.job_id}",
        "--operator=ops-1",
        "--reason=domain destroyed by hand on the host",
        stdout=out,
    )
    job = _job(vm)
    assert (job.state, job.released_by) == (S.UPGRADE_BLOCKED, "ops-1")
    assert "released by ops-1" in job.reason


# ─── phase 5: the component health leg ──────────────────────────────

HEALTHY = {"release_version": 2, "security_epoch": 1, "health": 15, "instance": 7}


def _health_build() -> GuestInitrdBuild:
    return _build(version=2, epoch=1, initrd="2a" * 32, health_mask=15)


def test_a_release_with_health_checks_gates_on_a_healthy_v4_sample(miner) -> None:
    vm = rz._vm()
    _to_verifying(vm, _health_build())
    m = miner.launches[-1]["measurement"]
    _attest_measurement(vm, m)  # v3-style: no components
    _attest_measurement(vm, m, **{**HEALTHY, "health": 0b0111, "unhealthy_ticks": 0})
    _attest_measurement(vm, m, **{**HEALTHY, "release_version": 1, "unhealthy_ticks": 0})
    _attest_measurement(vm, m, **{**HEALTHY, "security_epoch": 0, "unhealthy_ticks": 0})
    _tick(2)
    assert _job(vm).state == S.VERIFYING, "no sample meets condition 4"
    _attest_measurement(vm, m, **HEALTHY, unhealthy_ticks=1)
    _tick()
    job = _job(vm)
    assert job.state in (S.SOAKING, S.DONE), job.reason
    assert (job.gate_instance, job.gate_unhealthy_ticks) == (7, 1)


def _to_soaking_healthy(vm: Vm, miner: UpgradeMiner) -> tuple[GuestUpgradeJob, str, int]:
    _to_verifying(vm, _health_build())
    m = miner.launches[-1]["measurement"]
    gate_at = int(timezone.now().timestamp()) + 1
    _attest_measurement(vm, m, at=gate_at, **HEALTHY, unhealthy_ticks=1)
    _tick()
    job = _job(vm)
    assert job.state == S.SOAKING, job.reason
    return job, m, gate_at


@override_settings(VALI_GUEST_UPGRADE_SOAK_S=600)
def test_the_soak_holds_every_sample_to_the_gate_samples_keepalive(miner) -> None:
    vm = rz._vm()
    job, m, gate_at = _to_soaking_healthy(vm, miner)
    end = int(job.phase_started_at.timestamp()) + 600
    _attest_measurement(vm, m, at=gate_at + 300, **HEALTHY, unhealthy_ticks=1)
    _tick()
    assert _job(vm).state == S.SOAKING, "no sample past the soak's end yet"
    _attest_measurement(vm, m, at=end + 1, **HEALTHY, unhealthy_ticks=1)
    _tick()
    job = _job(vm)
    assert job.state == S.DONE, job.reason
    assert VmGuestComponents.objects.get(vm=vm).attested_epoch == 1


@override_settings(VALI_GUEST_UPGRADE_SOAK_S=600)
@pytest.mark.parametrize(
    ("later", "outcome", "evidence"),
    [
        # a tick failed in between — the sample that showed it was withheld,
        # the latch carries it
        ({**HEALTHY, "unhealthy_ticks": 2}, "health-latched", "2 failing tick(s)"),
        # the keepalive restarted
        ({**HEALTHY, "instance": 8, "unhealthy_ticks": 0}, "guest-restarted", "instance 8"),
        # a failing sample: which check is missing
        (
            {**HEALTHY, "health": 0b1011, "unhealthy_ticks": 2},
            "health-failed",
            "misses checks 0x4 (bits 2)",
        ),
        # a sample without the leg
        ({}, "health-failed", "without the health leg"),
    ],
)
def test_the_soak_fails_on_a_latched_failure_a_restart_or_a_failing_sample(
    miner, later: dict[str, int], outcome: str, evidence: str
) -> None:
    vm = rz._vm()
    job, m, _ = _to_soaking_healthy(vm, miner)
    end = int(job.phase_started_at.timestamp()) + 600
    _attest_measurement(vm, m, at=end + 1, **later)
    _tick()
    job = _job(vm)
    assert job.state not in (S.SOAKING, S.DONE), job.reason
    assert job.outcome == outcome, job.reason
    assert job.reason.startswith(f"{outcome}: soak:"), job.reason
    assert evidence in job.reason, job.reason


@override_settings(VALI_GUEST_UPGRADE_SOAK_S=600)
def test_another_launchs_guest_does_not_count_in_the_soak(miner) -> None:
    vm = rz._vm()
    job, m, _ = _to_soaking_healthy(vm, miner)
    end = int(job.phase_started_at.timestamp()) + 600
    _attest_measurement(vm, "ee" * 48, at=end + 1, **{**HEALTHY, "instance": 99})
    _tick()
    assert _job(vm).state == S.SOAKING


@override_settings(VALI_GUEST_UPGRADE_SOAK_S=600)
def test_a_check_the_relay_held_back_across_the_end_does_not_end_the_soak(miner) -> None:
    """A healthy request taken before the end, delayed and signed after
    it: its `observed_at` (the nonce's issuance) is before the end."""
    vm = rz._vm()
    job, m, _ = _to_soaking_healthy(vm, miner)
    end = int(job.phase_started_at.timestamp()) + 600
    _attest_measurement(vm, m, at=end + 200, observed=end - 100, **HEALTHY, unhealthy_ticks=1)
    _tick()
    assert _job(vm).state == S.SOAKING


@override_settings(VALI_GUEST_UPGRADE_SOAK_S=600)
def test_no_end_sample_by_the_deadline_fails_the_soak(miner) -> None:
    from apps.telemetry.models import VmLiveAttestation

    vm = rz._vm()
    job, m, _ = _to_soaking_healthy(vm, miner)
    end = int(job.phase_started_at.timestamp()) + 600
    _expire(job)  # the deadline is behind us…
    _attest_measurement(vm, m, at=end + 1, **HEALTHY, unhealthy_ticks=1)
    # …and the end sample reached vali only now.
    VmLiveAttestation.objects.filter(observed_at_unix=end + 1).update(created_at=timezone.now())
    _tick()
    job = _job(vm)
    assert job.state not in (S.SOAKING, S.DONE), job.reason


# ─── the operator API (phase 6) ──────────────────────────────────────


class _ViewClient:
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


class TestViews(_ViewClient):
    def test_components_schedule_reschedule_poll_and_cancel(self, client, miner) -> None:
        vm = rz._vm()
        _build(version=3, epoch=1, initrd="3a" * 32)
        r = client.get(f"/v1/vm/{vm.vm_id}/guest-components")
        assert r.status_code == 200, r.content
        body = r.json()
        assert (body["release"], body["newest_release"], body["upgrade"]) == (None, 3, None)
        assert (body["security_epoch"], body["newest_security_epoch"]) == (0, 1)

        later = (timezone.now() + timedelta(days=1)).isoformat()
        r = client.post(
            f"/v1/vm/{vm.vm_id}/guest-upgrade", {"release": 3, "not_before": later}, format="json"
        )
        assert r.status_code == 202, r.content
        job_id = r.json()["job_id"]
        assert (r.json()["state"], r.json()["release"]) == ("pending", 3)
        components = client.get(f"/v1/vm/{vm.vm_id}/guest-components").json()
        assert components["upgrade"]["job_id"] == job_id

        # "Upgrade now": the same release moves the pending job's window.
        r = client.post(f"/v1/vm/{vm.vm_id}/guest-upgrade", {"release": 3}, format="json")
        assert r.status_code == 200, r.content
        assert r.json()["job_id"] == job_id
        assert _job(vm).not_before <= timezone.now()

        r = client.get(f"/v1/vm/{vm.vm_id}/guest-upgrade/{job_id}")
        assert r.status_code == 200 and r.json()["state"] == "pending"
        r = client.get(f"/v1/vm/{vm.vm_id}/guest-upgrade")
        assert r.status_code == 200 and r.json()["job_id"] == job_id

        r = client.post(f"/v1/vm/{vm.vm_id}/guest-upgrade/{job_id}/cancel")
        assert r.status_code == 200, r.content
        assert r.json()["state"] == "cancelled"
        assert miner.stops == [] and miner.launches == []

    def test_a_job_that_holds_the_vm_is_not_cancelled_or_rescheduled(self, client, miner) -> None:
        vm = rz._vm()
        _build(version=3, epoch=1, initrd="3a" * 32)
        r = client.post(f"/v1/vm/{vm.vm_id}/guest-upgrade", {"release": 3}, format="json")
        job_id = r.json()["job_id"]
        _tick()  # pending → stopping
        assert _job(vm).state == S.STOPPING
        r = client.post(f"/v1/vm/{vm.vm_id}/guest-upgrade/{job_id}/cancel")
        assert (r.status_code, r.json()["category"]) == (409, "not-pending")
        r = client.post(f"/v1/vm/{vm.vm_id}/guest-upgrade", {"release": 3}, format="json")
        assert r.status_code == 409, r.content

    def test_refusals(self, client) -> None:
        vm = rz._vm()
        r = client.post(f"/v1/vm/{vm.vm_id}/guest-upgrade", {"release": 9}, format="json")
        assert (r.status_code, r.json()["category"]) == (400, "no-build")
        for bad in ({}, {"release": "3"}, {"release": 0}, {"release": 3, "not_before": "soon"}):
            r = client.post(f"/v1/vm/{vm.vm_id}/guest-upgrade", bad, format="json")
            assert (r.status_code, r.json()["category"]) == (400, "wire"), bad
        r = client.post(
            f"/v1/vm/{vm.vm_id}/guest-upgrade",
            {"release": 3, "not_before": "2026-10-06T02:00:00"},
            format="json",
        )
        assert r.status_code == 400, "a time without a zone is refused"
        r = client.post("/v1/vm/nope/guest-upgrade", {"release": 3}, format="json")
        assert r.status_code == 404
        assert client.get(f"/v1/vm/{vm.vm_id}/guest-upgrade").status_code == 404
        assert client.get("/v1/vm/nope/guest-components").status_code == 404


class TestViewsGuards:
    """The routes are root-only, and the review's edge cases."""

    def test_a_non_root_operator_is_refused(self, miner) -> None:
        from rest_framework.test import APIClient

        from apps.identity.models import ServiceClient

        vm = rz._vm()
        c = APIClient()
        c.force_authenticate(user=ServiceClient.objects.create(name="ops-2", scope="operator"))
        with override_settings(VALI_ORCHESTRATION_ROOT_PRINCIPAL="orchestration-root"):
            assert c.get(f"/v1/vm/{vm.vm_id}/guest-components").status_code == 403
            r = c.post(f"/v1/vm/{vm.vm_id}/guest-upgrade", {"release": 3}, format="json")
            assert r.status_code == 403


class TestViewsEdges(_ViewClient):
    def test_an_explicit_null_window_is_refused_not_read_as_now(self, client, miner) -> None:
        vm = rz._vm()
        _build(version=3, epoch=1, initrd="3a" * 32)
        later = (timezone.now() + timedelta(days=1)).isoformat()
        client.post(
            f"/v1/vm/{vm.vm_id}/guest-upgrade", {"release": 3, "not_before": later}, format="json"
        )
        r = client.post(
            f"/v1/vm/{vm.vm_id}/guest-upgrade", {"release": 3, "not_before": None}, format="json"
        )
        assert (r.status_code, r.json()["category"]) == (400, "wire")
        assert _job(vm).not_before > timezone.now(), "the window did not move"

    def test_a_pending_job_whose_target_was_withdrawn_is_cancelled(self, client, miner) -> None:
        vm = rz._vm()
        build = _build(version=3, epoch=1, initrd="3a" * 32)
        later = (timezone.now() + timedelta(days=1)).isoformat()
        client.post(
            f"/v1/vm/{vm.vm_id}/guest-upgrade", {"release": 3, "not_before": later}, format="json"
        )
        GuestInitrdBuild.objects.filter(pk=build.pk).update(withdrawn_at=timezone.now())
        r = client.post(f"/v1/vm/{vm.vm_id}/guest-upgrade", {"release": 3}, format="json")
        assert (r.status_code, r.json()["category"]) == (409, "build-withdrawn")
        assert _job(vm).state == S.CANCELLED

    def test_a_doomed_pending_job_never_blocks_another_release(self, client, miner) -> None:
        vm = rz._vm()
        old = _build(version=3, epoch=1, initrd="3a" * 32)
        _build(version=5, epoch=1, initrd="5a" * 32)
        later = (timezone.now() + timedelta(days=1)).isoformat()
        client.post(
            f"/v1/vm/{vm.vm_id}/guest-upgrade", {"release": 3, "not_before": later}, format="json"
        )
        GuestInitrdBuild.objects.filter(pk=old.pk).update(withdrawn_at=timezone.now())
        r = client.post(f"/v1/vm/{vm.vm_id}/guest-upgrade", {"release": 5}, format="json")
        assert r.status_code == 202, r.content
        assert r.json()["release"] == 5
        states = sorted(GuestUpgradeJob.objects.filter(vm=vm).values_list("state", flat=True))
        assert states == [S.CANCELLED, S.PENDING]

    def test_a_doomed_job_on_a_stopped_vm_is_cancelled_too(self, miner) -> None:
        vm = rz._vm(power_state=VmPowerState.STOPPED)
        build = _build(version=3, epoch=1, initrd="3a" * 32)
        _start(vm, build)
        GuestInitrdBuild.objects.filter(pk=build.pk).update(withdrawn_at=timezone.now())
        _tick()
        assert _job(vm).state == S.CANCELLED

    def test_the_tick_cancels_a_doomed_job_before_its_window(self, miner) -> None:
        vm = rz._vm()
        build = _build(version=3, epoch=1, initrd="3a" * 32)
        _start(vm, build, not_before=timezone.now() + timedelta(days=1))
        GuestInitrdBuild.objects.filter(pk=build.pk).update(withdrawn_at=timezone.now())
        _tick()
        job = _job(vm)
        assert job.state == S.CANCELLED and job.reason.startswith("build-withdrawn")

    def test_a_job_in_flight_is_a_conflict_whatever_its_stage(self, client, miner) -> None:
        vm = rz._vm()
        _build(version=3, epoch=1, initrd="3a" * 32)
        client.post(f"/v1/vm/{vm.vm_id}/guest-upgrade", {"release": 3}, format="json")
        _tick(4)  # → verifying (the record names the target now)
        assert _job(vm).state == S.VERIFYING
        r = client.post(f"/v1/vm/{vm.vm_id}/guest-upgrade", {"release": 3}, format="json")
        assert (r.status_code, r.json()["category"]) == (409, "job-in-flight")

    def test_a_vm_without_a_launch_record_is_a_conflict(self, client, miner) -> None:
        vm = rz._vm()
        launch_record.latest_record(vm.vm_id).delete()
        r = client.post(f"/v1/vm/{vm.vm_id}/guest-upgrade", {"release": 3}, format="json")
        assert (r.status_code, r.json()["category"]) == (409, "no-launch-record")
