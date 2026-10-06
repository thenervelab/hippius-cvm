"""Guest components releases and the per-VM security floor
(`services.guest_components`, docs/design/guest-component-rollout.md):
build registration from a real build document, the floor every launch
path enforces, and the interlocks that keep a guest upgrade holding a VM
apart from every other operation."""

from __future__ import annotations

import io
import json
from pathlib import Path
from typing import Any

import pytest
from django.core.management import call_command
from django.core.management.base import CommandError
from django.utils import timezone

from apps.lifecycle.models import VmPowerState
from apps.orchestration import service
from apps.orchestration.models import (
    GuestInitrdBuild,
    GuestUpgradeJob,
    GuestUpgradeState,
    VmGuestComponents,
)
from apps.orchestration.services import guest_components, launch, power

from .factories import make_launch_record, make_service_client, make_vm

pytestmark = pytest.mark.django_db

# The real output of `scripts/guest/guest-initrd-build.sh` (see
# test_swap_vm_initrd.py, which consumes the same capture).
FIXTURE = Path(__file__).parent / "fixtures" / "guest_release.golden.measurement.json"
DOC = json.loads(FIXTURE.read_text())
BUCKET = DOC["s3_bucket"]
PREFIX = DOC["s3_key_prefix"]


def _doc(**overrides: Any) -> dict[str, Any]:
    doc = json.loads(FIXTURE.read_text())
    for dotted, value in overrides.items():
        target = doc
        *path, last = dotted.split("__")
        for part in path:
            target = target[part]
        if value is None:
            target.pop(last, None)
        else:
            target[last] = value
    return doc


def _register(doc: dict[str, Any] | None = None) -> GuestInitrdBuild:
    parsed = guest_components.parse_build(doc or _doc(), bucket=BUCKET, prefix=PREFIX)
    build, _ = guest_components.register_build(parsed)
    return build


# ── registration ─────────────────────────────────────────────────────


def test_a_real_build_document_registers_its_release_and_build() -> None:
    build = _register()
    assert build.release.version == DOC["guest_release"]["version"]
    assert build.release.security_epoch == DOC["guest_release"]["security_epoch"]
    assert build.initrd_sha256 == DOC["initrd_sha256"]
    assert build.base_initrd_sha256 == DOC["initrd_rebuild"]["source_initrd_sha256"]
    assert build.s3_key_prefix == PREFIX
    assert build.family == "initramfs-tools"
    # Again: a no-op.
    again, created = guest_components.register_build(
        guest_components.parse_build(_doc(), bucket=BUCKET, prefix=PREFIX)
    )
    assert (again.pk, created) == (build.pk, False)
    assert GuestInitrdBuild.objects.count() == 1


@pytest.mark.parametrize(
    ("overrides", "where", "needle"),
    [
        ({"guest_release": None}, {}, "not a guest release build"),
        ({"initrd_rebuild__method": "rebuild"}, {}, "append-guest-release"),
        ({"guest_release__family": "systemd-boot"}, {}, "initramfs family"),
        ({"guest_release__commit": "abc"}, {}, "40-hex commit"),
        ({"initrd_sha256": DOC["initrd_rebuild"]["source_initrd_sha256"]}, {}, "equals the base"),
        ({"disk_mode": "legacy_luks"}, {}, "golden"),
        ({"guest_release__security_epoch": -1}, {}, "non-negative integer"),
        ({}, {"prefix": "tenant/elsewhere"}, "not s3://"),
        ({}, {"bucket": "another-bucket"}, "not s3://"),
    ],
)
def test_a_malformed_or_misplaced_document_is_refused(overrides, where, needle) -> None:
    with pytest.raises(guest_components.BuildRejected, match=needle):
        guest_components.parse_build(
            _doc(**overrides),
            bucket=where.get("bucket", BUCKET),
            prefix=where.get("prefix", PREFIX),
        )


def test_a_release_re_registered_with_another_epoch_or_image_is_refused() -> None:
    _register()
    other = _doc(
        guest_release__security_epoch=DOC["guest_release"]["security_epoch"] + 1,
        initrd_sha256="c" * 64,
        s3_key_prefix=PREFIX + "-b",
    )
    with pytest.raises(guest_components.BuildRejected, match="is registered with"):
        guest_components.register_build(
            guest_components.parse_build(other, bucket=BUCKET, prefix=PREFIX + "-b")
        )


def test_the_same_initrd_at_another_prefix_is_refused() -> None:
    _register()
    moved = _doc(s3_key_prefix=PREFIX + "-copy")
    with pytest.raises(guest_components.BuildRejected, match="already registered"):
        guest_components.register_build(
            guest_components.parse_build(moved, bucket=BUCKET, prefix=PREFIX + "-copy")
        )


def test_an_initrd_only_rebuild_of_the_base_carries_its_own_build_of_a_release() -> None:
    """The base initrd is part of the base: a build of the same release on
    an initrd-only rebuild (same kernel and dm-verity base) registers, a
    second build on the same base initrd is still refused."""
    first = _register()

    def _on(base_initrd: str, initrd: str, prefix: str) -> Any:
        doc = _doc(
            initrd_rebuild__source_initrd_sha256=base_initrd,
            initrd_sha256=initrd,
            s3_key_prefix=prefix,
        )
        return guest_components.register_build(
            guest_components.parse_build(doc, bucket=BUCKET, prefix=prefix)
        )

    rebuilt, created = _on("4e" * 32, "c1" * 32, PREFIX + "-hardened")
    assert created
    assert (rebuilt.release_id, rebuilt.base_initrd_sha256) == (first.release_id, "4e" * 32)
    assert (rebuilt.kernel_sha256, rebuilt.verity_root_hash) == (
        first.kernel_sha256,
        first.verity_root_hash,
    )
    for base_initrd in (first.base_initrd_sha256, "4e" * 32):
        with pytest.raises(guest_components.BuildRejected, match="for this base"):
            _on(base_initrd, "c2" * 32, PREFIX + "-again")
    assert GuestInitrdBuild.objects.count() == 2


def test_the_command_reads_the_document_from_s3(monkeypatch) -> None:
    from apps.storage import s3

    reads: list[dict[str, Any]] = []

    class _S3:
        def get_object(self, **kw: Any) -> bytes:
            reads.append(kw)
            return FIXTURE.read_bytes()

    monkeypatch.setattr(s3, "get_s3_client", lambda: _S3())
    out = io.StringIO()
    call_command(
        "vali_guest_build_register",
        f"--from-s3-prefix={PREFIX}/",
        f"--s3-bucket={BUCKET}",
        stdout=out,
    )
    assert "registered: build=" in out.getvalue()
    assert reads[0]["bucket"] == BUCKET
    assert reads[0]["key"] == f"{PREFIX}/golden.measurement.json"
    with pytest.raises(CommandError, match="not s3://"):
        call_command(
            "vali_guest_build_register",
            "--from-s3-prefix=tenant/not-where-it-says",
            f"--s3-bucket={BUCKET}",
            stdout=io.StringIO(),
        )


# ── the floor ────────────────────────────────────────────────────────


def test_the_floor_only_moves_up_and_gates_by_epoch() -> None:
    build = _register()
    vm = make_vm("vm-floor")
    base_initrd = build.base_initrd_sha256
    assert guest_components.launch_epoch_refusal(vm.vm_id, base_initrd) == ""
    epoch = build.release.security_epoch
    assert guest_components.raise_required_epoch(vm, epoch) == epoch
    assert guest_components.raise_required_epoch(vm, 0) == epoch, "never lowered"
    # The base initrd is epoch 0: refused once the floor is above it.
    assert "guest-epoch-below-required" in guest_components.launch_epoch_refusal(
        vm.vm_id, base_initrd
    )
    # The build itself is at the floor: allowed.
    assert guest_components.launch_epoch_refusal(vm.vm_id, build.initrd_sha256) == ""


def test_a_golden_launch_below_the_floor_is_refused_before_anything_moves(monkeypatch) -> None:
    from apps.orchestration.tests.test_launch_service import (
        _fake_the_launch_choreography,
        _register_miner,
        _spec,
    )
    from apps.orchestration.tests.test_register_gate import _count_register, _vm

    build = _register()
    miner = _register_miner(1)
    _fake_the_launch_choreography(monkeypatch, dispatch_ok=True)
    calls = _count_register(monkeypatch)
    vm = _vm(host="miner-a")
    VmGuestComponents.objects.create(vm=vm, required_epoch=build.release.security_epoch)
    spec = _spec(
        userdata=b"#cloud-config\n",
        disk_mode="golden_verity_overlay",
        verity_root_hash_hex="e" * 64,
        initrd_sha256_hex=build.base_initrd_sha256,
    )
    out = launch.launch_on_miner(spec, miner, require_existing_disks=True)
    assert out.disposition == launch.TERMINAL
    assert out.emit["outcome"] == "guest-epoch-below-required"
    assert calls == [], "nothing registered"


def test_a_remint_of_a_boot_below_the_floor_is_refused() -> None:
    from apps.orchestration.effects import EffectError
    from apps.orchestration.services import migration_ticket

    build = _register()
    vm = make_vm("vm-remint")
    make_launch_record(vm, disk_mode="golden_verity_overlay")
    record = migration_ticket._latest_launch_record(vm.vm_id)
    spec = dict(record.spec_json)
    spec["initrd_sha256_hex"] = build.base_initrd_sha256
    record.spec_json = spec
    record.save(update_fields=["spec_json"])
    guest_components.raise_required_epoch(vm, build.release.security_epoch)
    with pytest.raises(EffectError, match="guest-epoch-below-required"):
        migration_ticket.resolve_ticket_inputs(vm, node_id=vm.host, generation=vm.generation)


# ── interlocks ───────────────────────────────────────────────────────


def _running_vm(vm_id: str) -> Any:
    vm = make_vm(vm_id, host="miner-a")
    vm.power_state = VmPowerState.RUNNING
    vm.save(update_fields=["power_state"])
    return vm


def _job(vm: Any, build: GuestInitrdBuild, state: str) -> GuestUpgradeJob:
    now = timezone.now()
    return GuestUpgradeJob.objects.create(
        job_id=f"gu-{vm.vm_id}",
        vm=vm,
        target=build,
        previous_prefix="tenant/base",
        previous_initrd_sha256=build.base_initrd_sha256,
        node_id=vm.host,
        prior_power_state=vm.power_state,
        state=state,
        not_before=now,
        phase_started_at=now,
        decided_by=make_service_client(),
        **({"finished_at": now} if state == GuestUpgradeState.DONE else {}),
    )


@pytest.mark.parametrize(
    ("state", "holds"),
    [
        (GuestUpgradeState.PENDING, False),
        (GuestUpgradeState.STOPPING, True),
        (GuestUpgradeState.LAUNCHING, True),
        (GuestUpgradeState.VERIFYING, True),
        (GuestUpgradeState.SOAKING, True),
        (GuestUpgradeState.ROLLING_BACK, True),
        (GuestUpgradeState.DONE, False),
    ],
)
def test_an_upgrade_holds_the_vm_only_past_pending(state, holds) -> None:
    build = _register()
    vm = make_vm("vm-hold", host="miner-a")
    _job(vm, build, state)
    assert service._has_active_job(vm) is holds
    assert service._has_active_job(vm, ignore_guest_upgrade=True) is False


def test_the_power_api_refuses_everyone_but_the_holding_job() -> None:
    build = _register()
    vm = _running_vm("vm-pwr")
    job = _job(vm, build, GuestUpgradeState.STOPPING)
    with pytest.raises(power.PowerOpRefused) as refused:
        power._claim(vm, VmPowerState.STOPPING)
    assert refused.value.reason == "guest-upgrade-in-flight"
    with pytest.raises(power.PowerOpRefused) as refused:
        power._claim(vm, VmPowerState.STOPPING, by_guest_upgrade="gu-someone-else")
    assert refused.value.reason == "guest-upgrade-in-flight"
    claimed = power._claim(vm, VmPowerState.STOPPING, by_guest_upgrade=job.job_id)
    assert claimed.power_state == VmPowerState.STOPPING


def test_a_job_id_that_holds_nothing_does_not_open_the_power_api() -> None:
    vm = _running_vm("vm-pwr2")
    with pytest.raises(power.PowerOpRefused) as refused:
        power._claim(vm, VmPowerState.STOPPING, by_guest_upgrade="gu-nobody")
    assert refused.value.reason == "guest-upgrade-not-holding"


def test_a_backup_does_not_start_on_a_vm_an_upgrade_holds(monkeypatch) -> None:
    from apps.backup import service as backup_service
    from apps.backup.models import BackupInterval, BackupPolicy, BackupRun

    build = _register()
    vm = _running_vm("vm-bk")
    policy = BackupPolicy.objects.create(
        vm=vm, enabled=True, interval_s=BackupInterval.choices[0][0]
    )
    monkeypatch.setattr(backup_service, "plan_parts", lambda size: (1 << 26, 1))
    monkeypatch.setattr(backup_service, "source_disk_bytes", lambda vm: 1 << 26)
    monkeypatch.setattr(backup_service, "_bucket", lambda: "b")
    # The job takes the VM between the tick's check and the run's insert.
    _job(vm, build, GuestUpgradeState.STOPPING)
    assert backup_service._start_run(policy, "full", timezone.now()) is False
    assert not BackupRun.objects.filter(vm=vm).exists()


def test_lowering_the_floor_is_audited_and_refused_while_an_upgrade_holds() -> None:
    build = _register()
    vm = _running_vm("vm-lower")
    guest_components.raise_required_epoch(vm, 3, by="gu-1", reason="upgrade")
    job = _job(vm, build, GuestUpgradeState.VERIFYING)
    with pytest.raises(CommandError, match="in flight"):
        call_command(
            "vali_guest_epoch_lower",
            "--vm-id=vm-lower",
            "--to=0",
            "--operator=alice",
            "--reason=blocked",
            "--apply",
            stdout=io.StringIO(),
        )
    GuestUpgradeJob.objects.filter(pk=job.pk).update(
        state=GuestUpgradeState.UPGRADE_BLOCKED, finished_at=timezone.now()
    )
    out = io.StringIO()
    call_command(
        "vali_guest_epoch_lower",
        "--vm-id=vm-lower",
        "--to=0",
        "--operator=alice",
        "--reason=blocked",
        stdout=out,
    )
    assert "dry-run" in out.getvalue()
    assert guest_components.required_epoch("vm-lower") == 3
    call_command(
        "vali_guest_epoch_lower",
        "--vm-id=vm-lower",
        "--to=0",
        "--operator=alice",
        "--reason=blocked",
        "--apply",
        stdout=io.StringIO(),
    )
    row = VmGuestComponents.objects.get(vm=vm)
    assert row.required_epoch == 0
    assert [(h["from"], h["to"], h["by"]) for h in row.history] == [
        (0, 3, "gu-1"),
        (3, 0, "lowered-by:alice"),
    ]
    with pytest.raises(CommandError, match="not lower"):
        call_command(
            "vali_guest_epoch_lower",
            "--vm-id=vm-lower",
            "--to=0",
            "--operator=alice",
            "--reason=again",
            "--apply",
            stdout=io.StringIO(),
        )


def test_lowering_is_refused_while_an_upgrade_waits_too() -> None:
    build = _register()
    vm = _running_vm("vm-lower-pending")
    guest_components.raise_required_epoch(vm, 2, by="gu-x", reason="upgrade")
    _job(vm, build, GuestUpgradeState.PENDING)
    with pytest.raises(ValueError, match="in flight"):
        guest_components.lower_required_epoch(vm, 0, operator="alice", reason="x")


# ── registration is immutable ────────────────────────────────────────


def test_a_release_member_is_immutable_per_family() -> None:
    _register()
    other = _doc(
        initrd_sha256="c" * 64,
        s3_key_prefix=PREFIX + "-b",
        guest_release__release_cpio_sha256="d" * 64,
        kernel_sha256="e" * 64,
    )
    with pytest.raises(guest_components.BuildRejected, match="another initramfs-tools member"):
        guest_components.register_build(
            guest_components.parse_build(other, bucket=BUCKET, prefix=PREFIX + "-b")
        )


def test_epochs_never_decrease_with_the_version() -> None:
    _register()  # v1, epoch 1
    later = _doc(
        initrd_sha256="c" * 64,
        s3_key_prefix=PREFIX + "-v2",
        guest_release__version=2,
        guest_release__security_epoch=0,
    )
    with pytest.raises(guest_components.BuildRejected, match="epoch order"):
        guest_components.register_build(
            guest_components.parse_build(later, bucket=BUCKET, prefix=PREFIX + "-v2")
        )


def test_a_build_re_registered_with_another_base_is_refused() -> None:
    _register()
    forged = _doc(initrd_rebuild__source_bake_id="another-bake")
    with pytest.raises(guest_components.BuildRejected, match="source_bake_id"):
        guest_components.register_build(
            guest_components.parse_build(forged, bucket=BUCKET, prefix=PREFIX)
        )


# ── the floor at the register, under the row lock ────────────────────


def test_a_floor_raised_while_the_launch_mints_is_seen_at_the_register(monkeypatch) -> None:
    from apps.orchestration.services import ticket_mint
    from apps.orchestration.tests.test_launch_service import (
        _fake_the_launch_choreography,
        _register_miner,
        _spec,
    )
    from apps.orchestration.tests.test_register_gate import _count_register, _vm

    build = _register()
    miner = _register_miner(1)
    _fake_the_launch_choreography(monkeypatch, dispatch_ok=True)
    calls = _count_register(monkeypatch)
    vm = _vm(host="miner-a")

    def _mint(*a, **k):
        # An upgrade decided while this launch was minting.
        guest_components.raise_required_epoch(vm, build.release.security_epoch)
        return b"cose"

    monkeypatch.setattr(ticket_mint, "mint", _mint)
    monkeypatch.setattr(
        "apps.orchestration.services.migration_ticket.persist_intake", lambda *a, **k: None
    )
    spec = _spec(
        userdata=b"#cloud-config\n# {{NETBIRD_SETUP_KEY}}\n",
        disk_mode="golden_verity_overlay",
        verity_root_hash_hex="e" * 64,
        rootfs_img_sha256_hex="f" * 64,
        rootfs_verity_sha256_hex="f" * 64,
        initrd_sha256_hex=build.base_initrd_sha256,
    )
    out = launch.launch_on_miner(spec, miner, require_existing_disks=True)
    assert out.disposition == launch.TERMINAL
    assert out.emit["outcome"] == "guest-epoch-below-required", out.emit
    assert calls == [], "the KBS was never asked"


def test_a_register_naming_no_initrd_is_refused_once_a_vm_has_a_floor() -> None:
    from apps.orchestration.services import register_gate

    vm = make_vm("vm-noinitrd", host="miner-a")
    assert register_gate.register_refusal(vm, generation=vm.generation, miner_id="miner-a") is None
    guest_components.raise_required_epoch(vm, 1)
    assert "no initrd" in register_gate.register_refusal(
        vm, generation=vm.generation, miner_id="miner-a"
    )


def test_a_vm_born_on_a_release_starts_with_its_epoch_as_floor() -> None:
    """Only a NEW Vm row: a relaunch, a §25 move or a manual swap of an
    existing VM never moves the floor here."""
    from types import SimpleNamespace

    from apps.lifecycle.models import Vm
    from apps.orchestration.services import launch

    build = _register()
    epoch = build.release.security_epoch

    def _spec(vm_id: str, initrd: str) -> SimpleNamespace:
        return SimpleNamespace(
            vm_id=vm_id,
            lease_id=f"lease-{vm_id}",
            tenant_id="t",
            max_price_per_unit=None,
            initrd_sha256_hex=initrd,
            cmdline="ro",
            enable_netbird=False,
            userdata=b"",
            key_mode="hippius",
        )

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(launch, "_spec_binding", lambda spec: None)
        mp.setattr(launch, "_refuse_measured_cmdline_before_pin", lambda spec, b: None)
        launch._ensure_vm_row(_spec("vm-born", build.initrd_sha256))
        assert guest_components.required_epoch("vm-born") == epoch
        launch._ensure_vm_row(_spec("vm-bare", build.base_initrd_sha256))
        assert guest_components.required_epoch("vm-bare") == 0
        # An existing row (a relaunch) is left alone.
        launch._ensure_vm_row(_spec("vm-bare", build.initrd_sha256))
        assert guest_components.required_epoch("vm-bare") == 0
    assert Vm.objects.filter(vm_id__in=["vm-born", "vm-bare"]).count() == 2


# ── one ticket per VM per second ─────────────────────────────────────


def test_two_tickets_of_one_vm_never_share_an_issue_second(monkeypatch) -> None:
    from apps.orchestration.services import ticket_mint

    clock = {"t": 1_700_000_000.2}
    monkeypatch.setattr("time.time", lambda: clock["t"])

    def _sleep(s: float) -> None:
        clock["t"] += s

    monkeypatch.setattr("time.sleep", _sleep)
    first = ticket_mint.reserve_issue_time("vm-clock")
    second = ticket_mint.reserve_issue_time("vm-clock")
    other = ticket_mint.reserve_issue_time("vm-other")
    assert first == 1_700_000_000
    assert second == first + 1, "waited for the next second"
    assert other == int(clock["t"]), "per VM"
    assert second <= clock["t"], "never a future second"


def test_the_launch_intake_refuses_a_vm_another_operation_holds() -> None:
    from apps.orchestration import launch_jobs

    build = _register()
    vm = _running_vm("vm-intake")
    launch_jobs._refuse_held(vm)  # nothing holds it
    _job(vm, build, GuestUpgradeState.LAUNCHING)
    with pytest.raises(launch_jobs.LaunchIntentError, match="held by another operation"):
        launch_jobs._refuse_held(vm)


def test_the_ticket_clock_starts_after_the_tickets_a_vm_already_holds(monkeypatch) -> None:
    from apps.orchestration.services import ticket_mint
    from apps.orders.models import OrderTicketIntake

    clock = {"t": 1_700_000_000.5}
    monkeypatch.setattr("time.time", lambda: clock["t"])
    monkeypatch.setattr("time.sleep", lambda s: clock.__setitem__("t", clock["t"] + s))
    OrderTicketIntake.objects.create(
        ticket_id="tk-old",
        vm_id="vm-seed",
        tenant_id="t",
        user_id="u",
        lease_id="l",
        vm_generation=1,
        issue_time=1_700_000_000,
        expiry=1_700_086_400,
        node_id="n",
        platform_id="p",
        resource_class="small",
        kid_hex="00",
        cose_blob=b"x",
        received_from="test",
    )
    assert ticket_mint.reserve_issue_time("vm-seed") == 1_700_000_001


def test_a_build_re_registered_with_another_document_is_refused() -> None:
    _register()
    forged = _doc(extra_field="tampered")
    with pytest.raises(guest_components.BuildRejected, match="measurement"):
        guest_components.register_build(
            guest_components.parse_build(forged, bucket=BUCKET, prefix=PREFIX)
        )


def test_a_failed_seed_write_leaves_no_seed_file(monkeypatch, settings, tmp_path) -> None:
    import os as _os

    from apps.orchestration.effects import EffectError
    from apps.orchestration.services import ticket_mint

    settings.VALI_ORDER_TICKET_MINT_BIN = "/bin/true"
    monkeypatch.setattr(ticket_mint, "_bin_path", lambda: "/bin/true")
    monkeypatch.setattr(ticket_mint, "_resolve_l1_seed", lambda: "ab" * 32)
    monkeypatch.setattr(ticket_mint.os.path, "isdir", lambda p: False)
    monkeypatch.setattr(ticket_mint.tempfile, "tempdir", str(tmp_path))
    real_fdopen = _os.fdopen

    def failing_fdopen(fd, *a, **k):
        f = real_fdopen(fd, *a, **k)
        f.close()
        raise OSError("disk full")

    monkeypatch.setattr(ticket_mint.os, "fdopen", failing_fdopen)
    args = dict(
        kid="k",
        ticket_id="t",
        tenant_id="t",
        user_id="u",
        vm_id="vm-seedleak",
        lease_id="l",
        node_id="n",
        platform_id="p",
        allowed_measurement_hex="ab" * 48,
        userdata_vault_path="p/u",
        userdata_vault_version=1,
        luks_vault_path="p/l",
        luks_vault_version=1,
        allowed_userdata_digest_hex="cd" * 32,
        flavor="small",
    )
    with pytest.raises((OSError, EffectError)):
        ticket_mint.mint(ticket_mint.MintArgs(**args))
    assert list(tmp_path.iterdir()) == [], "no seed nor output file left behind"


def test_a_release_records_its_health_mask_and_keeps_it() -> None:
    """A document without `health_mask` (written before the leg) is a
    release without health checks; the mask is immutable once recorded."""
    assert _register().release.health_mask == 0
    with pytest.raises(guest_components.BuildRejected, match="health_mask"):
        guest_components.parse_build(
            _doc(guest_release__health_mask=2**32), bucket=BUCKET, prefix=PREFIX
        )
    other = _doc(
        guest_release__health_mask=15,
        initrd_sha256="c" * 64,
        s3_key_prefix=PREFIX + "-b",
    )
    with pytest.raises(guest_components.BuildRejected, match="health_mask 0"):
        guest_components.register_build(
            guest_components.parse_build(other, bucket=BUCKET, prefix=PREFIX + "-b")
        )


def test_a_release_with_health_checks_registers_them() -> None:
    doc = _doc(
        guest_release__version=5,
        guest_release__health_mask=15,
    )
    assert _register(doc).release.health_mask == 15
