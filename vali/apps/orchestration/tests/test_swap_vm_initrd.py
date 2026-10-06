"""`vali_swap_vm_initrd` moves a golden VM's launch record onto an
initrd-only rebuild, and every path that boots the VM afterwards boots the
right initrd: a relaunch (reboot-recovery / power start) the NEW one, a §25
destination the one the RUNNING guest measured."""

from __future__ import annotations

import io
import json
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from django.core.management import call_command
from django.core.management.base import CommandError
from django.utils import timezone

from apps.lifecycle.models import Vm, VmPowerState, VmState
from apps.orchestration import effects, order_dispatch, service
from apps.orchestration.models import LaunchJob, LaunchJobState, MigrationState, RebootRecovery
from apps.orchestration.services import launch, launch_record, migration_ticket

from .factories import make_migration_job, make_service_client, make_vm

pytestmark = pytest.mark.django_db

# The REAL output shape of `scripts/tenant-initrd-rebuild.sh`, captured from
# its fixture test (`scripts/dev/tenant-initrd-rebuild-test.sh`, the
# `out1/golden.measurement.json` it produces). Two edits, neither read by the
# command: `source_location` is a realistic value, and the per-input shas in
# `initrd_rebuild.inputs_sha256` are zeroed — gitleaks' generic-api-key rule
# reads `"hippius-luks-keyscript": <64 hex>` as a leaked key. Every sha below
# is read from the fixture, so a change of shape on the script side breaks
# these tests instead of drifting.
FIXTURE = Path(__file__).parent / "fixtures" / "initrd_rebuild.golden.measurement.json"
_REAL = json.loads(FIXTURE.read_text())

KERNEL = _REAL["kernel_sha256"]
ROOTFS_IMG = _REAL["rootfs_img_sha256"]
ROOTFS_VERITY = _REAL["rootfs_verity_sha256"]
VERITY_ROOT = _REAL["verity_root_hash"]
OLD_INITRD = _REAL["initrd_rebuild"]["source_initrd_sha256"]
NEW_INITRD = _REAL["initrd_sha256"]
SOURCE_BAKE = _REAL["initrd_rebuild"]["source_bake_id"]
OLD_PREFIX = "golden/ubuntu-24.04/abc123"
NEW_PREFIX = "golden/ubuntu-24.04/abc123-initrd-9f00"
BUCKET = "hippius-compute-images"
MEAS_OLD = "a" * 96
MEAS_NEW = "b" * 96

_SPEC = {
    "tenant_id": "tenant-1",
    "user_id": "user-1",
    "vm_id": "vm-g",
    "lease_id": "lease-vm-g",
    "s3_bucket": BUCKET,
    "s3_key_prefix": OLD_PREFIX,
    "luks_disk_sha256_hex": "",
    "kernel_sha256_hex": KERNEL,
    "initrd_sha256_hex": OLD_INITRD,
    "luks_header_sha256_hex": "",
    "flavor": "small",
    "cmdline": "console=ttyS0",
    "disk_mode": "golden_verity_overlay",
    "verity_root_hash_hex": VERITY_ROOT,
    "rootfs_img_sha256_hex": ROOTFS_IMG,
    "rootfs_verity_sha256_hex": ROOTFS_VERITY,
    "bake_id": SOURCE_BAKE,
    "auto_pin_allowlist": True,
}


def _golden_vm(vm_id: str = "vm-g", **spec_overrides: Any) -> tuple[Vm, LaunchJob]:
    vm = make_vm(vm_id)
    now = timezone.now()
    job = LaunchJob.objects.create(
        job_id=f"job-{vm_id}",
        vm_id=vm_id,
        tenant_id="tenant-1",
        flavor="small",
        spec_json={**_SPEC, "vm_id": vm_id, "lease_id": f"lease-{vm_id}", **spec_overrides},
        userdata_vault_path=f"x/{vm_id}/userdata",
        userdata_vault_version=1,
        kek_vault_path=f"x/{vm_id}/luks-kek",
        state=LaunchJobState.SUCCEEDED.value,
        phase_started_at=now,
        finished_at=now,
        result_json={
            "emit": {"measurement_hex": MEAS_OLD, "measured_cmdline": "console=ttyS0 n=1"}
        },
        decided_by=make_service_client(),
    )
    return vm, job


_NESTED = ("source_initrd_sha256", "source_bake_id")


def _rebuild(tmp_path: Path, **overrides: Any) -> list[str]:
    """Command args for the real rebuild measurement with `overrides`
    applied (`None` deletes a key). `source_*` go where the script writes
    them, under `initrd_rebuild`; `s3_key_prefix` is the `--s3-key-prefix`
    the operator passes (the script's JSON never names one)."""
    doc = json.loads(FIXTURE.read_text())
    prefix = overrides.pop("s3_key_prefix", NEW_PREFIX)
    for key, value in overrides.items():
        target = doc["initrd_rebuild"] if key in _NESTED else doc
        if value is None:
            target.pop(key, None)
        else:
            target[key] = value
    path = tmp_path / "golden.measurement.json"
    path.write_text(json.dumps(doc))
    args = [f"--measurement-json={path}"]
    if prefix is not None:
        args.append(f"--s3-key-prefix={prefix}")
    return args


def _run(rebuild: list[str], *vm_ids: str, apply: bool = False) -> str:
    out = io.StringIO()
    args = [f"--vm-id={v}" for v in vm_ids]
    args += [*rebuild, "--operator=alice", "--reason=m0-guard"]
    if apply:
        args.append("--apply")
    call_command("vali_swap_vm_initrd", *args, stdout=out)
    return out.getvalue()


def _job(vm_id: str = "vm-g") -> LaunchJob:
    return LaunchJob.objects.get(vm_id=vm_id, state=LaunchJobState.SUCCEEDED.value)


def _record(job: LaunchJob) -> tuple[str, str]:
    return job.spec_json["s3_key_prefix"], job.spec_json["initrd_sha256_hex"]


# ── dry-run / apply ──────────────────────────────────────────────────


def test_dry_run_is_the_default_and_writes_nothing(tmp_path: Path) -> None:
    _, job = _golden_vm()
    before = (job.spec_json, job.result_json)
    out = _run(_rebuild(tmp_path), "vm-g")
    assert "vm=vm-g outcome=swap" in out
    assert "mode=dry-run swapped=0 problems=0" in out
    job.refresh_from_db()
    assert (job.spec_json, job.result_json) == before


def test_apply_swaps_the_record_and_audits_it(tmp_path: Path) -> None:
    _golden_vm()
    out = _run(_rebuild(tmp_path), "vm-g", apply=True)
    assert "vm=vm-g outcome=swapped" in out
    assert "power stop + start" in out
    job = _job()
    assert _record(job) == (NEW_PREFIX, NEW_INITRD)
    # Nothing else in the spec moves: kernel, base, verity root, bake id.
    assert {
        k: v for k, v in job.spec_json.items() if k not in ("s3_key_prefix", "initrd_sha256_hex")
    } == {k: v for k, v in _SPEC.items() if k not in ("s3_key_prefix", "initrd_sha256_hex")}
    emit = job.result_json["emit"]
    # The running boot is unchanged — measurement, cmdline, and the
    # artefacts it measured are all still recorded.
    assert emit["measurement_hex"] == MEAS_OLD
    assert emit[launch_record.BOOTED_ARTIFACTS_KEY] == {
        "s3_key_prefix": OLD_PREFIX,
        "initrd_sha256_hex": OLD_INITRD,
    }
    (entry,) = emit["superseded"]
    assert entry["reason"] == "initrd-swap:m0-guard"
    assert entry["operator"] == "alice"
    assert entry["previous"] == {
        "spec.s3_key_prefix": OLD_PREFIX,
        "spec.initrd_sha256_hex": OLD_INITRD,
    }
    assert entry["new"] == {"spec.s3_key_prefix": NEW_PREFIX, "spec.initrd_sha256_hex": NEW_INITRD}
    assert entry["evidence"]["rebuild_measurement"] == _REAL


def test_a_second_apply_is_a_no_op(tmp_path: Path) -> None:
    _golden_vm()
    path = _rebuild(tmp_path)
    _run(path, "vm-g", apply=True)
    out = _run(path, "vm-g", apply=True)
    assert "outcome=already-swapped" in out
    assert len(_job().result_json["emit"]["superseded"]) == 1


# ── refusals ─────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("rebuild_overrides", "spec_overrides", "outcome"),
    [
        ({"kernel_sha256": "ff" * 32}, {}, "kernel_sha256-mismatch"),
        ({"rootfs_img_sha256": "ff" * 32}, {}, "rootfs_img_sha256-mismatch"),
        ({"rootfs_verity_sha256": "ff" * 32}, {}, "rootfs_verity_sha256-mismatch"),
        ({"verity_root_hash": "ff" * 32}, {}, "verity_root_hash-mismatch"),
        ({"source_initrd_sha256": "ff" * 32}, {}, "source-initrd-mismatch"),
        ({"s3_bucket": "other-bucket"}, {}, "bucket-mismatch"),
        ({"source_bake_id": "bake-other"}, {}, "source-bake-mismatch"),
        ({"s3_key_prefix": OLD_PREFIX + "/"}, {}, "prefix-unchanged"),
        ({}, {"disk_mode": "legacy_luks"}, "not-golden"),
        ({}, {"measurement_hex": MEAS_OLD}, "measurement-pinned"),
        ({}, {"auto_pin_allowlist": False}, "auto-pin-off"),
    ],
)
def test_a_mismatched_rebuild_is_refused_and_nothing_written(
    tmp_path: Path, rebuild_overrides: dict, spec_overrides: dict, outcome: str
) -> None:
    _, job = _golden_vm(**spec_overrides)
    before = (job.spec_json, job.result_json)
    out = _capture(_rebuild(tmp_path, **rebuild_overrides))
    assert f"outcome={outcome} " in out
    job.refresh_from_db()
    assert (job.spec_json, job.result_json) == before


def _capture(rebuild: list[str]) -> str:
    out = io.StringIO()
    with pytest.raises(CommandError):
        call_command(
            "vali_swap_vm_initrd",
            "--vm-id=vm-g",
            *rebuild,
            "--operator=alice",
            "--reason=r",
            "--apply",
            stdout=out,
        )
    return out.getvalue()


def _vm_in_flight(kind: str, vm: Vm) -> None:
    now = timezone.now()
    if kind == "not-active":
        Vm.objects.filter(pk=vm.pk).update(state=VmState.DECOMMISSIONING)
    elif kind == "migrating":
        make_migration_job(vm, state=MigrationState.DRAINING.value)
    elif kind == "stopping":
        Vm.objects.filter(pk=vm.pk).update(power_state=VmPowerState.STOPPING, power_state_at=now)
    elif kind == "starting":
        Vm.objects.filter(pk=vm.pk).update(power_state=VmPowerState.STARTING, power_state_at=now)
    elif kind == "relaunching":
        RebootRecovery.objects.create(
            vm=vm, last_outcome=service.RELAUNCH_IN_FLIGHT, last_relaunch_at=now
        )
    elif kind == "launch-job":
        base = LaunchJob.objects.get(vm_id=vm.vm_id)
        LaunchJob.objects.create(
            job_id="job-running",
            vm_id=vm.vm_id,
            tenant_id="tenant-1",
            flavor="small",
            spec_json=dict(base.spec_json),
            userdata_vault_path=base.userdata_vault_path,
            userdata_vault_version=1,
            kek_vault_path=base.kek_vault_path,
            state=LaunchJobState.RUNNING.value,
            phase_started_at=now,
            decided_by=base.decided_by,
        )


@pytest.mark.parametrize(
    ("kind", "outcome"),
    [
        ("not-active", "vm-not-active:decommissioning"),
        ("migrating", "migration-in-flight"),
        ("stopping", "power-op-in-flight:stopping"),
        ("starting", "power-op-in-flight:starting"),
        ("relaunching", "recovery-relaunch-in-flight"),
        ("launch-job", "launch-job-in-flight"),
    ],
)
def test_a_vm_mid_flight_is_refused(tmp_path: Path, kind: str, outcome: str) -> None:
    vm, job = _golden_vm()
    _vm_in_flight(kind, vm)
    out = _capture(_rebuild(tmp_path))
    assert f"outcome={outcome} " in out
    job.refresh_from_db()
    assert _record(job) == (OLD_PREFIX, OLD_INITRD)


def test_a_stale_power_marker_does_not_block(tmp_path: Path) -> None:
    vm, _ = _golden_vm()
    Vm.objects.filter(pk=vm.pk).update(
        power_state=VmPowerState.STARTING,
        power_state_at=timezone.now() - timedelta(hours=1),
    )
    assert "outcome=swapped" in _run(_rebuild(tmp_path), "vm-g", apply=True)


def test_one_refused_vm_does_not_stop_the_others(tmp_path: Path) -> None:
    _golden_vm("vm-a")
    _golden_vm("vm-b", initrd_sha256_hex="ee" * 32)
    out = _capture_many(_rebuild(tmp_path), "vm-a", "vm-b", "vm-missing")
    assert "vm=vm-a outcome=swapped" in out
    assert "vm=vm-b outcome=source-initrd-mismatch" in out
    assert "vm=vm-missing outcome=no-such-vm" in out
    assert _record(_job("vm-a")) == (NEW_PREFIX, NEW_INITRD)
    assert _record(_job("vm-b")) == (OLD_PREFIX, "ee" * 32)


def _capture_many(rebuild: list[str], *vm_ids: str) -> str:
    out = io.StringIO()
    with pytest.raises(CommandError, match="2 VM"):
        call_command(
            "vali_swap_vm_initrd",
            *[f"--vm-id={v}" for v in vm_ids],
            *rebuild,
            "--operator=alice",
            "--reason=r",
            "--apply",
            stdout=out,
        )
    return out.getvalue()


@pytest.mark.parametrize(
    "overrides",
    [
        {"initrd_sha256": None},
        {"kernel_sha256": "not-hex"},
        {"initrd_sha256": OLD_INITRD},
        {"source_initrd_sha256": None},
        {"initrd_rebuild": None},
        {"initrd_rebuild": "not-an-object"},
        {"s3_key_prefix": None},
    ],
)
def test_a_malformed_measurement_json_is_refused_before_any_vm(
    tmp_path: Path, overrides: dict
) -> None:
    _, job = _golden_vm()
    with pytest.raises(CommandError):
        _run(_rebuild(tmp_path, **overrides), "vm-g", apply=True)
    job.refresh_from_db()
    assert _record(job) == (OLD_PREFIX, OLD_INITRD)


def test_the_prefix_must_be_passed_when_the_json_names_none(tmp_path: Path) -> None:
    _golden_vm()
    with pytest.raises(CommandError, match="--s3-key-prefix is required"):
        _run(_rebuild(tmp_path, s3_key_prefix=None), "vm-g")


@pytest.mark.parametrize("name", ["source_initrd_sha256", "source_bake_id"])
def test_a_top_level_provenance_copy_must_agree_with_the_nested_one(
    tmp_path: Path, name: str
) -> None:
    """The script nests provenance under `initrd_rebuild`; a top-level
    copy that says something else is refused, never silently preferred."""
    _, job = _golden_vm()
    other = "ee" * 32 if name == "source_initrd_sha256" else "bake-other"
    args = _rebuild(tmp_path)
    path = Path(args[0].split("=", 1)[1])
    doc = json.loads(path.read_text())
    doc[name] = other
    path.write_text(json.dumps(doc))
    with pytest.raises(CommandError, match=f"top-level {name} disagrees"):
        _run(args, "vm-g", apply=True)
    # An agreeing copy is fine.
    doc[name] = doc["initrd_rebuild"][name]
    path.write_text(json.dumps(doc))
    assert "outcome=swapped" in _run(args, "vm-g", apply=True)


def test_a_rebuild_without_a_source_bake_id_still_swaps(tmp_path: Path) -> None:
    _, job = _golden_vm()
    assert "outcome=swapped" in _run(_rebuild(tmp_path, source_bake_id=None), "vm-g", apply=True)
    job.refresh_from_db()
    assert _record(job) == (NEW_PREFIX, NEW_INITRD)


# ── the CAS ──────────────────────────────────────────────────────────


def test_the_write_is_compare_and_set_against_what_was_read() -> None:
    _, job = _golden_vm()
    # Someone else moved the record between the read and the write.
    LaunchJob.objects.filter(pk=job.pk).update(
        spec_json={**job.spec_json, "initrd_sha256_hex": "ee" * 32}
    )
    with pytest.raises(ValueError, match="changed since it was read"):
        launch_record.swap_initrd(
            "vm-g",
            new_prefix=NEW_PREFIX,
            new_initrd_sha256_hex=NEW_INITRD,
            expected_job_id=job.job_id,
            expected_prefix=OLD_PREFIX,
            expected_initrd_sha256_hex=OLD_INITRD,
            expected_marker=None,
            reason="r",
            operator="o",
            evidence={},
        )
    job.refresh_from_db()
    assert job.spec_json["initrd_sha256_hex"] == "ee" * 32
    assert "superseded" not in job.result_json["emit"]


def test_the_write_refuses_a_record_that_was_not_the_one_checked() -> None:
    """Same prefix + initrd, but a different (unchecked) record is now the
    current one: the CAS is on the record too, not just the two values."""
    _, job = _golden_vm()
    newer = LaunchJob.objects.create(
        job_id="job-newer",
        vm_id="vm-g",
        tenant_id="tenant-1",
        flavor="small",
        spec_json={**job.spec_json, "disk_mode": "legacy_luks"},
        userdata_vault_path=job.userdata_vault_path,
        userdata_vault_version=1,
        kek_vault_path=job.kek_vault_path,
        state=LaunchJobState.SUCCEEDED.value,
        phase_started_at=timezone.now(),
        finished_at=timezone.now() + timedelta(seconds=1),
        decided_by=job.decided_by,
    )
    with pytest.raises(ValueError, match="not the 'job-vm-g' that was checked"):
        launch_record.swap_initrd(
            "vm-g",
            new_prefix=NEW_PREFIX,
            new_initrd_sha256_hex=NEW_INITRD,
            expected_job_id="job-vm-g",
            expected_prefix=OLD_PREFIX,
            expected_initrd_sha256_hex=OLD_INITRD,
            expected_marker=None,
            reason="r",
            operator="o",
            evidence={},
        )
    newer.refresh_from_db()
    assert newer.spec_json["initrd_sha256_hex"] == OLD_INITRD


def test_the_command_reports_a_cas_conflict(tmp_path: Path, monkeypatch) -> None:
    _golden_vm()
    real = launch_record.swap_initrd

    def racing(vm_id: str, **kw: Any) -> bool:
        job = _job(vm_id)
        LaunchJob.objects.filter(pk=job.pk).update(
            spec_json={**job.spec_json, "s3_key_prefix": "someone/else"}
        )
        return real(vm_id, **kw)

    monkeypatch.setattr(launch_record, "swap_initrd", racing)
    out = _capture(_rebuild(tmp_path))
    assert "outcome=write-refused:" in out
    assert _record(_job()) == ("someone/else", OLD_INITRD)


# ── what boots afterwards ────────────────────────────────────────────


def _relaunch(
    monkeypatch: pytest.MonkeyPatch,
    vm: Vm,
    *,
    disposition: str = launch.ACCEPTED,
    emit: dict[str, Any] | None = None,
) -> list[Any]:
    """Run the REAL reboot-recovery relaunch (what power start calls) with
    the miner call captured."""
    from apps.miners.models import MinerIdentity
    from apps.orchestration.services import vault_kv as vk

    from .test_reboot_recovery import _make_alive_miner

    miner = MinerIdentity.objects.filter(miner_id="node-src").first() or _make_alive_miner()
    handed: list[Any] = []

    def fake_launch_on_miner(spec: Any, m: Any, **_kw: Any) -> SimpleNamespace:
        handed.append(spec)
        return SimpleNamespace(
            disposition=disposition,
            emit=emit or {"measurement_hex": MEAS_NEW, "measured_cmdline": "console=ttyS0 n=2"},
        )

    monkeypatch.setattr(vk, "get_kv", lambda mount, path, version=None: b"user-data")
    monkeypatch.setattr(launch, "launch_on_miner", fake_launch_on_miner)
    monkeypatch.setattr(service, "rebind_placement_to_host", lambda *a, **k: None)
    accepted = service._reboot_recovery_relaunch(vm, miner.miner_id)
    assert accepted is (disposition == launch.ACCEPTED)
    return handed


def test_a_relaunch_after_the_swap_boots_the_new_initrd(tmp_path: Path, monkeypatch) -> None:
    vm, _ = _golden_vm()
    _run(_rebuild(tmp_path), "vm-g", apply=True)

    (spec,) = _relaunch(monkeypatch, vm)

    assert (spec.s3_key_prefix, spec.initrd_sha256_hex) == (NEW_PREFIX, NEW_INITRD)
    # …and fetches it from the rebuild's prefix, keyed by the new sha.
    artifacts = launch._select_preflight_artifacts(spec)
    assert (artifacts.initrd.key, artifacts.initrd.sha256_hex) == (
        f"{NEW_PREFIX}/tenant.initrd.img",
        NEW_INITRD,
    )
    assert (spec.kernel_sha256_hex, spec.verity_root_hash_hex) == (KERNEL, VERITY_ROOT)
    # The new boot is recorded, and the swap marker is gone: the running
    # guest now IS on the spec's initrd.
    job = _job()
    assert job.result_json["emit"]["measurement_hex"] == MEAS_NEW
    assert launch_record.BOOTED_ARTIFACTS_KEY not in job.result_json["emit"]
    assert launch_record.booted_artifacts(job) == (NEW_PREFIX, NEW_INITRD)


def test_a_relaunch_that_raced_the_swap_keeps_the_old_initrd_recorded() -> None:
    """A relaunch that read the spec BEFORE the swap booted the old initrd:
    recording it must not claim the new one is running."""
    _, job = _golden_vm()
    launch_record.swap_initrd(
        "vm-g",
        new_prefix=NEW_PREFIX,
        new_initrd_sha256_hex=NEW_INITRD,
        expected_job_id="job-vm-g",
        expected_prefix=OLD_PREFIX,
        expected_initrd_sha256_hex=OLD_INITRD,
        expected_marker=None,
        reason="r",
        operator="o",
        evidence={},
    )
    launch_record.record_relaunch(
        "vm-g",
        {"measurement_hex": MEAS_NEW},
        reason="reboot-recovery-relaunch",
        booted=(OLD_PREFIX, OLD_INITRD),
    )
    assert launch_record.booted_artifacts(_job()) == (OLD_PREFIX, OLD_INITRD)


class _FakeS3:
    def presign_get(self, *, bucket: str, key: str, ttl_seconds: int) -> SimpleNamespace:
        return SimpleNamespace(url=f"https://s3.example/{bucket}/{key}?sig=x")


def _dispatch_migration(fx: Any, monkeypatch: pytest.MonkeyPatch, vm: Vm) -> dict[str, Any]:
    """Run the REAL §25 dest-activation dispatch (the `DestActivating`
    handler's call: `dispatch_migrate_activate(..., boot_artifacts=
    resolve_boot_artifacts(vm))`) and return the order payload it sends."""
    from apps.storage import s3

    monkeypatch.setattr(s3, "get_s3_client", lambda: _FakeS3())
    monkeypatch.setattr(migration_ticket, "remint_dest_ticket", lambda *a, **k: b"ticket")
    monkeypatch.setattr(effects, "_miner_identity", lambda node: ("miner-dst", "100.64.0.2"))
    sent: list[dict[str, Any]] = []

    def fake_dispatch(**kw: Any) -> order_dispatch.DispatchResult:
        sent.append(json.loads(kw["payload_json"]))
        return order_dispatch.DispatchResult(ok=True, status=200, classifier="")

    monkeypatch.setattr(order_dispatch, "dispatch_order", fake_dispatch)
    fx.real["dispatch_migrate_activate"](
        vm,
        dest_node_id="node-dst",
        new_gen=vm.generation + 1,
        get_url="https://s3.example/snap",
        boot_artifacts=fx.real["resolve_boot_artifacts"](vm),
    )
    (payload,) = sent
    return payload


def test_migration_before_the_relaunch_stages_the_initrd_the_guest_booted(
    tmp_path: Path, monkeypatch, fx
) -> None:
    """Between the swap and the relaunch the running guest measured the OLD
    initrd, and §25 replays its measured cmdline against a ticket for that
    measurement: staging the NEW initrd would change the dest's launch
    digest and the KBS would deny the key."""
    vm, _ = _golden_vm()
    _run(_rebuild(tmp_path), "vm-g", apply=True)

    payload = _dispatch_migration(fx, monkeypatch, vm)

    initrd = payload["boot_artifacts"]["initrd"]
    assert initrd["sha256_hex"] == OLD_INITRD
    assert f"/{OLD_PREFIX}/tenant.initrd.img?" in initrd["url"]
    assert payload["cmdline"] == "console=ttyS0 n=1"
    # Kernel + base are the same bytes either way; they come from the same
    # (old) prefix, which still holds all of them.
    assert payload["boot_artifacts"]["kernel"]["sha256_hex"] == KERNEL
    assert f"/{OLD_PREFIX}/rootfs.img?" in payload["boot_artifacts"]["rootfs_data"]["url"]


def test_migration_after_the_relaunch_stages_the_new_initrd(
    tmp_path: Path, monkeypatch, fx
) -> None:
    vm, _ = _golden_vm()
    _run(_rebuild(tmp_path), "vm-g", apply=True)
    _relaunch(monkeypatch, vm)

    payload = _dispatch_migration(fx, monkeypatch, vm)

    initrd = payload["boot_artifacts"]["initrd"]
    assert initrd["sha256_hex"] == NEW_INITRD
    assert f"/{NEW_PREFIX}/tenant.initrd.img?" in initrd["url"]
    # The replayed cmdline is the one the NEW boot measured.
    assert payload["cmdline"] == "console=ttyS0 n=2"


def test_the_digest_recompute_uses_the_booted_initrd(tmp_path: Path, monkeypatch) -> None:
    from apps.miners.models import MinerIdentity
    from apps.orchestration.management.commands import vali_backfill_launch_measurement as bf
    from apps.orchestration.services import launch_digest

    vm, _ = _golden_vm()
    MinerIdentity.objects.create(
        miner_id="node-src", pubkey_hex="0" * 64, platform_id="plat", chain_node_id="1" * 64
    )
    _run(_rebuild(tmp_path), "vm-g", apply=True)
    seen: dict[str, Any] = {}
    monkeypatch.setattr(
        launch_digest, "recompute_expected_digest", lambda **kw: seen.update(kw) or "d"
    )
    bf.recompute_digest(vm, "console=ttyS0 n=1")
    assert (seen["s3_key_prefix"], seen["initrd_sha256_hex"]) == (OLD_PREFIX, OLD_INITRD)


def test_a_prefix_in_the_json_must_agree_with_the_flag(tmp_path: Path) -> None:
    """The script never writes one, but a JSON that does must not be
    contradicted by the flag."""
    _, job = _golden_vm()
    args = _rebuild(tmp_path)
    path = Path(args[0].split("=", 1)[1])
    doc = json.loads(path.read_text())
    doc["s3_key_prefix"] = "golden/somewhere-else"
    path.write_text(json.dumps(doc))
    with pytest.raises(CommandError, match="disagrees with the measurement.json"):
        _run(args, "vm-g", apply=True)
    job.refresh_from_db()
    assert _record(job) == (OLD_PREFIX, OLD_INITRD)


# ── a record already on the rebuild ──────────────────────────────────


def test_a_record_on_the_rebuild_without_a_boot_record_is_refused(tmp_path: Path) -> None:
    """Spec names the rebuild but nothing says the running boot measured it
    (hand edit / half-applied write): `booted_artifacts` would fall back to
    the NEW spec while the emit holds the OLD measurement, and §25 would
    stage the new initrd against an old-measurement ticket."""
    _, job = _golden_vm(s3_key_prefix=NEW_PREFIX, initrd_sha256_hex=NEW_INITRD)
    before = (job.spec_json, job.result_json)
    out = _capture(_rebuild(tmp_path))
    assert "outcome=on-rebuild-without-boot-record " in out
    job.refresh_from_db()
    assert (job.spec_json, job.result_json) == before


def test_a_record_on_the_rebuild_with_a_foreign_marker_is_refused(tmp_path: Path) -> None:
    _, job = _golden_vm(s3_key_prefix=NEW_PREFIX, initrd_sha256_hex=NEW_INITRD)
    job.result_json["emit"][launch_record.BOOTED_ARTIFACTS_KEY] = {
        "s3_key_prefix": OLD_PREFIX,
        "initrd_sha256_hex": "ee" * 32,
    }
    job.save()
    out = _capture(_rebuild(tmp_path))
    assert "outcome=already-swapped-inconsistent-marker " in out


def test_already_swapped_still_runs_every_other_check(tmp_path: Path) -> None:
    _golden_vm()
    _run(_rebuild(tmp_path), "vm-g", apply=True)
    out = _capture(_rebuild(tmp_path, kernel_sha256="ff" * 32))
    assert "outcome=kernel_sha256-mismatch " in out


def test_a_swapped_then_relaunched_vm_is_a_clean_no_op(tmp_path: Path, monkeypatch) -> None:
    vm, _ = _golden_vm()
    _run(_rebuild(tmp_path), "vm-g", apply=True)
    _relaunch(monkeypatch, vm)
    out = _run(_rebuild(tmp_path), "vm-g", apply=True)
    assert "outcome=already-swapped-relaunched " in out
    assert "problems=0" in out


def test_the_locked_write_never_no_ops_on_a_record_already_on_the_rebuild() -> None:
    _, job = _golden_vm(s3_key_prefix=NEW_PREFIX, initrd_sha256_hex=NEW_INITRD)
    with pytest.raises(ValueError, match="changed since it was read"):
        launch_record.swap_initrd(
            "vm-g",
            new_prefix=NEW_PREFIX,
            new_initrd_sha256_hex=NEW_INITRD,
            expected_job_id=job.job_id,
            expected_prefix=OLD_PREFIX,
            expected_initrd_sha256_hex=OLD_INITRD,
            expected_marker=None,
            reason="r",
            operator="o",
            evidence={},
        )


# ── a relaunch whose record write failed ─────────────────────────────


def test_backfill_repairs_a_relaunch_whose_record_write_failed(tmp_path: Path, monkeypatch) -> None:
    """The relaunch booted the NEW initrd (measurement B, cmdline n=2) but
    `record_relaunch` raised: the record still says OLD initrd +
    measurement A. The backfill proves B over the SPEC's (swapped) initrd —
    never over the stale marker's — and records the boot and the marker in
    one write, after which §25 stages the new initrd."""
    from apps.miners.models import MinerIdentity
    from apps.orchestration.services import kbs_evidence, launch_digest

    vm, _ = _golden_vm()
    _run(_rebuild(tmp_path), "vm-g", apply=True)

    def boom(*_a: Any, **_k: Any) -> bool:
        raise RuntimeError("db down")

    real_record = launch_record.record_relaunch
    monkeypatch.setattr(launch_record, "record_relaunch", boom)
    (spec,) = _relaunch(monkeypatch, vm)
    monkeypatch.setattr(launch_record, "record_relaunch", real_record)
    assert spec.initrd_sha256_hex == NEW_INITRD
    stale = _job()
    assert stale.result_json["emit"]["measurement_hex"] == MEAS_OLD
    assert launch_record.booted_artifacts(stale) == (OLD_PREFIX, OLD_INITRD)

    assert MinerIdentity.objects.filter(miner_id=vm.host).exists()

    def digest(**kw: Any) -> str:
        table = {
            (OLD_PREFIX, OLD_INITRD, "console=ttyS0 n=1"): MEAS_OLD,
            (NEW_PREFIX, NEW_INITRD, "console=ttyS0 n=2"): MEAS_NEW,
        }
        return table.get((kw["s3_key_prefix"], kw["initrd_sha256_hex"], kw["cmdline"]), "c" * 96)

    monkeypatch.setattr(launch_digest, "recompute_expected_digest", digest)
    monkeypatch.setattr(kbs_evidence, "fetch_evidence", lambda vm_id: {"measurement_hex": MEAS_NEW})
    digests = tmp_path / "d.json"
    digests.write_text(json.dumps({"vm-g": MEAS_NEW}))
    cmdlines = tmp_path / "c.json"
    cmdlines.write_text(json.dumps({"vm-g": "console=ttyS0 n=2"}))

    def backfill(*extra: str) -> str:
        out = io.StringIO()
        call_command(
            "vali_backfill_launch_measurement",
            f"--miner-digests={digests}",
            f"--miner-cmdlines={cmdlines}",
            "--vm-id=vm-g",
            *extra,
            stdout=out,
        )
        return out.getvalue()

    assert "outcome=correct " in backfill()
    assert launch_record.booted_artifacts(_job()) == (OLD_PREFIX, OLD_INITRD), "dry-run"
    assert "outcome=corrected" in backfill("--commit")
    job = _job()
    emit = job.result_json["emit"]
    assert (emit["measurement_hex"], emit["measured_cmdline"]) == (MEAS_NEW, "console=ttyS0 n=2")
    assert launch_record.BOOTED_ARTIFACTS_KEY not in emit
    assert launch_record.booted_artifacts(job) == (NEW_PREFIX, NEW_INITRD)


def test_backfill_never_proves_a_measurement_over_bytes_the_record_does_not_name(
    tmp_path: Path, monkeypatch
) -> None:
    """The fallback is the spec's initrd only: a measurement that matches
    neither the booted nor the spec's artefacts is not recorded."""
    from apps.miners.models import MinerIdentity
    from apps.orchestration.management.commands import vali_backfill_launch_measurement as bf
    from apps.orchestration.services import kbs_evidence, launch_digest

    vm, _ = _golden_vm()
    MinerIdentity.objects.create(
        miner_id="node-src", pubkey_hex="0" * 64, platform_id="plat", chain_node_id="1" * 64
    )
    _run(_rebuild(tmp_path), "vm-g", apply=True)
    monkeypatch.setattr(launch_digest, "recompute_expected_digest", lambda **kw: "c" * 96)
    monkeypatch.setattr(kbs_evidence, "fetch_evidence", lambda vm_id: {"measurement_hex": MEAS_NEW})
    assert bf.verdict(vm, MEAS_NEW, "console=ttyS0 n=2")[0] == "cmdline-does-not-measure"


def test_a_correction_refuses_boot_artefacts_the_record_does_not_name() -> None:
    _golden_vm()
    with pytest.raises(ValueError, match="record moved"):
        launch_record.correct_measurement(
            "vm-g",
            MEAS_NEW,
            measured_cmdline="c",
            reason="r",
            evidence={},
            expected_previous=MEAS_OLD,
            booted=("elsewhere", "ee" * 32),
        )
    assert _job().result_json["emit"]["measurement_hex"] == MEAS_OLD


# ── a launch job created during the write ────────────────────────────


def test_a_launch_job_queued_during_the_write_is_reported(tmp_path: Path, monkeypatch) -> None:
    """Launch intake accepts an ACTIVE vm_id and does not take the Vm lock,
    so a job can appear while the swap is written. It would become the
    record relaunches read: the command must not report a clean swap."""
    _golden_vm()
    real = launch_record.swap_initrd

    def with_intake(vm_id: str, **kw: Any) -> bool:
        ok = real(vm_id, **kw)
        base = _job(vm_id)
        LaunchJob.objects.create(
            job_id="job-intake",
            vm_id=vm_id,
            tenant_id="tenant-1",
            flavor="small",
            spec_json=dict(_SPEC),
            userdata_vault_path=base.userdata_vault_path,
            userdata_vault_version=1,
            kek_vault_path=base.kek_vault_path,
            state=LaunchJobState.QUEUED.value,
            phase_started_at=timezone.now(),
            decided_by=base.decided_by,
        )
        return ok

    monkeypatch.setattr(launch_record, "swap_initrd", with_intake)
    out = _capture(_rebuild(tmp_path))
    assert "outcome=swapped-but-shadowed:launch-job-in-flight " in out
    assert "swapped=0" in out


def test_a_marker_that_is_not_what_the_swap_replaced_is_refused(tmp_path: Path) -> None:
    """A marker carrying the source initrd under a prefix the audited swap
    never replaced is not a consistent pending swap."""
    _golden_vm()
    _run(_rebuild(tmp_path), "vm-g", apply=True)
    job = _job()
    job.result_json["emit"][launch_record.BOOTED_ARTIFACTS_KEY]["s3_key_prefix"] = "golden/foreign"
    job.save()
    out = _capture(_rebuild(tmp_path))
    assert "outcome=already-swapped-inconsistent-marker " in out


def test_prefixes_are_compared_case_sensitively(tmp_path: Path, monkeypatch) -> None:
    """S3 keys are case-sensitive: an audited swap onto `…/ABC` does not
    vouch for a record on `…/abc`."""
    vm, _ = _golden_vm()
    _run(_rebuild(tmp_path), "vm-g", apply=True)
    _relaunch(monkeypatch, vm)
    job = _job()
    for entry in job.result_json["emit"]["superseded"]:
        if "new" in entry:
            entry["new"]["spec.s3_key_prefix"] = NEW_PREFIX.upper()
    job.save()
    out = _capture(_rebuild(tmp_path))
    assert "outcome=on-rebuild-without-boot-record " in out


def test_backfill_tries_the_swapped_initrd_when_the_old_one_cannot_be_read(
    tmp_path: Path, monkeypatch
) -> None:
    from apps.miners.models import MinerIdentity
    from apps.orchestration.management.commands import vali_backfill_launch_measurement as bf
    from apps.orchestration.services import kbs_evidence, launch_digest

    vm, _ = _golden_vm()
    MinerIdentity.objects.create(
        miner_id="node-src", pubkey_hex="0" * 64, platform_id="plat", chain_node_id="1" * 64
    )
    _run(_rebuild(tmp_path), "vm-g", apply=True)

    def digest(**kw: Any) -> str:
        if kw["s3_key_prefix"] == OLD_PREFIX:
            raise RuntimeError("old prefix unreadable")
        return MEAS_NEW

    monkeypatch.setattr(launch_digest, "recompute_expected_digest", digest)
    monkeypatch.setattr(kbs_evidence, "fetch_evidence", lambda vm_id: {"measurement_hex": MEAS_NEW})
    outcome, detail = bf.verdict(vm, MEAS_NEW, "console=ttyS0 n=2")
    assert outcome == "correct"
    assert detail["booted_artifacts"] == [NEW_PREFIX, NEW_INITRD]


THIRD_INITRD = "7a" * 32
THIRD_PREFIX = "golden/ubuntu-24.04/abc123-initrd-a100"


def _second_rebuild(tmp_path: Path) -> list[str]:
    """A rebuild of the FIRST rebuild (B → C)."""
    sub = tmp_path / "second"
    sub.mkdir(exist_ok=True)
    return _rebuild(
        sub,
        s3_key_prefix=THIRD_PREFIX,
        initrd_sha256=THIRD_INITRD,
        source_initrd_sha256=NEW_INITRD,
    )


def test_a_second_swap_before_the_relaunch_is_refused(tmp_path: Path) -> None:
    _golden_vm()
    _run(_rebuild(tmp_path), "vm-g", apply=True)
    with pytest.raises(CommandError):
        out = io.StringIO()
        call_command(
            "vali_swap_vm_initrd",
            "--vm-id=vm-g",
            *_second_rebuild(tmp_path),
            "--operator=o",
            "--reason=r",
            "--apply",
            stdout=out,
        )
    assert "outcome=swap-pending-relaunch-first " in out.getvalue()
    assert _record(_job()) == (NEW_PREFIX, NEW_INITRD)


def test_an_older_audited_swap_does_not_vouch_after_a_later_one(
    tmp_path: Path, monkeypatch
) -> None:
    """A→B, boot B, B→C, boot C, then the spec is hand-reset to B: the
    running boot is C, so the B swap's audit entry must not make B a no-op."""
    vm, _ = _golden_vm()
    _run(_rebuild(tmp_path), "vm-g", apply=True)
    _relaunch(monkeypatch, vm)
    _run(_second_rebuild(tmp_path), "vm-g", apply=True)
    _relaunch(monkeypatch, vm)
    job = _job()
    job.spec_json = {**job.spec_json, "s3_key_prefix": NEW_PREFIX, "initrd_sha256_hex": NEW_INITRD}
    job.save()
    out = _capture(_rebuild(tmp_path))
    assert "outcome=on-rebuild-without-boot-record " in out


def test_a_launch_record_that_succeeded_during_the_write_is_reported(
    tmp_path: Path, monkeypatch
) -> None:
    _golden_vm()
    real = launch_record.swap_initrd

    def with_launch(vm_id: str, **kw: Any) -> bool:
        ok = real(vm_id, **kw)
        base = _job(vm_id)
        LaunchJob.objects.create(
            job_id="job-later",
            vm_id=vm_id,
            tenant_id="tenant-1",
            flavor="small",
            spec_json=dict(_SPEC),
            userdata_vault_path=base.userdata_vault_path,
            userdata_vault_version=1,
            kek_vault_path=base.kek_vault_path,
            state=LaunchJobState.SUCCEEDED.value,
            phase_started_at=timezone.now(),
            finished_at=timezone.now() + timedelta(seconds=5),
            decided_by=base.decided_by,
        )
        return ok

    monkeypatch.setattr(launch_record, "swap_initrd", with_launch)
    out = _capture(_rebuild(tmp_path))
    assert "outcome=swapped-but-shadowed:latest-launch-record-changed " in out


def test_backfill_reports_a_failed_candidate_as_unproven(tmp_path: Path, monkeypatch) -> None:
    from apps.miners.models import MinerIdentity
    from apps.orchestration.management.commands import vali_backfill_launch_measurement as bf
    from apps.orchestration.services import kbs_evidence, launch_digest

    vm, _ = _golden_vm()
    MinerIdentity.objects.create(
        miner_id="node-src", pubkey_hex="0" * 64, platform_id="plat", chain_node_id="1" * 64
    )
    _run(_rebuild(tmp_path), "vm-g", apply=True)

    def digest(**kw: Any) -> str:
        if kw["s3_key_prefix"] == NEW_PREFIX:
            raise RuntimeError("new prefix unreadable")
        return "c" * 96

    monkeypatch.setattr(launch_digest, "recompute_expected_digest", digest)
    monkeypatch.setattr(kbs_evidence, "fetch_evidence", lambda vm_id: {"measurement_hex": MEAS_NEW})
    assert bf.verdict(vm, MEAS_NEW, "console=ttyS0 n=2")[0] == "recompute-failed"


# ── --revert ─────────────────────────────────────────────────────────

REVERT = ["--revert"]


def test_revert_after_a_refused_relaunch_restores_the_original_initrd(
    tmp_path: Path, monkeypatch, fx
) -> None:
    vm, job = _golden_vm()
    _run(_rebuild(tmp_path), "vm-g", apply=True)
    # The power start is refused by the miner: nothing new booted.
    (spec,) = _relaunch(monkeypatch, vm, disposition=launch.RETRIABLE)
    assert spec.initrd_sha256_hex == NEW_INITRD

    dry = _run(REVERT, "vm-g")
    assert "vm=vm-g outcome=revert " in dry
    assert _record(_job()) == (NEW_PREFIX, NEW_INITRD), "dry-run writes nothing"

    out = _run(REVERT, "vm-g", apply=True)
    assert "vm=vm-g outcome=reverted " in out
    assert "reverted=1 problems=0" in out
    job = _job()
    assert _record(job) == (OLD_PREFIX, OLD_INITRD)
    emit = job.result_json["emit"]
    # The spec IS the running boot again: no pending marker.
    assert launch_record.BOOTED_ARTIFACTS_KEY not in emit
    assert emit["measurement_hex"] == MEAS_OLD
    revert = emit["superseded"][-1]
    assert revert["reason"] == "initrd-swap-revert:m0-guard"
    assert revert["operator"] == "alice"
    assert revert["previous"] == {
        "spec.s3_key_prefix": NEW_PREFIX,
        "spec.initrd_sha256_hex": NEW_INITRD,
    }
    assert revert["new"] == {"spec.s3_key_prefix": OLD_PREFIX, "spec.initrd_sha256_hex": OLD_INITRD}
    # The next start boots the original initrd, and §25 stages it.
    (spec,) = _relaunch(
        monkeypatch, vm, emit={"measurement_hex": "d" * 96, "measured_cmdline": "console=ttyS0 n=3"}
    )
    assert (spec.s3_key_prefix, spec.initrd_sha256_hex) == (OLD_PREFIX, OLD_INITRD)
    payload = _dispatch_migration(fx, monkeypatch, vm)
    assert payload["boot_artifacts"]["initrd"]["sha256_hex"] == OLD_INITRD


def _attest(measurement: str, seq: int = 1) -> None:
    from apps.telemetry.models import VmLiveAttestation

    VmLiveAttestation.objects.create(
        vm_id="vm-g",
        node_id_hex="aa" * 32,
        attestation_seq=seq,
        epoch=7,
        observed_at_unix=1_000,
        verified_at_unix=1_001,
        expiry_unix=2_000,
        measurement=measurement,
        snp_report_digest="11" * 32,
        body_digest=f"{measurement[:8]}-{seq}".encode().hex().ljust(64, "0")[:64],
    )


def _domain(monkeypatch: pytest.MonkeyPatch, running: bool | None) -> list[str]:
    calls: list[str] = []

    def poll(vm: Any) -> bool | None:
        calls.append(vm.vm_id)
        return running

    monkeypatch.setattr(effects, "poll_domain_running", poll)
    return calls


def test_revert_is_refused_after_a_successful_relaunch(tmp_path: Path, monkeypatch) -> None:
    """The new initrd booted AND unlocked (the KBS live-attested its
    measurement): going back is a forward swap, not a revert."""
    _swapped_and_relaunched(tmp_path, monkeypatch)
    _attest(MEAS_NEW.upper())
    _domain(monkeypatch, False)
    before = _job().result_json
    out = _capture(REVERT)
    assert "outcome=new-measurement-attested " in out
    job = _job()
    assert _record(job) == (NEW_PREFIX, NEW_INITRD)
    assert job.result_json == before


def test_revert_is_refused_on_a_vm_that_was_never_swapped(tmp_path: Path) -> None:
    _golden_vm()
    assert "outcome=no-swap-to-revert " in _capture(REVERT)
    assert _record(_job()) == (OLD_PREFIX, OLD_INITRD)


def test_revert_is_refused_when_the_record_is_not_the_swapped_one(tmp_path: Path) -> None:
    _golden_vm()
    _run(_rebuild(tmp_path), "vm-g", apply=True)
    job = _job()
    job.spec_json = {**job.spec_json, "initrd_sha256_hex": "ee" * 32}
    job.save()
    assert "outcome=record-is-not-the-swapped-one " in _capture(REVERT)
    assert _record(_job()) == (NEW_PREFIX, "ee" * 32)


def test_revert_is_refused_when_the_marker_is_not_what_the_swap_replaced(
    tmp_path: Path,
) -> None:
    _golden_vm()
    _run(_rebuild(tmp_path), "vm-g", apply=True)
    job = _job()
    job.result_json["emit"][launch_record.BOOTED_ARTIFACTS_KEY]["s3_key_prefix"] = "golden/x"
    job.save()
    assert "outcome=inconsistent-marker " in _capture(REVERT)


def test_revert_is_refused_mid_flight(tmp_path: Path) -> None:
    vm, _ = _golden_vm()
    _run(_rebuild(tmp_path), "vm-g", apply=True)
    _vm_in_flight("migrating", vm)
    assert "outcome=migration-in-flight " in _capture(REVERT)
    assert _record(_job()) == (NEW_PREFIX, NEW_INITRD)


def test_revert_happens_once_and_the_swap_can_be_redone(tmp_path: Path) -> None:
    _golden_vm()
    _run(_rebuild(tmp_path), "vm-g", apply=True)
    _run(REVERT, "vm-g", apply=True)
    assert "outcome=no-swap-to-revert " in _capture(REVERT)
    assert "outcome=swapped " in _run(_rebuild(tmp_path), "vm-g", apply=True)
    assert _record(_job()) == (NEW_PREFIX, NEW_INITRD)


def test_a_revert_is_not_a_boot_record(tmp_path: Path) -> None:
    """After a revert, a record hand-set back onto the rebuild has no boot
    proving it: the revert entry must not count as one."""
    _golden_vm()
    _run(_rebuild(tmp_path), "vm-g", apply=True)
    _run(REVERT, "vm-g", apply=True)
    job = _job()
    job.spec_json = {**job.spec_json, "s3_key_prefix": NEW_PREFIX, "initrd_sha256_hex": NEW_INITRD}
    job.save()
    assert "outcome=on-rebuild-without-boot-record " in _capture(_rebuild(tmp_path))


def test_revert_and_measurement_json_are_exclusive(tmp_path: Path) -> None:
    _golden_vm()
    with pytest.raises(CommandError, match="--revert takes no"):
        _run([*_rebuild(tmp_path), "--revert"], "vm-g")
    with pytest.raises(CommandError, match="--measurement-json or --from-s3-prefix is required"):
        _run([], "vm-g")


def test_revert_refuses_a_boot_recorded_after_its_decision(tmp_path: Path, monkeypatch) -> None:
    """A backfill (which does not take the Vm lock) records the new boot
    between the revert's decision and its write: the write must refuse,
    not put the spec back under a guest running the new initrd."""
    _golden_vm()
    _run(_rebuild(tmp_path), "vm-g", apply=True)
    real = launch_record.swap_initrd

    def after_a_backfill(vm_id: str, **kw: Any) -> bool:
        launch_record.correct_measurement(
            vm_id,
            MEAS_NEW,
            measured_cmdline="console=ttyS0 n=2",
            reason="backfill",
            evidence={},
            expected_previous=MEAS_OLD,
            booted=(NEW_PREFIX, NEW_INITRD),
        )
        return real(vm_id, **kw)

    monkeypatch.setattr(launch_record, "swap_initrd", after_a_backfill)
    out = _capture(REVERT)
    assert "outcome=write-refused:" in out
    assert "recorded boot changed" in out
    job = _job()
    assert _record(job) == (NEW_PREFIX, NEW_INITRD)
    assert launch_record.booted_artifacts(job) == (NEW_PREFIX, NEW_INITRD)


# ── --revert after an accepted relaunch that never came up ───────────


def _swapped_and_relaunched(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Vm:
    vm, _ = _golden_vm()
    job = _job()
    job.result_json["emit"].update(
        {"initrd_path": "/var/lib/hippius-miner/staging/vm-g/tenant.initrd.img"}
    )
    job.save()
    _run(_rebuild(tmp_path), "vm-g", apply=True)
    _relaunch(
        monkeypatch,
        vm,
        emit={
            "measurement_hex": MEAS_NEW,
            "measured_cmdline": "console=ttyS0 n=2",
            "initrd_path": "/var/lib/hippius-miner/staging/vm-g/tenant.initrd.img.new",
        },
    )
    # The operator power-stopped it an hour ago.
    stopped_at = timezone.now() - timedelta(hours=1)
    Vm.objects.filter(pk=vm.pk).update(
        power_state=VmPowerState.STOPPED,
        power_state_at=stopped_at,
        power_stop_ordered_at=stopped_at,
    )
    vm.refresh_from_db()
    return vm


def test_revert_after_an_accepted_relaunch_that_never_attested(
    tmp_path: Path, monkeypatch, fx
) -> None:
    vm = _swapped_and_relaunched(tmp_path, monkeypatch)
    # An attestation of the OLD measurement (the pre-swap boot) is fine.
    _attest(MEAS_OLD)
    polled = _domain(monkeypatch, False)

    assert "vm=vm-g outcome=revert " in _run(REVERT, "vm-g")
    assert _record(_job()) == (NEW_PREFIX, NEW_INITRD), "dry-run writes nothing"

    out = _run(REVERT, "vm-g", apply=True)
    assert "vm=vm-g outcome=reverted " in out
    assert polled, "the miner was asked whether a domain is live"
    job = _job()
    assert _record(job) == (OLD_PREFIX, OLD_INITRD)
    emit = job.result_json["emit"]
    # The recorded boot is the pre-swap one again.
    assert (emit["measurement_hex"], emit["measured_cmdline"]) == (MEAS_OLD, "console=ttyS0 n=1")
    assert emit["initrd_path"] == "/var/lib/hippius-miner/staging/vm-g/tenant.initrd.img"
    assert launch_record.BOOTED_ARTIFACTS_KEY not in emit
    assert launch_record.booted_artifacts(job) == (OLD_PREFIX, OLD_INITRD)
    revert = emit["superseded"][-1]
    assert revert["reason"] == "initrd-swap-revert:m0-guard"
    assert revert["previous_boot"]["measurement_hex"] == MEAS_NEW
    assert revert["new"] == {"spec.s3_key_prefix": OLD_PREFIX, "spec.initrd_sha256_hex": OLD_INITRD}

    # §25 before the next start stages the ORIGINAL initrd with the
    # original boot's cmdline…
    payload = _dispatch_migration(fx, monkeypatch, vm)
    assert payload["boot_artifacts"]["initrd"]["sha256_hex"] == OLD_INITRD
    assert f"/{OLD_PREFIX}/tenant.initrd.img?" in payload["boot_artifacts"]["initrd"]["url"]
    assert payload["cmdline"] == "console=ttyS0 n=1"
    # …and the next start re-mints on the ORIGINAL initrd.
    (spec,) = _relaunch(
        monkeypatch, vm, emit={"measurement_hex": "d" * 96, "measured_cmdline": "console=ttyS0 n=3"}
    )
    assert (spec.s3_key_prefix, spec.initrd_sha256_hex) == (OLD_PREFIX, OLD_INITRD)
    assert launch_record.booted_artifacts(_job()) == (OLD_PREFIX, OLD_INITRD)


@pytest.mark.parametrize(
    ("running", "outcome"), [(True, "domain-running"), (None, "domain-state-unknown")]
)
def test_revert_after_a_relaunch_refuses_unless_no_domain_is_live(
    tmp_path: Path, monkeypatch, running: bool | None, outcome: str
) -> None:
    _swapped_and_relaunched(tmp_path, monkeypatch)
    _domain(monkeypatch, running)
    before = _job().result_json
    assert f"outcome={outcome} " in _capture(REVERT)
    assert _record(_job()) == (NEW_PREFIX, NEW_INITRD)
    assert _job().result_json == before


def test_revert_after_two_relaunches_is_refused(tmp_path: Path, monkeypatch) -> None:
    vm = _swapped_and_relaunched(tmp_path, monkeypatch)
    _relaunch(monkeypatch, vm, emit={"measurement_hex": "e" * 96, "measured_cmdline": "n=4"})
    _domain(monkeypatch, False)
    assert "outcome=relaunched-on-new-initrd " in _capture(REVERT)


def test_revert_after_a_relaunch_refuses_a_boot_recorded_after_its_decision(
    tmp_path: Path, monkeypatch
) -> None:
    _swapped_and_relaunched(tmp_path, monkeypatch)
    _domain(monkeypatch, False)
    real = launch_record.swap_initrd

    def after_another_relaunch(vm_id: str, **kw: Any) -> bool:
        launch_record.record_relaunch(
            vm_id, {"measurement_hex": "e" * 96}, reason="reboot-recovery-relaunch"
        )
        return real(vm_id, **kw)

    monkeypatch.setattr(launch_record, "swap_initrd", after_another_relaunch)
    out = _capture(REVERT)
    assert "outcome=write-refused:" in out
    assert "gained an audit entry" in out
    assert _record(_job()) == (NEW_PREFIX, NEW_INITRD)


# ── --from-s3-prefix ─────────────────────────────────────────────────


class _ReadOnlyS3:
    """Serves objects; any write is a test failure."""

    def __init__(self, objects: dict[tuple[str, str], bytes]) -> None:
        self.objects = objects
        self.reads: list[tuple[str, str]] = []

    def get_object(self, *, bucket: str, key: str, max_bytes: int) -> bytes | None:
        self.reads.append((bucket, key))
        return self.objects.get((bucket, key))

    def __getattr__(self, name: str) -> Any:
        raise AssertionError(f"the command must only read S3, it called {name}")


def _s3(monkeypatch: pytest.MonkeyPatch, doc: dict[str, Any] | None = None) -> _ReadOnlyS3:
    from apps.storage import s3

    client = _ReadOnlyS3(
        {}
        if doc is None
        else {(BUCKET, f"{NEW_PREFIX}/golden.measurement.json"): json.dumps(doc).encode()}
    )
    monkeypatch.setattr(s3, "get_s3_client", lambda: client)
    return client


def _run_s3(*extra: str, apply: bool = False) -> str:
    out = io.StringIO()
    args = ["--vm-id=vm-g", *extra, "--operator=alice", "--reason=m0-guard"]
    if apply:
        args.append("--apply")
    call_command("vali_swap_vm_initrd", *args, stdout=out)
    return out.getvalue()


@pytest.fixture
def _images_bucket(settings: Any) -> None:
    settings.VALI_PACKER_IMAGES_BUCKET = BUCKET


def test_the_measurement_is_read_from_the_rebuild_prefix(monkeypatch, _images_bucket) -> None:
    _golden_vm()
    client = _s3(monkeypatch, _REAL)
    out = _run_s3(f"--from-s3-prefix={NEW_PREFIX}/", apply=True)
    assert "outcome=swapped " in out
    assert client.reads == [(BUCKET, f"{NEW_PREFIX}/golden.measurement.json")]
    job = _job()
    assert _record(job) == (NEW_PREFIX, NEW_INITRD)
    assert job.result_json["emit"]["superseded"][-1]["evidence"]["rebuild_measurement"] == _REAL


def test_a_missing_s3_measurement_is_refused(monkeypatch, _images_bucket) -> None:
    _golden_vm()
    _s3(monkeypatch, None)
    with pytest.raises(CommandError, match="does not exist"):
        _run_s3(f"--from-s3-prefix={NEW_PREFIX}", apply=True)
    assert _record(_job()) == (OLD_PREFIX, OLD_INITRD)


def test_the_s3_prefix_is_cross_checked(monkeypatch, _images_bucket) -> None:
    _golden_vm()
    _s3(monkeypatch, _REAL)
    with pytest.raises(CommandError, match="disagrees with --from-s3-prefix"):
        _run_s3(f"--from-s3-prefix={NEW_PREFIX}", "--s3-key-prefix=golden/else", apply=True)
    # An agreeing --s3-key-prefix is fine.
    out = _run_s3(f"--from-s3-prefix={NEW_PREFIX}", f"--s3-key-prefix={NEW_PREFIX}/")
    assert "outcome=swap " in out


def test_a_doc_naming_another_prefix_is_refused(monkeypatch, _images_bucket) -> None:
    _golden_vm()
    _s3(monkeypatch, {**_REAL, "s3_key_prefix": "golden/else"})
    with pytest.raises(CommandError, match="disagrees"):
        _run_s3(f"--from-s3-prefix={NEW_PREFIX}", apply=True)


def test_the_bucket_read_must_be_the_vms(monkeypatch, _images_bucket) -> None:
    _golden_vm(s3_bucket="another-bucket")
    _s3(monkeypatch, _REAL)
    out = io.StringIO()
    with pytest.raises(CommandError):
        call_command(
            "vali_swap_vm_initrd",
            "--vm-id=vm-g",
            f"--from-s3-prefix={NEW_PREFIX}",
            "--operator=o",
            "--reason=r",
            "--apply",
            stdout=out,
        )
    assert "outcome=bucket-mismatch " in out.getvalue()


@pytest.mark.parametrize(
    ("args", "message"),
    [
        (["--from-s3-prefix=p", "--measurement-json=/x"], "mutually exclusive"),
        (["--revert", "--from-s3-prefix=p"], "--revert takes no"),
        (["--s3-bucket=b", "--measurement-json=/x"], "only applies to --from-s3-prefix"),
    ],
)
def test_source_flags_are_exclusive(args: list[str], message: str) -> None:
    _golden_vm()
    with pytest.raises(CommandError, match=message):
        _run_s3(*args)


@pytest.mark.parametrize(
    ("power", "age", "outcome"),
    [
        (VmPowerState.RUNNING, timedelta(hours=1), "not-stopped:running"),
        (VmPowerState.STOPPED, timedelta(minutes=11), "stopped-too-recently"),
    ],
)
def test_revert_after_a_relaunch_needs_a_durable_stop(
    tmp_path: Path, monkeypatch, power: str, age: timedelta, outcome: str
) -> None:
    """One "domain down" poll is not a stop: an in-guest reboot's watcher
    restarts the domain on its own. And a fresh stop leaves the skew window
    in which a late attestation of the new boot could still be ingested."""
    vm = _swapped_and_relaunched(tmp_path, monkeypatch)
    at = timezone.now() - age
    Vm.objects.filter(pk=vm.pk).update(
        power_state=power, power_state_at=at, power_stop_ordered_at=at
    )
    _domain(monkeypatch, False)
    assert f"outcome={outcome} " in _capture(REVERT)
    assert _record(_job()) == (NEW_PREFIX, NEW_INITRD)


def test_revert_after_a_relaunch_refuses_a_stop_that_was_only_settled(
    tmp_path: Path, monkeypatch
) -> None:
    """`stopped` settled from an abandoned marker by one "domain down" poll
    is not a stop order: the miner may restart that domain."""
    vm = _swapped_and_relaunched(tmp_path, monkeypatch)
    Vm.objects.filter(pk=vm.pk).update(power_stop_ordered_at=None)
    _domain(monkeypatch, False)
    assert "outcome=stop-not-ordered " in _capture(REVERT)


def test_a_later_power_write_that_ignores_the_column_voids_the_order(
    tmp_path: Path, monkeypatch
) -> None:
    """An older image (mid-rollout) or any writer that does not know the
    column still stamps `power_state_at`: the order then no longer
    describes the current `stopped`."""
    vm = _swapped_and_relaunched(tmp_path, monkeypatch)
    Vm.objects.filter(pk=vm.pk).update(
        power_state=VmPowerState.STOPPED, power_state_at=timezone.now() - timedelta(minutes=30)
    )
    _domain(monkeypatch, False)
    assert "outcome=stop-not-ordered " in _capture(REVERT)


def test_revert_after_a_relaunch_refuses_a_guest_that_signalled(
    tmp_path: Path, monkeypatch
) -> None:
    vm = _swapped_and_relaunched(tmp_path, monkeypatch)
    Vm.objects.filter(pk=vm.pk).update(guest_signal_at=timezone.now())
    _domain(monkeypatch, False)
    assert "outcome=guest-signalled-after-relaunch " in _capture(REVERT)
    # A signal from BEFORE the relaunch (the old boot) is fine.
    Vm.objects.filter(pk=vm.pk).update(guest_signal_at=timezone.now() - timedelta(days=2))
    assert "outcome=revert " in _run(REVERT, "vm-g")


def test_revert_after_a_relaunch_rolls_back_on_a_late_attestation(
    tmp_path: Path, monkeypatch
) -> None:
    _swapped_and_relaunched(tmp_path, monkeypatch)
    _domain(monkeypatch, False)
    before = _job()
    real = launch_record.swap_initrd

    def then_attested(vm_id: str, **kw: Any) -> bool:
        ok = real(vm_id, **kw)
        _attest(MEAS_NEW)
        return ok

    monkeypatch.setattr(launch_record, "swap_initrd", then_attested)
    assert "outcome=write-refused:new-measurement-attested-meanwhile " in _capture(REVERT)
    job = _job()
    assert (job.spec_json, job.result_json) == (before.spec_json, before.result_json)


def test_only_a_completed_stop_order_marks_the_stop_ordered(monkeypatch) -> None:
    from apps.orchestration.services import power

    vm, _ = _golden_vm()
    monkeypatch.setattr(effects, "dispatch_graceful_stop", lambda *a, **k: None)
    power.stop_vm(vm)
    vm.refresh_from_db()
    assert (vm.power_state, vm.stopped_by_order) == (VmPowerState.STOPPED, True)
    power._set_power(vm, VmPowerState.STARTING)
    vm.refresh_from_db()
    assert vm.stopped_by_order is False
    power._set_power(vm, VmPowerState.STOPPED)
    vm.refresh_from_db()
    assert vm.stopped_by_order is False


def test_the_power_axis_is_not_hand_editable_in_the_admin() -> None:
    from django.contrib import admin

    readonly = set(admin.site._registry[Vm].readonly_fields)
    assert {"power_state", "power_state_at", "power_stop_ordered_at"} <= readonly


# ── a guest components release build (scripts/guest/guest-initrd-build.sh) ──

# The REAL output shape of `scripts/guest/guest-initrd-build.sh` (base initrd
# ‖ release member, docs/design/guest-component-rollout.md), captured from a
# run against the fixture base set of `scripts/dev/guest-initrd-build-test.sh`
# published through its fake S3: it names its own bucket and prefix.
GUEST_FIXTURE = Path(__file__).parent / "fixtures" / "guest_release.golden.measurement.json"


def test_a_guest_release_build_swaps_by_its_own_prefix(tmp_path: Path) -> None:
    doc = json.loads(GUEST_FIXTURE.read_text())
    base_prefix = doc["initrd_rebuild"]["source_location"].split("/", 3)[3].rstrip("/")
    _, job = _golden_vm(
        kernel_sha256_hex=doc["kernel_sha256"],
        initrd_sha256_hex=doc["initrd_rebuild"]["source_initrd_sha256"],
        rootfs_img_sha256_hex=doc["rootfs_img_sha256"],
        rootfs_verity_sha256_hex=doc["rootfs_verity_sha256"],
        verity_root_hash_hex=doc["verity_root_hash"],
        bake_id=doc["initrd_rebuild"]["source_bake_id"],
        s3_bucket=doc["s3_bucket"],
        s3_key_prefix=base_prefix,
    )
    # No --s3-key-prefix: the build's measurement names where it lives.
    out = _run([f"--measurement-json={GUEST_FIXTURE}"], "vm-g", apply=True)
    assert "vm=vm-g outcome=swapped" in out
    job.refresh_from_db()
    assert _record(job) == (doc["s3_key_prefix"], doc["initrd_sha256"])
    assert job.result_json["emit"][launch_record.BOOTED_ARTIFACTS_KEY] == {
        "s3_key_prefix": base_prefix,
        "initrd_sha256_hex": doc["initrd_rebuild"]["source_initrd_sha256"],
    }
