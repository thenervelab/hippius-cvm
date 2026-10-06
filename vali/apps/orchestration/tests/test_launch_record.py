"""The launch record describes the VM's CURRENT boot: a reboot-recovery
relaunch records its new measurement, and `vali_backfill_launch_measurement`
corrects VMs relaunched before that, on two agreeing sources only."""

from __future__ import annotations

import json
from io import StringIO
from types import SimpleNamespace
from typing import Any

import pytest
from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import override_settings
from django.utils import timezone

from apps.orchestration import service
from apps.orchestration.effects import EffectUnavailable
from apps.orchestration.models import LaunchJob, LaunchJobState
from apps.orchestration.services import launch, launch_record

from .factories import make_launch_record, make_service_client, make_vm

pytestmark = pytest.mark.django_db

A = "a" * 96
B = "b" * 96
C = "c" * 96


def _emit(vm_id: str) -> dict[str, Any]:
    job = LaunchJob.objects.get(vm_id=vm_id, state=LaunchJobState.SUCCEEDED.value)
    return (job.result_json or {}).get("emit") or {}


# ── record_relaunch ──────────────────────────────────────────────────


def test_a_relaunch_rewrites_the_boot_keys_and_keeps_the_old_ones() -> None:
    vm = make_vm("vm-r")
    job = make_launch_record(vm, measurement_hex=A, measured_cmdline="old nonce=1")
    job.result_json = {"ticket_id": "tk-vm-r-first", "emit": dict(job.result_json["emit"])}
    job.save()

    changed = launch_record.record_relaunch(
        "vm-r",
        {"measurement_hex": B, "measured_cmdline": "new nonce=2", "ok": True, "outcome": "x"},
        reason="reboot-recovery-relaunch",
    )

    assert changed is True
    job.refresh_from_db()
    emit = job.result_json["emit"]
    assert (emit["measurement_hex"], emit["measured_cmdline"]) == (B, "new nonce=2")
    # Only boot keys move: the launch's own ticket and non-boot emit keys stay.
    assert job.result_json["ticket_id"] == "tk-vm-r-first"
    assert "ok" not in emit and "outcome" not in emit
    (entry,) = emit["superseded"]
    assert entry["reason"] == "reboot-recovery-relaunch"
    assert entry["previous"] == {"measurement_hex": A, "measured_cmdline": "old nonce=1"}
    assert launch_record.recorded_measurement("vm-r") == B


def test_an_identical_relaunch_writes_nothing() -> None:
    vm = make_vm("vm-r")
    make_launch_record(vm, measurement_hex=A)
    assert launch_record.record_relaunch("vm-r", {"measurement_hex": A}, reason="r") is False
    assert "superseded" not in _emit("vm-r")


def test_a_relaunch_without_a_measurement_or_a_record_is_an_error() -> None:
    vm = make_vm("vm-r")
    make_launch_record(vm, measurement_hex=A)
    with pytest.raises(ValueError):
        launch_record.record_relaunch("vm-r", {"measured_cmdline": "x"}, reason="r")
    assert _emit("vm-r") == {"measurement_hex": A}
    with pytest.raises(LookupError):
        launch_record.record_relaunch("vm-none", {"measurement_hex": B}, reason="r")


def test_the_audit_trail_is_bounded() -> None:
    vm = make_vm("vm-r")
    make_launch_record(vm, measurement_hex=A)
    for i in range(launch_record.MAX_SUPERSEDED + 5):
        launch_record.record_relaunch("vm-r", {"measurement_hex": f"{i:096x}"}, reason="r")
    assert len(_emit("vm-r")["superseded"]) == launch_record.MAX_SUPERSEDED


def test_the_latest_succeeded_record_is_the_one_rewritten() -> None:
    vm = make_vm("vm-r")
    old = make_launch_record(vm, measurement_hex=A)
    LaunchJob.objects.filter(pk=old.pk).update(
        finished_at=timezone.now() - timezone.timedelta(days=1)
    )
    new = make_launch_record(vm, measurement_hex=C)
    launch_record.record_relaunch("vm-r", {"measurement_hex": B}, reason="r")
    old.refresh_from_db()
    new.refresh_from_db()
    assert old.result_json["emit"]["measurement_hex"] == A
    assert new.result_json["emit"]["measurement_hex"] == B


# ── reboot-recovery wires it ─────────────────────────────────────────


_FULL_SPEC = {
    "tenant_id": "tenant-1",
    "user_id": "user-1",
    "vm_id": "vm-r",
    "lease_id": "lease-vm-r",
    "s3_bucket": "b",
    "s3_key_prefix": "p",
    "luks_disk_sha256_hex": "a" * 64,
    "kernel_sha256_hex": "b" * 64,
    "initrd_sha256_hex": "c" * 64,
    "luks_header_sha256_hex": "d" * 64,
    "flavor": "small",
    "cmdline": "console=ttyS0",
}


def _relaunch_fixture(monkeypatch: pytest.MonkeyPatch, disposition: str) -> Any:
    from apps.orchestration.services import vault_kv as vk

    from .test_reboot_recovery import _make_alive_miner

    vm = make_vm("vm-r")
    miner = _make_alive_miner()
    LaunchJob.objects.create(
        job_id="succ1",
        vm_id=vm.vm_id,
        tenant_id="tenant-1",
        flavor="small",
        spec_json=dict(_FULL_SPEC),
        userdata_vault_path="x/vm-r/userdata",
        userdata_vault_version=1,
        kek_vault_path="x/vm-r/luks-kek",
        state=LaunchJobState.SUCCEEDED.value,
        phase_started_at=timezone.now(),
        finished_at=timezone.now(),
        result_json={"emit": {"measurement_hex": A, "measured_cmdline": "c nonce=1"}},
        decided_by=make_service_client(),
    )
    monkeypatch.setattr(vk, "get_kv", lambda mount, path, version=None: b"user-data")
    monkeypatch.setattr(
        launch,
        "launch_on_miner",
        lambda spec, m, **_kw: SimpleNamespace(
            disposition=disposition,
            emit={"measurement_hex": B, "measured_cmdline": "c nonce=2"},
        ),
    )
    monkeypatch.setattr(service, "rebind_placement_to_host", lambda *a, **k: None)
    return vm, miner


@override_settings(VALI_REBOOT_RECOVERY_ENABLED=True)
def test_an_accepted_relaunch_records_the_new_boot(monkeypatch) -> None:
    vm, miner = _relaunch_fixture(monkeypatch, launch.ACCEPTED)
    assert service._reboot_recovery_relaunch(vm, miner.miner_id) is True
    emit = _emit("vm-r")
    assert (emit["measurement_hex"], emit["measured_cmdline"]) == (B, "c nonce=2")


@override_settings(VALI_REBOOT_RECOVERY_ENABLED=True)
def test_a_refused_relaunch_records_nothing(monkeypatch) -> None:
    vm, miner = _relaunch_fixture(monkeypatch, launch.RETRIABLE)
    assert service._reboot_recovery_relaunch(vm, miner.miner_id) is False
    assert _emit("vm-r")["measurement_hex"] == A


@override_settings(VALI_REBOOT_RECOVERY_ENABLED=True)
def test_a_failed_record_never_undoes_an_accepted_relaunch(monkeypatch) -> None:
    vm, miner = _relaunch_fixture(monkeypatch, launch.ACCEPTED)

    def boom(*_a: Any, **_k: Any) -> bool:
        raise RuntimeError("db down")

    logged: list[str] = []
    monkeypatch.setattr(launch_record, "record_relaunch", boom)
    monkeypatch.setattr(service.log, "exception", lambda msg, *a, **k: logged.append(msg % a))
    assert service._reboot_recovery_relaunch(vm, miner.miner_id) is True
    assert any("was NOT recorded" in m for m in logged)


# ── correct_measurement ──────────────────────────────────────────────


def test_a_correction_keeps_the_evidence_and_refuses_to_override_a_pin() -> None:
    vm = make_vm("vm-r")
    make_launch_record(vm, measurement_hex=A)
    assert (
        launch_record.correct_measurement(
            "vm-r",
            B,
            measured_cmdline="cmd B",
            reason="why",
            evidence={"kbs": B},
            expected_previous=A,
        )
        is True
    )
    emit = _emit("vm-r")
    assert emit["measurement_hex"] == B
    assert emit["superseded"][-1]["evidence"] == {"kbs": B}
    assert emit["measured_cmdline"] == "cmd B"
    assert emit["superseded"][-1]["previous"] == {"measurement_hex": A, "measured_cmdline": None}

    pinned = make_vm("vm-p")
    job = make_launch_record(pinned, measurement_hex=A)
    job.spec_json = {**job.spec_json, "measurement_hex": A}
    job.save()
    with pytest.raises(ValueError):
        launch_record.correct_measurement(
            "vm-p", B, measured_cmdline="cmd B", reason="why", evidence={}, expected_previous=A
        )
    assert _emit("vm-p")["measurement_hex"] == A


# ── vali_backfill_launch_measurement ─────────────────────────────────


def _evidence(monkeypatch: pytest.MonkeyPatch, bundles: dict[str, Any]) -> None:
    from apps.orchestration.services import kbs_evidence

    def fetch(vm_id: str) -> Any:
        b = bundles.get(vm_id)
        if isinstance(b, Exception):
            raise b
        return b

    monkeypatch.setattr(kbs_evidence, "fetch_evidence", fetch)


def _recompute(monkeypatch: pytest.MonkeyPatch, table: dict[str, Any]) -> None:
    """`cmdline -> digest` (or an exception) standing in for vali's C2
    launch-digest recompute."""
    from apps.orchestration.management.commands import vali_backfill_launch_measurement as cmd

    def recompute(vm: Any, cmdline: str, artifacts: Any = None) -> str:
        r = table[cmdline]
        if isinstance(r, Exception):
            raise r
        return r

    monkeypatch.setattr(cmd, "recompute_digest", recompute)


def _run(tmp_path: Any, digests: dict[str, str], cmdlines: dict[str, str], *args: str) -> str:
    d = tmp_path / "digests.json"
    d.write_text(json.dumps(digests))
    c = tmp_path / "cmdlines.json"
    c.write_text(json.dumps(cmdlines))
    out = StringIO()
    call_command(
        "vali_backfill_launch_measurement",
        "--miner-digests",
        str(d),
        "--miner-cmdlines",
        str(c),
        *args,
        stdout=out,
    )
    return out.getvalue()


def test_backfill_corrects_measurement_and_cmdline_when_everything_agrees(
    monkeypatch, tmp_path
) -> None:
    make_launch_record(make_vm("vm-stale"), measurement_hex=A, measured_cmdline="cmd A")
    make_launch_record(make_vm("vm-ok"), measurement_hex=C)
    _evidence(
        monkeypatch,
        {"vm-stale": {"measurement_hex": B, "boot_counter": 2}, "vm-ok": {"measurement_hex": C}},
    )
    _recompute(monkeypatch, {"cmd B": B})
    digests = {"vm-stale": B, "vm-ok": C}
    cmdlines = {"vm-stale": "cmd B"}

    out = _run(tmp_path, digests, cmdlines)
    assert "vm=vm-stale outcome=correct " in out
    assert "vm=vm-ok outcome=already-correct" in out
    assert _emit("vm-stale")["measurement_hex"] == A, "dry-run writes nothing"

    out = _run(tmp_path, digests, cmdlines, "--commit")
    assert "vm=vm-stale outcome=corrected" in out
    emit = _emit("vm-stale")
    assert (emit["measurement_hex"], emit["measured_cmdline"]) == (B, "cmd B")
    audit = emit["superseded"][-1]
    assert audit["previous"] == {"measurement_hex": A, "measured_cmdline": "cmd A"}
    assert audit["evidence"]["miner_adopt_digest"] == B
    assert audit["evidence"]["kbs_evidence"] == B
    assert audit["evidence"]["recomputed_from_cmdline"] == B
    assert _emit("vm-ok") == {"measurement_hex": C}


@pytest.mark.parametrize(
    ("bundle", "digest", "cmdline", "recompute", "outcome"),
    [
        ({"measurement_hex": B}, C, "cmd B", {"cmd B": B}, "sources-disagree"),
        ({"measurement_hex": "zz"}, "zz", "cmd B", {"cmd B": B}, "malformed-source"),
        ({"measurement_hex": B}, B, None, {}, "no-miner-cmdline"),
        ({"measurement_hex": B}, B, "cmd X", {"cmd X": C}, "cmdline-does-not-measure"),
        ({"measurement_hex": B}, B, "cmd B", {"cmd B": RuntimeError("s3")}, "recompute-failed"),
        (EffectUnavailable("kbs down"), B, "cmd B", {"cmd B": B}, "kbs-evidence-error"),
        (None, B, "cmd B", {"cmd B": B}, "no-kbs-evidence"),
        ({"measurement_hex": B}, None, "cmd B", {"cmd B": B}, "no-miner-digest"),
    ],
)
def test_backfill_never_writes_unless_every_proof_holds(
    monkeypatch, tmp_path, bundle, digest, cmdline, recompute, outcome
) -> None:
    from apps.orchestration.management.commands import vali_backfill_launch_measurement as cmd

    vm = make_vm("vm-x")
    make_launch_record(vm, measurement_hex=A, measured_cmdline="cmd A")
    _evidence(monkeypatch, {"vm-x": bundle})
    _recompute(monkeypatch, recompute)
    digests = {} if digest is None else {"vm-x": digest}
    cmdlines = {} if cmdline is None else {"vm-x": cmdline}
    assert cmd.verdict(vm, digests.get("vm-x"), cmdlines.get("vm-x"))[0] == outcome
    # Naming the VM makes every one of these a failure the operator sees.
    with pytest.raises(CommandError):
        _run(tmp_path, digests, cmdlines, "--commit", "--vm-id", "vm-x")
    assert (_emit("vm-x")["measurement_hex"], _emit("vm-x")["measured_cmdline"]) == (A, "cmd A")


def test_backfill_flags_a_named_vm_that_is_not_active_and_a_digest_for_no_vm(
    monkeypatch, tmp_path
) -> None:
    from apps.lifecycle.models import Vm, VmState

    vm = make_vm("vm-d")
    make_launch_record(vm, measurement_hex=A)
    Vm.objects.filter(pk=vm.pk).update(state=VmState.DESTROYED)
    _evidence(monkeypatch, {"vm-d": {"measurement_hex": B}})
    _recompute(monkeypatch, {"cmd B": B})
    with pytest.raises(CommandError):
        _run(tmp_path, {"vm-d": B}, {"vm-d": "cmd B"}, "--commit", "--vm-id", "vm-d")
    with pytest.raises(CommandError):
        _run(tmp_path, {"vm-typo": B}, {}, "--commit")
    assert _emit("vm-d")["measurement_hex"] == A


def test_backfill_ignores_vms_without_miner_input_when_none_is_named(monkeypatch, tmp_path) -> None:
    make_launch_record(make_vm("vm-other"), measurement_hex=A)
    _evidence(monkeypatch, {})
    _recompute(monkeypatch, {})
    out = _run(tmp_path, {}, {})
    assert "vm=vm-other outcome=no-miner-digest" in out
    assert "problems=0" in out


def test_a_correction_never_overwrites_a_record_that_moved_since_it_was_read() -> None:
    # A relaunch recorded C after the backfill read A: writing B now would
    # put the stale-record brick straight back.
    vm = make_vm("vm-r")
    make_launch_record(vm, measurement_hex=A)
    launch_record.record_relaunch("vm-r", {"measurement_hex": C}, reason="relaunch")
    with pytest.raises(ValueError):
        launch_record.correct_measurement(
            "vm-r", B, measured_cmdline="cmd B", reason="why", evidence={}, expected_previous=A
        )
    assert _emit("vm-r")["measurement_hex"] == C


@override_settings(VALI_REBOOT_RECOVERY_ENABLED=True)
@pytest.mark.parametrize(
    ("flavor", "supersede"), [("medium", True), ("medium", False), (None, False)]
)
def test_the_relaunch_supersedes_only_when_asked(monkeypatch, flavor, supersede) -> None:
    """Only a resize's first relaunch asks (`resize._relaunch`): its ticket
    tells the KBS to refuse the pre-resize launch from register on. Any
    other relaunch becomes current at its first release."""
    vm, miner = _relaunch_fixture(monkeypatch, launch.ACCEPTED)
    seen: list[bool] = []

    def _launch(spec, m, **kw):
        seen.append(kw.get("supersede", False))
        return SimpleNamespace(disposition=launch.ACCEPTED, emit={"measurement_hex": B})

    monkeypatch.setattr(launch, "launch_on_miner", _launch)
    service._reboot_recovery_relaunch(vm, miner.miner_id, flavor=flavor, supersede=supersede)
    assert seen == [supersede]
