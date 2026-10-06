"""A relaunch the miner answers `already-launched` started nothing: the
domain up is the boot on record or an earlier dispatch answered as failed.
The launch record — what a §25 hop and a KBS recovery re-mint — never names
the retry's measurement: it waits for the guest's KBS-attested measurement,
refuses a KBS recovery of it meanwhile, and then names the boot that runs."""

from __future__ import annotations

import time
from typing import Any

import pytest
from django.test import override_settings

from apps.orchestration import service
from apps.orchestration.effects import EffectError
from apps.orchestration.models import MeasurementLedger
from apps.orchestration.services import launch, launch_record, migration_ticket

from .test_launch_record import A, B, C, _emit, _relaunch_fixture

pytestmark = pytest.mark.django_db

D = "d" * 96


def _boot(measurement: str, nonce: int) -> dict[str, Any]:
    return {"measurement_hex": measurement, "measured_cmdline": f"c nonce={nonce}"}


def _outcome(disposition: str, boot: dict[str, Any], **emit: Any) -> launch.LaunchOutcome:
    return launch.LaunchOutcome(
        disposition=disposition,
        emit={**boot, launch.DISPATCHED_BOOT_KEY: boot, **emit},
        exit_code=0,
        registered=True,
    )


def _answers(monkeypatch: pytest.MonkeyPatch, *outcomes: launch.LaunchOutcome) -> None:
    queue = list(outcomes)
    monkeypatch.setattr(launch, "launch_on_miner", lambda spec, m, **_kw: queue.pop(0))


def _remint(vm: Any, miner: Any) -> str:
    """What a §25 hop / KBS recovery re-mints (`resolve_ticket_inputs`)."""
    from apps.miners.models import MinerIdentity

    MinerIdentity.objects.filter(miner_id=miner.miner_id).update(platform_id="11" * 64)
    vm.host = miner.miner_id
    with override_settings(VALI_VAULT_KV_PREFIX="x"):
        return migration_ticket.resolve_ticket_inputs(
            vm, node_id=miner.miner_id, generation=vm.generation
        ).measurement_hex


def _attests(vm_id: str, measurement: str, *, at: float | None = None) -> None:
    """A live attestation verified at `at` (default: past the skew window
    after now, as a keepalive minutes after the answer is)."""
    from apps.telemetry.models import VmLiveAttestation
    from apps.telemetry.vm_liveness import _skew_seconds

    now = int(at if at is not None else time.time() + _skew_seconds() + 5)
    VmLiveAttestation.objects.create(
        vm_id=vm_id,
        node_id_hex="00" * 32,
        attestation_seq=1,
        epoch=1,
        observed_at_unix=now,
        verified_at_unix=now,
        expiry_unix=now + 600,
        measurement=measurement,
        snp_report_digest="0" * 64,
        body_digest=f"{measurement[:8]}{now:056x}",
    )


@override_settings(VALI_REBOOT_RECOVERY_ENABLED=True)
def test_the_dispatch_that_booted_is_recorded_once_its_guest_attests(monkeypatch) -> None:
    """B timed out at the Edge but booted, C was refused without booting, D
    is answered `already-launched`. The guest attests B: B is recorded —
    not D (the retry), not C (the latest failure)."""
    vm, miner = _relaunch_fixture(monkeypatch, launch.ACCEPTED)
    MeasurementLedger.objects.create(vm_id=vm.vm_id, launch_digest_hex=B, allowlist_epoch=1)
    _answers(
        monkeypatch,
        _outcome(launch.TERMINAL, _boot(B, 2), outcome="edge-unreachable"),
        _outcome(launch.RETRIABLE, _boot(C, 3), outcome="miner-rejected"),
        _outcome(launch.ACCEPTED, _boot(D, 4), classifier="already-launched"),
    )
    assert service._reboot_recovery_relaunch(vm, miner.miner_id) is False
    assert service._reboot_recovery_relaunch(vm, miner.miner_id) is False
    assert _emit(vm.vm_id)["measurement_hex"] == A, "a refused dispatch is not the boot"
    assert service._reboot_recovery_relaunch(vm, miner.miner_id) is True
    assert _emit(vm.vm_id)["measurement_hex"] == A, "never the already-launched retry's"
    with pytest.raises(EffectError, match="attests"):
        launch_record.assert_boot_verified(vm.vm_id)

    assert service.sweep_unverified_boots() == 0, "no attestation yet"
    _attests(vm.vm_id, B)
    assert service.sweep_unverified_boots() == 1
    emit = _emit(vm.vm_id)
    assert (emit["measurement_hex"], emit["measured_cmdline"]) == (B, "c nonce=2")
    assert launch_record.DISPATCHED_BOOTS_KEY not in emit
    assert launch_record.BOOT_UNVERIFIED_KEY not in emit
    launch_record.assert_boot_verified(vm.vm_id)
    assert _remint(vm, miner) == B
    assert MeasurementLedger.objects.get(launch_digest_hex=B).launched_at is not None


@override_settings(VALI_REBOOT_RECOVERY_ENABLED=True)
def test_the_boot_on_record_attesting_settles_it_as_it_was(monkeypatch) -> None:
    """Nothing dispatched since came up: the guest attests the recorded A."""
    vm, miner = _relaunch_fixture(monkeypatch, launch.ACCEPTED)
    _answers(
        monkeypatch,
        _outcome(launch.TERMINAL, _boot(B, 2), outcome="edge-unreachable"),
        _outcome(launch.ACCEPTED, _boot(C, 3), classifier="already-launched"),
    )
    service._reboot_recovery_relaunch(vm, miner.miner_id)
    service._reboot_recovery_relaunch(vm, miner.miner_id)
    _attests(vm.vm_id, A)
    assert service.sweep_unverified_boots() == 1
    assert _emit(vm.vm_id)["measurement_hex"] == A
    assert _remint(vm, miner) == A


@pytest.mark.parametrize("ago", [3600, 0])
@override_settings(VALI_REBOOT_RECOVERY_ENABLED=True)
def test_an_attestation_within_the_skew_of_the_answer_decides_nothing(monkeypatch, ago) -> None:
    """Even one verified in the same second: the boot on record may have
    taken it before it stopped (KBS clock up to the ingest skew ahead)."""
    vm, miner = _relaunch_fixture(monkeypatch, launch.ACCEPTED)
    _attests(vm.vm_id, A, at=time.time() - ago)
    _answers(monkeypatch, _outcome(launch.ACCEPTED, _boot(C, 3), classifier="already-launched"))
    service._reboot_recovery_relaunch(vm, miner.miner_id)
    assert service.sweep_unverified_boots() == 0
    with pytest.raises(EffectError, match="attests"):
        launch_record.assert_boot_verified(vm.vm_id)


@override_settings(VALI_REBOOT_RECOVERY_ENABLED=True)
def test_an_unknown_attested_boot_leaves_the_record_unverified(monkeypatch) -> None:
    vm, miner = _relaunch_fixture(monkeypatch, launch.ACCEPTED)
    _answers(monkeypatch, _outcome(launch.ACCEPTED, _boot(C, 3), classifier="already-launched"))
    service._reboot_recovery_relaunch(vm, miner.miner_id)
    _attests(vm.vm_id, C)
    assert service.sweep_unverified_boots() == 0
    assert _emit(vm.vm_id)["measurement_hex"] == A
    with pytest.raises(EffectError, match="attests"):
        launch_record.assert_boot_verified(vm.vm_id)


@override_settings(VALI_REBOOT_RECOVERY_ENABLED=True)
def test_a_new_boot_records_itself_and_drops_the_candidates(monkeypatch) -> None:
    vm, miner = _relaunch_fixture(monkeypatch, launch.ACCEPTED)
    _answers(
        monkeypatch,
        _outcome(launch.RETRIABLE, _boot(B, 2), outcome="miner-rejected"),
        _outcome(launch.ACCEPTED, _boot(C, 3), classifier="launched"),
    )
    service._reboot_recovery_relaunch(vm, miner.miner_id)
    assert service._reboot_recovery_relaunch(vm, miner.miner_id) is True
    emit = _emit(vm.vm_id)
    assert emit["measurement_hex"] == C
    assert launch_record.DISPATCHED_BOOTS_KEY not in emit
    assert _remint(vm, miner) == C


@override_settings(VALI_REBOOT_RECOVERY_ENABLED=True)
def test_an_attempt_refused_before_its_dispatch_keeps_nothing(monkeypatch) -> None:
    vm, miner = _relaunch_fixture(monkeypatch, launch.ACCEPTED)
    refused = launch.LaunchOutcome(
        disposition=launch.RETRIABLE, emit={"outcome": "preflight-failure"}, exit_code=1
    )
    _answers(monkeypatch, refused)
    assert service._reboot_recovery_relaunch(vm, miner.miner_id) is False
    assert launch_record.DISPATCHED_BOOTS_KEY not in _emit(vm.vm_id)


def test_a_same_miner_retry_in_one_launch_waits_for_the_attested_boot() -> None:
    """`launch_vm`'s same-miner retry answered `already-launched`: the
    launch's emit (the record to be) keeps the earlier dispatches and waits."""
    out = _outcome(launch.ACCEPTED, _boot(C, 3), classifier="already-launched")
    candidates = [launch_record.dispatched_boot_candidate(_boot(B, 2), booted=None, flavor=None)]
    launch._await_the_attested_boot("vm-x", out, candidates)
    assert out.emit[launch_record.BOOT_UNVERIFIED_KEY]
    assert out.emit[launch_record.DISPATCHED_BOOTS_KEY][0]["boot"]["measurement_hex"] == B
    assert launch.answered_already_launched(out)


@pytest.mark.parametrize("dispatch", ["timeout", "rejected"])
def test_every_dispatched_outcome_names_what_it_booted(monkeypatch, dispatch: str) -> None:
    """An Edge timeout and a miner refusal may both have booted: each
    carries the boot it dispatched."""
    from apps.orchestration import order_dispatch
    from apps.orchestration.tests.test_launch_service import (
        _fake_the_launch_choreography,
        _register_miner,
        _spec,
    )

    _fake_the_launch_choreography(monkeypatch, dispatch_ok=False)
    if dispatch == "timeout":

        def _timeout(*a: Any, **k: Any) -> Any:
            raise order_dispatch.OrderDispatchUnavailable("POST timed out")

        monkeypatch.setattr(order_dispatch, "dispatch_order", _timeout)
    out = launch.launch_on_miner(
        _spec(userdata=b"#cloud-config\n# {{NETBIRD_SETUP_KEY}}\n"), _register_miner(1)
    )
    assert out.disposition != launch.ACCEPTED and out.registered
    boot = out.emit[launch.DISPATCHED_BOOT_KEY]
    assert len(boot["measurement_hex"]) == 96
    assert boot["measured_cmdline"]


@override_settings(VALI_REBOOT_RECOVERY_ENABLED=True)
def test_settling_on_an_earlier_dispatch_drops_the_ones_that_never_ran(monkeypatch) -> None:
    """B settles as current: A before it, and C / D pinned after it but never
    run, all leave the allowlist."""
    from apps.orchestration.services import allowlist_pin

    vm, miner = _relaunch_fixture(monkeypatch, launch.ACCEPTED)
    for measurement in (A, B, C, D):
        MeasurementLedger.objects.create(
            vm_id=vm.vm_id, launch_digest_hex=measurement, allowlist_epoch=1
        )
    MeasurementLedger.objects.filter(launch_digest_hex=A).update(launched_at=_an_hour_ago())
    _answers(
        monkeypatch,
        _outcome(launch.TERMINAL, _boot(B, 2), outcome="edge-unreachable"),
        _outcome(launch.RETRIABLE, _boot(C, 3), outcome="miner-rejected"),
        _outcome(launch.ACCEPTED, _boot(D, 4), classifier="already-launched"),
    )
    for _ in range(3):
        service._reboot_recovery_relaunch(vm, miner.miner_id)
    assert {r.launch_digest_hex for r in allowlist_pin.pending_superseded_pins()} == set()
    _attests(vm.vm_id, B)
    service.sweep_unverified_boots()
    assert {r.launch_digest_hex for r in allowlist_pin.pending_superseded_pins()} == {A, C, D}


def _an_hour_ago() -> Any:
    from datetime import timedelta

    from django.utils import timezone

    return timezone.now() - timedelta(hours=1)


@override_settings(VALI_REBOOT_RECOVERY_ENABLED=True)
def test_an_operator_correction_settles_the_record(monkeypatch) -> None:
    vm, miner = _relaunch_fixture(monkeypatch, launch.ACCEPTED)
    _answers(monkeypatch, _outcome(launch.ACCEPTED, _boot(C, 3), classifier="already-launched"))
    service._reboot_recovery_relaunch(vm, miner.miner_id)
    launch_record.correct_measurement(
        vm.vm_id,
        B,
        measured_cmdline="c nonce=2",
        reason="operator",
        evidence={"kbs": "release of B"},
        expected_previous=A,
    )
    launch_record.assert_boot_verified(vm.vm_id)
    assert launch_record.DISPATCHED_BOOTS_KEY not in _emit(vm.vm_id)


def test_a_re_posted_launch_carries_the_failed_jobs_dispatches() -> None:
    """A launch job that failed at the Edge may have booted; a re-POSTed
    launch answered `already-launched` meets it."""
    from django.utils import timezone

    from apps.orchestration.models import LaunchJob, LaunchJobState

    from .factories import make_service_client

    LaunchJob.objects.create(
        job_id="failed1",
        vm_id="vm-re",
        tenant_id="tenant-1",
        flavor="small",
        spec_json={},
        userdata_vault_path="x",
        userdata_vault_version=1,
        kek_vault_path="x",
        state=LaunchJobState.FAILED.value,
        phase_started_at=timezone.now(),
        finished_at=timezone.now(),
        result_json={
            "emit": {
                launch_record.DISPATCHED_BOOTS_KEY: [
                    launch_record.dispatched_boot_candidate(
                        _boot(B, 2), booted=("p", "c" * 64), flavor="small"
                    )
                ]
            }
        },
        decided_by=make_service_client(),
    )
    (candidate,) = launch._earlier_dispatched_boots("vm-re")
    assert candidate["boot"]["measurement_hex"] == B
    assert (candidate["flavor"], candidate["booted"]) == ("small", ["p", "c" * 64])


@override_settings(VALI_REBOOT_RECOVERY_ENABLED=True)
def test_the_boot_on_record_attesting_drops_the_dispatches_that_never_ran(monkeypatch) -> None:
    from apps.orchestration.services import allowlist_pin

    vm, miner = _relaunch_fixture(monkeypatch, launch.ACCEPTED)
    MeasurementLedger.objects.create(vm_id=vm.vm_id, launch_digest_hex=A, allowlist_epoch=1)
    MeasurementLedger.objects.filter(launch_digest_hex=A).update(launched_at=_an_hour_ago())
    for measurement in (B, C):
        MeasurementLedger.objects.create(
            vm_id=vm.vm_id, launch_digest_hex=measurement, allowlist_epoch=1
        )
    _answers(
        monkeypatch,
        _outcome(launch.TERMINAL, _boot(B, 2), outcome="edge-unreachable"),
        _outcome(launch.ACCEPTED, _boot(C, 3), classifier="already-launched"),
    )
    service._reboot_recovery_relaunch(vm, miner.miner_id)
    service._reboot_recovery_relaunch(vm, miner.miner_id)
    _attests(vm.vm_id, A)
    assert service.sweep_unverified_boots() == 1
    assert {r.launch_digest_hex for r in allowlist_pin.pending_superseded_pins()} == {B, C}


def test_backfill_settles_a_waiting_record_when_both_sources_name_it(monkeypatch, tmp_path) -> None:
    from .factories import make_launch_record, make_vm
    from .test_launch_record import _evidence, _run

    make_launch_record(make_vm("vm-w"), measurement_hex=A, measured_cmdline="cmd A")
    launch_record.mark_boot_unverified("vm-w")
    _evidence(monkeypatch, {"vm-w": {"measurement_hex": A}})
    assert "vm=vm-w outcome=settle " in _run(tmp_path, {"vm-w": A}, {})
    assert "vm=vm-w outcome=settled" in _run(tmp_path, {"vm-w": A}, {}, "--commit")
    launch_record.assert_boot_verified("vm-w")


@override_settings(VALI_REBOOT_RECOVERY_ENABLED=True)
def test_a_recorded_boot_is_the_current_launch_whoever_stamped_last(monkeypatch) -> None:
    """A settlement stamping the older boot cannot outlast a genuine
    relaunch that records after it: recording stamps under the same lock."""
    vm, miner = _relaunch_fixture(monkeypatch, launch.ACCEPTED)
    for measurement in (A, C):
        MeasurementLedger.objects.create(
            vm_id=vm.vm_id, launch_digest_hex=measurement, allowlist_epoch=1
        )
    launch_record._stamp_current_launch(vm.vm_id, A)
    launch_record.record_relaunch(vm.vm_id, _boot(C, 3), reason="relaunch")
    current = MeasurementLedger.objects.exclude(launched_at=None).order_by("-launched_at").first()
    assert current.launch_digest_hex == C


def test_an_operator_correction_is_the_current_launch() -> None:
    from .factories import make_launch_record, make_vm

    make_launch_record(make_vm("vm-c"), measurement_hex=A, measured_cmdline="cmd A")
    MeasurementLedger.objects.create(vm_id="vm-c", launch_digest_hex=B, allowlist_epoch=1)
    launch_record.correct_measurement(
        "vm-c", B, measured_cmdline="cmd B", reason="op", evidence={}, expected_previous=A
    )
    assert MeasurementLedger.objects.get(launch_digest_hex=B).launched_at is not None
