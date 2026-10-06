"""The guest upgrade report (`apps.orchestration.guest_report`): the gauges
the `hippius-guest-upgrade` alerts read."""

from __future__ import annotations

from datetime import timedelta

import pytest
from django.core.management import call_command
from django.utils import timezone

from apps.lifecycle.models import Vm, VmPowerState
from apps.orchestration import guest_report, guest_rollout, guest_upgrade
from apps.orchestration.models import GuestComponentRelease, GuestUpgradeJob, GuestUpgradeState

from . import test_resize as rz
from .factories import make_service_client
from .test_guest_upgrade import _attest_measurement, _build

pytestmark = [pytest.mark.django_db]

S = GuestUpgradeState


@pytest.fixture(autouse=True)
def _c2(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(guest_upgrade, "_c2_enforced", lambda: True)


def _samples(name: str) -> list[tuple[dict[str, str], float]]:
    ms = guest_report.report_metrics()
    return [(s.labels, s.value) for s in ms.samples if s.name == name]


def test_rollouts_and_jobs_are_reported() -> None:
    vms = [rz._vm(f"vm-{i}", host=f"miner-{i}") for i in range(2)]
    _build(version=4, epoch=1, initrd="4a" * 32, health_mask=15)
    rollout = guest_rollout.create_rollout(
        release=4,
        canary_vm_ids=["vm-0"],
        scope={"vm_ids": [vm.vm_id for vm in vms]},
        decided_by=make_service_client(),
    )
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(guest_upgrade, "enabled", lambda: True)
        guest_rollout.tick_guest_rollouts()
    assert _samples(guest_report.M_ROLLOUT_STATE) == [
        ({"rollout": rollout.rollout_id, "release": "4", "state": "active"}, 1)
    ]
    assert _samples(guest_report.M_ROLLOUT_JOBS) == [
        ({"rollout": rollout.rollout_id, "state": "pending"}, 1)
    ]
    assert _samples(guest_report.M_JOBS) == [({"state": "pending"}, 1)]


def test_a_job_past_its_state_deadline_is_overdue() -> None:
    vm = rz._vm()
    build = _build(version=4, epoch=1, initrd="4a" * 32)
    job = guest_upgrade.start_guest_upgrade(vm=vm, build=build, decided_by=make_service_client())
    GuestUpgradeJob.objects.filter(pk=job.pk).update(
        state=S.PARKING, phase_started_at=timezone.now() - timedelta(hours=3)
    )
    ((labels, seconds),) = _samples(guest_report.M_OVERDUE)
    assert (labels["upgrade_job"], labels["state"]) == (job.job_id, "parking")
    assert "job" not in labels and "kind" not in labels, "Pushgateway grouping labels"
    assert seconds > 3600


def test_a_vm_behind_a_newer_or_more_secure_release_is_reported() -> None:
    """Since the BUILD for the VM's base exists — not since the release was
    first registered (for another base, days earlier)."""
    vm = rz._vm()
    b4 = _build(version=4, epoch=0, initrd="4a" * 32)
    b5 = _build(version=5, epoch=2, initrd="5a" * 32)
    GuestComponentRelease.objects.filter(version=5).update(
        registered_at=timezone.now() - timedelta(days=30)
    )
    behind = {labels["lag"]: value for labels, value in _samples(guest_report.M_BEHIND)}
    assert behind == {
        "release": min(b4.registered_at, b5.registered_at).timestamp(),
        "security": b5.registered_at.timestamp(),
    }
    assert vm


def test_a_build_for_another_base_initrd_is_not_behind() -> None:
    """A release built only on an initrd-only rebuild of the VM's base is
    not one the VM can move to."""
    rz._vm()
    _build(version=4, epoch=1, initrd="4a" * 32, base_initrd="4e" * 32, prefix="other-gr4")
    assert _samples(guest_report.M_BEHIND) == []
    b5 = _build(version=5, epoch=1, initrd="5a" * 32)
    assert {labels["lag"]: v for labels, v in _samples(guest_report.M_BEHIND)} == {
        "release": b5.registered_at.timestamp(),
        "security": b5.registered_at.timestamp(),
    }


def test_a_staged_swap_not_relaunched_is_still_behind() -> None:
    """The VM's record names release 4, but its running boot is the base."""
    vm = rz._vm()
    b4 = _build(version=4, epoch=1, initrd="4a" * 32)
    from apps.orchestration.services import launch_record

    record = launch_record.latest_record(vm.vm_id)
    launch_record.swap_initrd(
        vm.vm_id,
        new_prefix=b4.s3_key_prefix,
        new_initrd_sha256_hex=b4.initrd_sha256,
        expected_job_id=record.job_id,
        expected_prefix=rz.SPEC["s3_key_prefix"],
        expected_initrd_sha256_hex=rz.SPEC["initrd_sha256_hex"],
        expected_marker=None,
        reason="test",
        operator="test",
        evidence={},
    )
    lags = {labels["lag"] for labels, _ in _samples(guest_report.M_BEHIND)}
    assert lags == {"release", "security"}
    assert guest_upgrade.components_of(vm)["release"] is None


def test_a_superseded_guest_still_attesting_is_t4() -> None:
    from apps.telemetry.models import VmLiveAttestation

    vm = rz._vm()
    _attest_measurement(vm, "ab" * 48)
    VmLiveAttestation.objects.update(resource_verdict="superseded")
    assert _samples(guest_report.M_SUPERSEDED) == [({"vm": vm.vm_id, "node": rz.HOST_NODE}, 1)]


def test_a_live_attestation_after_a_completed_stop_is_t4() -> None:
    vm = rz._vm()
    stopped_at = timezone.now() - timedelta(minutes=30)
    Vm.objects.filter(pk=vm.pk).update(
        power_state=VmPowerState.STOPPED,
        power_state_at=stopped_at,
        power_stop_ordered_at=stopped_at,
    )
    assert _samples(guest_report.M_LIVE_ON_STOPPED) == []
    # The keepalive's last tick in flight at the stop is not a finding…
    _attest_measurement(vm, "ab" * 48, at=int(stopped_at.timestamp()) + 30)
    assert _samples(guest_report.M_LIVE_ON_STOPPED) == []
    # …a guest still attesting minutes later is.
    _attest_measurement(vm, "ab" * 48, at=int(stopped_at.timestamp()) + 900)
    assert _samples(guest_report.M_LIVE_ON_STOPPED) == [({"vm": vm.vm_id, "node": vm.host}, 1)]


def test_a_stop_that_was_not_a_completed_order_is_not_t4() -> None:
    """A VM settled `stopped` from a miner's "down" (a reboot) is not one
    the miner was ordered to stop."""
    vm = rz._vm()
    stopped_at = timezone.now() - timedelta(minutes=30)
    Vm.objects.filter(pk=vm.pk).update(power_state=VmPowerState.STOPPED, power_state_at=stopped_at)
    _attest_measurement(vm, "ab" * 48, at=int(stopped_at.timestamp()) + 900)
    assert _samples(guest_report.M_LIVE_ON_STOPPED) == []


def test_the_command_prints_without_pushing(capsys) -> None:
    call_command("vali_guest_report", "--no-push")
    assert guest_report.M_REPORT_TS in capsys.readouterr().out


def test_a_refused_push_fails_the_command(monkeypatch) -> None:
    from django.core.management.base import CommandError

    from apps.synthetic import metrics

    monkeypatch.setattr(metrics, "push", lambda *a, **k: False)
    with pytest.raises(CommandError):
        call_command("vali_guest_report")


def test_a_vm_left_blocked_is_reported_until_a_later_job_replaces_it() -> None:
    """Per VM, with what the alerts route on: its power (stopped = an
    outage), whether a tenant owns it, why the target failed and whose side
    that points at."""
    vm = rz._vm()
    Vm.objects.filter(pk=vm.pk).update(power_state=VmPowerState.STOPPED, tenant_id="tenant-1")
    build = _build(version=4, epoch=1, initrd="4a" * 32)
    job = guest_upgrade.start_guest_upgrade(vm=vm, build=build, decided_by=make_service_client())
    finished = timezone.now() - timedelta(hours=30)
    GuestUpgradeJob.objects.filter(pk=job.pk).update(
        state=S.UPGRADE_BLOCKED, outcome="no-sample", finished_at=finished
    )
    ((labels, since),) = _samples(guest_report.M_STUCK)
    assert labels == {
        "vm": vm.vm_id,
        "upgrade_job": job.job_id,
        "state": "upgrade_blocked",
        "outcome": "no-sample",
        "suspect": "miner",
        "power": "stopped",
        "tenant": "yes",
    }
    assert since == finished.timestamp(), "still reported past the 24 h outcome window"
    assert _samples(guest_report.M_FAILURES) == [], "ended 30 h ago"

    # A retry replaces it as the VM's latest job.
    GuestUpgradeJob.objects.create(
        job_id="gu-retry",
        vm=vm,
        target=build,
        previous_prefix="p",
        previous_initrd_sha256="i",
        node_id=vm.host,
        prior_power_state="stopped",
        state=S.DONE,
        not_before=timezone.now(),
        phase_started_at=timezone.now(),
        finished_at=timezone.now(),
        decided_by=make_service_client(),
        retry_of=job,
    )
    assert _samples(guest_report.M_STUCK) == []


def test_failures_are_counted_by_outcome_and_suspect() -> None:
    vms = [rz._vm(f"vm-{i}", host=f"miner-{i}") for i in range(3)]
    build = _build(version=4, epoch=1, initrd="4a" * 32)
    for vm, (state, outcome) in zip(
        vms,
        [
            (S.UPGRADE_BLOCKED, "health-failed"),
            (S.UPGRADE_BLOCKED, "no-sample"),
            (S.ROLLED_BACK, "no-sample"),
        ],
        strict=True,
    ):
        job = guest_upgrade.start_guest_upgrade(
            vm=vm, build=build, decided_by=make_service_client()
        )
        GuestUpgradeJob.objects.filter(pk=job.pk).update(
            state=state, outcome=outcome, finished_at=timezone.now()
        )
    failures = _samples(guest_report.M_FAILURES)
    assert sorted(failures, key=lambda s: (s[0]["state"], s[0]["outcome"])) == [
        ({"state": "rolled_back", "outcome": "no-sample", "suspect": "miner"}, 1),
        ({"state": "upgrade_blocked", "outcome": "health-failed", "suspect": "release"}, 1),
        ({"state": "upgrade_blocked", "outcome": "no-sample", "suspect": "miner"}, 1),
    ]
    stuck = {labels["vm"]: labels["suspect"] for labels, _ in _samples(guest_report.M_STUCK)}
    assert stuck == {"vm-0": "release", "vm-1": "miner"}, "a rolled-back VM needs no one"


@pytest.mark.usefixtures("_kbs_t4")
def test_only_the_kbs_reasons_naming_the_vms_own_guest_count() -> None:
    import time

    from apps.orchestration.models import KbsAuditEntry, MeasurementLedger

    now = int(time.time())
    seq = iter(range(1, 100))

    def _entry(
        vm: str,
        reason: str,
        *,
        at: int = now,
        granted: bool = False,
        ticket: str = "",
        chain_ok: bool = True,
    ) -> None:
        n = next(seq)
        KbsAuditEntry.objects.create(
            log="release",
            kbs_epoch="e" * 64,
            seq=n,
            body_cbor=b"",
            sha256=f"{n:064x}",
            prev_hash="0" * 64,
            fetched_at=timezone.now(),
            event_unix=at,
            op="release",
            vm_id=vm,
            ticket_id=ticket,
            reason=reason,
            granted=granted,
            chain_ok=chain_ok,
        )

    launch = "lifecycle: superseded-launch: the attested measurement is not the VM's current launch"
    guest = (
        "attestation: superseded-guest: the guest released for this vm_id before its "
        "current one still runs"
    )
    _entry("vm-a", launch)
    _entry("vm-a", guest)
    _entry("vm-a", guest)
    # Not findings:
    _entry("vm-a", "lifecycle: superseded-launch-unbound: identity not verified")
    _entry("vm-a", "attestation: keepalive guest is not the guest released for this vm_id")
    _entry("vm-a", launch, ticket="tk-1")  # a release denial, not a keepalive
    _entry("vm-a", launch, chain_ok=False)  # unverified audit entry
    _entry("vm-a", launch, at=now - 2 * 86400)  # outside the window
    # vm-b: inside the hand-over margin after its last launch transition.
    MeasurementLedger.objects.create(
        vm_id="vm-b",
        launch_digest_hex="ab" * 48,
        allowlist_epoch=1,
        launched_at=timezone.now() - timedelta(seconds=60),
    )
    _entry("vm-b", guest)
    # vm-c: an honest in-guest reboot — a release granted a minute ago
    # (new REPORT_ID, same launch); the old guest's in-flight request reads
    # superseded-guest and is not a finding.
    _entry("vm-c", "released", at=now - 60, granted=True, ticket="tk-reboot")
    _entry("vm-c", guest)
    got = sorted(
        (labels["vm"], labels["reason"], v) for labels, v in _samples(guest_report.M_KBS_SUPERSEDED)
    )
    assert got == [("vm-a", "superseded-guest", 2), ("vm-a", "superseded-launch", 1)]


@pytest.fixture
def _kbs_t4(settings) -> None:
    settings.VALI_GUEST_KBS_T4_ENABLED = True


def test_the_kbs_signal_is_off_until_enabled() -> None:
    from apps.orchestration.models import KbsAuditEntry

    KbsAuditEntry.objects.create(
        log="release",
        kbs_epoch="e" * 64,
        seq=1,
        body_cbor=b"",
        sha256="1" * 64,
        prev_hash="0" * 64,
        fetched_at=timezone.now(),
        event_unix=int(timezone.now().timestamp()),
        op="release",
        vm_id="vm-a",
        ticket_id="",
        granted=False,
        reason="attestation: superseded-guest: the guest released before still runs",
    )
    assert _samples(guest_report.M_KBS_SUPERSEDED) == []
