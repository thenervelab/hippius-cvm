"""Guest upgrade — after the job failed (`apps.orchestration.guest_upgrade`,
docs/operator/guest-upgrade-recovery.md).

The same fake miner as `test_guest_upgrade`. Each test pins one claim:

1. an operator restarts a blocked VM on the TARGET — audited, through the
   power API with a KBS supersede — and never below the floor, never with a
   domain possibly up, never around a newer job;
2. a retry of a blocked VM (the same build, or a newer release) restarts
   the VM the blocked job left stopped and verifies it; a failing retry
   blocks again — the previous set is never launched;
3. a failure says WHY (`outcome`), from the evidence;
4. the CLI and the API expose all of it.
"""

from __future__ import annotations

from io import StringIO

import pytest
from django.core.management import CommandError, call_command
from django.utils import timezone

from apps.lifecycle.models import Vm, VmPowerState
from apps.orchestration import guest_upgrade
from apps.orchestration.models import (
    GuestInitrdBuild,
    GuestUpgradeJob,
    GuestUpgradeState,
    VmGuestComponents,
)
from apps.orchestration.service import StartError
from apps.orchestration.services import guest_components, launch, power

from . import test_resize as rz
from .test_guest_upgrade import (
    BASE_INITRD,
    BASE_PREFIX,
    HEALTHY,
    SETTINGS,
    UpgradeMiner,
    _attest_latest_launch,
    _attest_measurement,
    _build,
    _expire,
    _health_build,
    _job,
    _record,
    _start,
    _tick,
    _to_verifying,
    _ViewClient,
)

pytestmark = [pytest.mark.django_db]

S = GuestUpgradeState
EPOCH = 3


@pytest.fixture(autouse=True)
def _settings(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(guest_upgrade, "_c2_enforced", lambda: True)
    with SETTINGS:
        yield


@pytest.fixture(autouse=True)
def _hosts() -> None:
    rz._miner(rz.HOST, rz.HOST_NODE)


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


def _blocked(vm: Vm, fake: UpgradeMiner, build: GuestInitrdBuild | None = None) -> GuestUpgradeJob:
    """An epoch-raising upgrade whose target never attests: parked, then
    `upgrade_blocked` with the VM stopped on the target."""
    build = build or _build(epoch=EPOCH)
    job = _to_verifying(vm, build)
    _expire(job)
    _tick(4)  # timeout → parking → stop → DOWN → upgrade_blocked
    job = _job(vm)
    assert job.state == S.UPGRADE_BLOCKED, job.reason
    vm.refresh_from_db()
    assert vm.power_state == VmPowerState.STOPPED and fake.domain_running is False
    assert _record(vm) == (build.s3_key_prefix, build.initrd_sha256)
    return job


def _recover(job: GuestUpgradeJob, **kw: str) -> dict:
    return guest_upgrade.recover_start_on_target(
        job, operator=kw.get("operator", "ops-1"), reason=kw.get("reason", "tenant outage")
    )


def _no_previous_set(fake: UpgradeMiner) -> None:
    assert BASE_INITRD not in [launch_["initrd"] for launch_ in fake.launches[1:]], (
        "the previous set (below the floor) is never launched again"
    )


# ─── claim 1: start on target ────────────────────────────────────────


def test_an_operator_restarts_a_blocked_vm_on_the_target(miner) -> None:
    vm = rz._vm()
    build = _build(epoch=EPOCH)
    job = _blocked(vm, miner, build)
    entry = _recover(job)

    vm.refresh_from_db()
    assert vm.power_state == VmPowerState.RUNNING
    last = miner.launches[-1]
    assert (last["initrd"], last["supersede"]) == (build.initrd_sha256, True), (
        "the target, superseding every earlier launch at register"
    )
    job.refresh_from_db()
    assert job.state == S.UPGRADE_BLOCKED, "not gated: the job stays as it ended"
    assert job.recoveries == [entry]
    assert (entry["by"], entry["reason"], entry["result"]) == ("ops-1", "tenant outage", "started")
    attempt = job.attempt_rows.get(kind="operator_start")
    assert (str(attempt.id), attempt.outcome) == (entry["attempt"], "accepted")
    assert attempt.measurement == last["measurement"], "linked to the pin of THAT start"
    epochs = VmGuestComponents.objects.get(vm=vm)
    assert (epochs.required_epoch, epochs.attested_epoch) == (EPOCH, 0)
    _no_previous_set(miner)


def test_a_recovery_needs_an_operator_and_a_reason(miner) -> None:
    vm = rz._vm()
    job = _blocked(vm, miner)
    for who, why in (("", "x"), ("ops-1", " ")):
        with pytest.raises(StartError) as exc:
            guest_upgrade.recover_start_on_target(job, operator=who, reason=why)
        assert exc.value.category == "wire"
    assert len(miner.launches) == 1


def test_a_recovery_never_starts_a_domain_possibly_up(miner, monkeypatch) -> None:
    from apps.orchestration import effects

    vm = rz._vm()
    job = _blocked(vm, miner)
    miner.domain_running = True
    with pytest.raises(StartError) as exc:
        _recover(job)
    assert exc.value.category == "domain-running"
    monkeypatch.setattr(effects, "poll_domain_running", lambda vm: None)
    with pytest.raises(StartError) as exc:
        _recover(job)
    assert exc.value.category == "domain-unknown"
    assert len(miner.launches) == 1
    assert job.attempt_rows.filter(kind="operator_start").count() == 0


def test_a_recovery_never_goes_below_the_floor(miner) -> None:
    vm = rz._vm()
    job = _blocked(vm, miner)
    guest_components.raise_required_epoch(vm, EPOCH + 1, by="test", reason="a later fix")
    with pytest.raises(StartError) as exc:
        _recover(job)
    assert exc.value.category == "below-floor"
    assert len(miner.launches) == 1


@pytest.mark.parametrize(
    ("setup", "category"),
    [
        ("c2-off", "c2-not-enforced"),
        ("withdrawn", "build-withdrawn"),
        ("running", "vm-not-stopped"),
        ("newer-job", "superseded"),
    ],
)
def test_a_recovery_is_refused_when_it_cannot_be_done_safely(
    miner, monkeypatch, setup: str, category: str
) -> None:
    vm = rz._vm()
    job = _blocked(vm, miner)
    if setup == "c2-off":
        monkeypatch.setattr(guest_upgrade, "_c2_enforced", lambda: False)
    elif setup == "withdrawn":
        GuestInitrdBuild.objects.filter(pk=job.target_id).update(withdrawn_at=timezone.now())
    elif setup == "running":
        Vm.objects.filter(pk=vm.pk).update(power_state=VmPowerState.RUNNING)
    else:
        _start(vm, job.target)
        _tick()  # the retry took the vm
        assert _job(vm).state == S.STOPPING
    with pytest.raises(StartError) as exc:
        _recover(job)
    assert exc.value.category == category, exc.value.message
    assert len(miner.launches) == 1


def test_a_parking_job_is_not_recovered(miner) -> None:
    vm = rz._vm()
    job = _to_verifying(vm, _build(epoch=EPOCH))
    _expire(job)
    _tick()
    job = _job(vm)
    assert job.state == S.PARKING
    with pytest.raises(StartError) as exc:
        _recover(job)
    assert exc.value.category == "parking"


def test_a_failed_rollback_is_recovered_onto_the_target_by_a_swap(miner) -> None:
    """A same-epoch target whose rollback failed: the record names the
    previous set again — the recovery CAS-swaps it onto the target."""
    vm = rz._vm()
    build = _build(epoch=0)
    job = _to_verifying(vm, build)
    _expire(job)
    miner.disposition = launch.RETRIABLE
    for _ in range(12):
        _tick()
        if _job(vm).state == S.FAILED:
            break
    job = _job(vm)
    assert job.state == S.FAILED, job.reason
    assert _record(vm) == (BASE_PREFIX, BASE_INITRD)
    miner.disposition = launch.ACCEPTED
    _recover(job)
    assert _record(vm) == (build.s3_key_prefix, build.initrd_sha256)
    assert miner.launches[-1]["initrd"] == build.initrd_sha256


def test_a_refused_start_that_may_have_landed_holds_the_vm_until_it_settled(
    miner, monkeypatch
) -> None:
    """Answered as refused after the order may have gone out: the attempt
    stays open and the VM `starting` — never `stopped`, not even for an
    instant — so no second start (a recovery, a retry, a plain start)
    dispatches over it until it settled with the domain DOWN."""
    from datetime import timedelta

    vm = rz._vm()
    job = _blocked(vm, miner)
    miner.disposition = launch.RETRIABLE
    written: list[str] = []
    real_set_power = power._set_power

    def set_power(vm_: Vm, state: str, **kw) -> None:
        written.append(state)
        real_set_power(vm_, state, **kw)

    monkeypatch.setattr(power, "_set_power", set_power)
    with pytest.raises(StartError) as exc:
        _recover(job)
    assert exc.value.category == "relaunch-rejected"
    assert written == [VmPowerState.STARTING], "the claim, and nothing after it"
    job.refresh_from_db()
    assert job.recoveries[-1]["result"] == "unsettled:relaunch-rejected"
    attempt = job.attempt_rows.get(kind="operator_start")
    assert (attempt.outcome, attempt.answer) == ("", "relaunch-rejected")
    vm.refresh_from_db()
    assert vm.power_state == VmPowerState.STARTING
    with pytest.raises(power.PowerOpRefused):
        power.start_vm(vm)
    miner.disposition = launch.ACCEPTED
    with pytest.raises(StartError) as exc:
        _recover(job)
    assert exc.value.category == "start-settling"
    assert len(miner.launches) == 2

    # The marker went stale and the dispatch settled with the domain DOWN.
    Vm.objects.filter(pk=vm.pk).update(power_state_at=timezone.now() - timedelta(minutes=11))
    _recover(job)
    attempt.refresh_from_db()
    assert attempt.outcome == "refused:relaunch-rejected"
    vm.refresh_from_db()
    assert vm.power_state == VmPowerState.RUNNING
    assert len(miner.launches) == 3


def test_a_superseded_job_does_not_settle_its_open_starts(miner) -> None:
    """Once a later job took the VM, a domain up is that job's — the old
    recovery start is not judged on it."""
    from apps.orchestration.models import GuestUpgradeAttempt

    vm = rz._vm()
    build = _build(epoch=EPOCH)
    job = _blocked(vm, miner, build)
    open_start = GuestUpgradeAttempt.objects.create(
        job=job, kind="operator_start", prefix="p", initrd_sha256=build.initrd_sha256
    )
    _start(vm, build)
    _tick(4)  # the retry took the vm and relaunched it
    miner.domain_running = True
    with pytest.raises(StartError) as exc:
        _recover(job)
    assert exc.value.category == "superseded"
    open_start.refresh_from_db()
    assert open_start.outcome == ""


def test_a_definite_refusal_leaves_the_vm_stopped(miner, monkeypatch) -> None:
    def busy(*_a, **_kw):
        raise power.PowerOpRefused(power.PIN_BUSY_REASON, "pin busy")

    vm = rz._vm()
    job = _blocked(vm, miner)
    monkeypatch.setattr(power, "start_vm", busy)
    with pytest.raises(StartError) as exc:
        _recover(job)
    assert exc.value.category == power.PIN_BUSY_REASON
    assert job.attempt_rows.get(kind="operator_start").outcome == "lost"


def test_the_recovery_start_is_claimed_with_the_swap(miner, monkeypatch) -> None:
    """No other start can take the VM between the decision (and the record
    swap) and the dispatch: the claim commits with them."""
    vm = rz._vm()
    job = _blocked(vm, miner)
    real = power.start_vm
    seen: list[str] = []

    def start(vm_: Vm, **kw):
        seen.append(Vm.objects.get(pk=vm_.pk).power_state)
        with pytest.raises(power.PowerOpRefused) as exc:
            real(Vm.objects.get(pk=vm_.pk))  # a plain start racing it
        assert exc.value.reason == "already-starting"
        return real(vm_, **kw)

    monkeypatch.setattr(power, "start_vm", start)
    _recover(job)
    assert seen == [VmPowerState.STARTING]


# ─── claim 2: retry ──────────────────────────────────────────────────


def test_a_retry_of_the_same_build_restarts_the_stopped_vm_and_verifies_it(miner) -> None:
    vm = rz._vm()
    build = _build(epoch=EPOCH)
    blocked = _blocked(vm, miner, build)
    retry = _start(vm, build)
    assert retry.retry_of_id == blocked.pk
    assert (retry.previous_initrd_sha256, retry.previous_epoch) == (BASE_INITRD, 0), (
        "the blocked job's previous set, not the target"
    )
    _tick(4)  # pending (stopped VM taken) → stopping → launching → verifying
    job = _job(vm)
    assert job.state == S.VERIFYING, job.reason
    assert (miner.launches[-1]["initrd"], miner.launches[-1]["supersede"]) == (
        build.initrd_sha256,
        True,
    )
    _attest_latest_launch(vm, miner)
    _tick(2)
    job = _job(vm)
    assert job.state == S.DONE, job.reason
    assert VmGuestComponents.objects.get(vm=vm).attested_epoch == EPOCH
    _no_previous_set(miner)


def test_a_failing_retry_blocks_again_and_never_launches_the_previous_set(miner) -> None:
    vm = rz._vm()
    build = _build(epoch=EPOCH)
    _blocked(vm, miner, build)
    _start(vm, build)
    _tick(4)
    _expire(_job(vm))
    _tick(4)
    job = _job(vm)
    assert job.state == S.UPGRADE_BLOCKED, job.reason
    assert job.outcome == guest_upgrade.NO_SAMPLE
    assert "rollback forbidden" in job.reason
    _no_previous_set(miner)
    assert guest_components.required_epoch(vm.vm_id) == EPOCH


def test_a_retry_onto_a_newer_release_from_a_blocked_vm(miner) -> None:
    vm = rz._vm()
    first = _build(epoch=EPOCH)
    blocked = _blocked(vm, miner, first)
    newer = _build(version=2, epoch=EPOCH, initrd="88" * 32)
    job = _start(vm, newer)
    assert job.retry_of_id == blocked.pk
    assert job.previous_initrd_sha256 == first.initrd_sha256
    _tick(4)
    _attest_latest_launch(vm, miner)
    _tick(2)
    job = _job(vm)
    assert job.state == S.DONE, job.reason
    assert _record(vm) == (newer.s3_key_prefix, newer.initrd_sha256)


def test_a_retry_after_a_recovery_upgrades_the_running_vm(miner) -> None:
    vm = rz._vm()
    build = _build(epoch=EPOCH)
    job = _blocked(vm, miner, build)
    _recover(job)
    retry = _start(vm, build)
    assert retry.retry_of_id == job.pk
    _tick(4)
    _attest_latest_launch(vm, miner)
    _tick(2)
    assert _job(vm).state == S.DONE, _job(vm).reason


def test_a_vm_someone_stopped_after_the_block_waits_for_its_next_start(miner) -> None:
    vm = rz._vm()
    build = _build(epoch=EPOCH)
    job = _blocked(vm, miner, build)
    _recover(job)
    vm.refresh_from_db()
    power.stop_vm(vm)  # the tenant's choice, after the block
    _start(vm, build)
    _tick(3)
    retry = _job(vm)
    assert retry.state == S.PENDING, "a VM stopped on purpose is not started by a retry"
    launches = len(miner.launches)
    _tick()
    assert len(miner.launches) == launches


def test_a_retry_of_a_block_that_never_stopped_the_vm_upgrades_it(miner) -> None:
    """The stop never took: blocked with the VM still running the previous
    set and the record naming it — the retry is a plain upgrade."""
    vm = rz._vm()
    build = _build(epoch=EPOCH)
    _start(vm, build)
    miner.stop_error = RuntimeError("edge 502")
    _tick(3)
    _expire(_job(vm))
    _tick()
    # The abandoned stop settles to what the miner runs: the old guest.
    Vm.objects.filter(pk=vm.pk).update(power_state=VmPowerState.RUNNING)
    blocked = _job(vm)
    assert blocked.state == S.UPGRADE_BLOCKED, blocked.reason
    assert blocked.outcome == guest_upgrade.STOP_TIMEOUT
    assert _record(vm) == (BASE_PREFIX, BASE_INITRD)
    miner.stop_error = None
    retry = _start(vm, build)
    assert retry.retry_of_id == blocked.pk
    _tick(4)
    _attest_latest_launch(vm, miner)
    _tick(2)
    assert _job(vm).state == S.DONE, _job(vm).reason
    assert _record(vm) == (build.s3_key_prefix, build.initrd_sha256)


def test_a_cancelled_retry_leaves_the_blocked_job_in_charge(miner) -> None:
    from datetime import timedelta

    vm = rz._vm()
    build = _build(epoch=EPOCH)
    job = _blocked(vm, miner, build)
    retry = _start(vm, build, not_before=timezone.now() + timedelta(days=1))
    assert guest_upgrade.anchor_job(vm).pk == job.pk, "a pending retry has not taken the vm"
    guest_upgrade.cancel_pending(retry, by="ops-1")
    assert guest_upgrade.blocked_job(vm).pk == job.pk
    again = _start(vm, build)
    assert again.retry_of_id == job.pk
    guest_upgrade.cancel_pending(again, by="ops-1")
    _recover(job)  # still recoverable
    assert Vm.objects.get(pk=vm.pk).power_state == VmPowerState.RUNNING


def test_a_pending_retry_does_not_hide_the_outage(miner) -> None:
    from datetime import timedelta

    from apps.orchestration import guest_report

    vm = rz._vm()
    build = _build(epoch=EPOCH)
    job = _blocked(vm, miner, build)
    _start(vm, build, not_before=timezone.now() + timedelta(days=1))
    stuck = [
        s.labels for s in guest_report.report_metrics().samples if s.name == guest_report.M_STUCK
    ]
    assert [(labels["upgrade_job"], labels["power"]) for labels in stuck] == [
        (job.job_id, "stopped")
    ]
    assert guest_upgrade.components_of(vm)["needs_operator"]["job_id"] == job.job_id
    _recover(job)  # the operator may restore service before the window


def test_without_a_blocked_job_the_same_build_is_still_refused(miner) -> None:
    vm = rz._vm()
    build = _build(epoch=1)
    _to_verifying(vm, build)
    _attest_latest_launch(vm, miner)
    _tick(2)
    assert _job(vm).state == S.DONE
    with pytest.raises(StartError) as exc:
        _start(vm, build)
    assert exc.value.category == "already-on-target"


# ─── claim 3: why ────────────────────────────────────────────────────


def test_a_gate_timeout_with_only_another_boot_attesting_is_a_measurement_mismatch(
    miner,
) -> None:
    vm = rz._vm()
    job = _to_verifying(vm, _build(epoch=0))
    _attest_measurement(vm, "ee" * 48)
    _expire(job)
    _tick()
    job = _job(vm)
    assert job.outcome == guest_upgrade.MEASUREMENT_MISMATCH, job.reason
    assert guest_upgrade.OUTCOME_SUSPECT[job.outcome] == "miner"


def test_a_gate_timeout_with_the_target_unhealthy_names_the_missing_checks(miner) -> None:
    vm = rz._vm()
    job = _to_verifying(vm, _health_build())
    m = miner.launches[-1]["measurement"]
    _attest_measurement(vm, m, **{**HEALTHY, "health": 0b0011, "unhealthy_ticks": 0})
    _expire(job)
    _tick()
    job = _job(vm)
    assert job.outcome == guest_upgrade.HEALTH_FAILED, job.reason
    assert "misses checks 0xc (bits 2,3)" in job.reason
    assert guest_upgrade.OUTCOME_SUSPECT[job.outcome] == "release"


def test_rejected_relaunches_are_a_dispatch_failure(miner) -> None:
    vm = rz._vm()
    _start(vm, _build(epoch=EPOCH))
    miner.disposition = launch.RETRIABLE
    for _ in range(8):
        _tick()
        if _job(vm).outcome:
            break
    assert _job(vm).outcome == guest_upgrade.DISPATCH_FAILED, _job(vm).reason


# ─── claim 4: the CLI and the API ────────────────────────────────────


def test_the_command_recovers_after_a_dry_run_and_shows_why(miner) -> None:
    vm = rz._vm()
    job = _blocked(vm, miner)
    args = [f"--vm-id={vm.vm_id}", "--recover=start-on-target"]
    with pytest.raises(CommandError, match="--operator and --reason"):
        call_command("vali_guest_upgrade", *args)
    out = StringIO()
    audit = ["--operator=ops-1", "--reason=tenant outage"]
    call_command("vali_guest_upgrade", *args, *audit, stdout=out)
    assert "dry-run" in out.getvalue() and len(miner.launches) == 1
    out = StringIO()
    call_command("vali_guest_upgrade", *args, *audit, "--apply", stdout=out)
    assert "recovered" in out.getvalue() and "NOT health-verified" in out.getvalue()
    assert len(miner.launches) == 2
    out = StringIO()
    call_command("vali_guest_upgrade", f"--vm-id={vm.vm_id}", "--status", stdout=out)
    status = out.getvalue()
    assert f"{job.job_id} v1 upgrade_blocked outcome=no-sample suspect=miner" in status
    assert "recovery start-on-target by=ops-1" in status and "result=started" in status
    assert "operator_start accepted" in status


class TestRecoveryViews(_ViewClient):
    def test_recover_retry_and_components(self, client, miner) -> None:
        vm = rz._vm()
        job = _blocked(vm, miner)
        body = client.get(f"/v1/vm/{vm.vm_id}/guest-components").json()
        assert body["needs_operator"]["job_id"] == job.job_id
        assert (body["needs_operator"]["outcome"], body["needs_operator"]["suspect"]) == (
            "no-sample",
            "miner",
        )
        url = f"/v1/vm/{vm.vm_id}/guest-upgrade/{job.job_id}/recover"
        for bad in ({}, {"action": "start-on-target"}, {"action": "nope", "reason": "x"}):
            r = client.post(url, bad, format="json")
            assert (r.status_code, r.json()["category"]) == (400, "wire"), bad
        miner.domain_running = True
        r = client.post(url, {"action": "start-on-target", "reason": "outage"}, format="json")
        assert (r.status_code, r.json()["category"]) == (409, "domain-running")
        miner.domain_running = False
        r = client.post(url, {"action": "start-on-target", "reason": "outage"}, format="json")
        assert r.status_code == 200, r.content
        assert r.json()["recoveries"][0]["by"] == "orchestration-root"
        assert r.json()["recoveries"][0]["result"] == "started"
        # The same release again: a retry of the blocked job.
        r = client.post(f"/v1/vm/{vm.vm_id}/guest-upgrade", {"release": 1}, format="json")
        assert r.status_code == 202, r.content
        assert r.json()["retry_of"] == job.job_id
        assert client.post(f"/v1/vm/{vm.vm_id}/guest-upgrade/nope/recover").status_code == 400
        r = client.post(
            f"/v1/vm/{vm.vm_id}/guest-upgrade/nope/recover",
            {"action": "start-on-target", "reason": "x"},
            format="json",
        )
        assert r.status_code == 404
