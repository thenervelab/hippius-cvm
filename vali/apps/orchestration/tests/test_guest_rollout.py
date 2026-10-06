"""Guest rollouts (`apps.orchestration.guest_rollout`,
docs/design/guest-component-rollout.md, "`GuestRollout`").

The rollout only admits jobs and watches them, so these tests drive the
rollout tick alone and settle its jobs by hand (each job's own run is
`test_guest_upgrade`'s). Claims:

1. creation refuses what it cannot do — listing the VMs without a build;
2. canaries first, then cumulative percentages of the rest, fixed when a
   wave starts, after the wave pause;
3. at most `max_concurrent` VMs at a time, one per miner; a pending job on
   a stopped VM holds no slot and does not keep its wave open;
4. it stops on a canary outcome but done, a failed / blocked job, or too
   many rollbacks; resume acknowledges; abort cancels pending jobs.
"""

from __future__ import annotations

from typing import Any

import pytest
from django.test import override_settings
from django.utils import timezone

from apps.lifecycle.models import Vm, VmPowerState
from apps.orchestration import guest_rollout, guest_upgrade
from apps.orchestration.models import (
    GuestRollout,
    GuestUpgradeJob,
    GuestUpgradeState,
)

from . import test_resize as rz
from .factories import make_service_client
from .test_guest_upgrade import _build

pytestmark = [pytest.mark.django_db]

S = GuestUpgradeState


@pytest.fixture(autouse=True)
def _settings(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(guest_upgrade, "_c2_enforced", lambda: True)
    with override_settings(VALI_GUEST_UPGRADE_ENABLED=True):
        yield


@pytest.fixture(autouse=True)
def _hosts() -> None:
    rz._miner(rz.HOST, rz.HOST_NODE)


def _fleet(n: int, *, same_host: bool = False) -> list[Vm]:
    return [
        rz._vm(f"vm-{i:02d}", host="miner-a" if same_host else f"miner-{i:02d}") for i in range(n)
    ]


def _release(health_mask: int = 15) -> int:
    _build(version=4, epoch=1, initrd="4a" * 32, health_mask=health_mask)
    return 4


def _create(**kw: Any) -> GuestRollout:
    args: dict[str, Any] = {
        "release": 4,
        "canary_vm_ids": ["vm-00"],
        "scope": {"vm_ids": list(Vm.objects.values_list("vm_id", flat=True))},
        "decided_by": make_service_client(),
        "wave_pause_s": 0,
    }
    args.update(kw)
    return guest_rollout.create_rollout(**args)


def _tick(n: int = 1) -> None:
    for _ in range(n):
        guest_rollout.tick_guest_rollouts()


def _jobs(rollout: GuestRollout, wave: int | None = None) -> list[GuestUpgradeJob]:
    qs = GuestUpgradeJob.objects.filter(rollout=rollout).select_related("vm")
    if wave is not None:
        qs = qs.filter(wave=wave)
    return list(qs.order_by("vm__vm_id"))


def _settle(job: GuestUpgradeJob, state: str) -> None:
    GuestUpgradeJob.objects.filter(pk=job.pk).update(state=state, finished_at=timezone.now())


def _r(rollout: GuestRollout) -> GuestRollout:
    rollout.refresh_from_db()
    return rollout


# ─── claim 1: creation ───────────────────────────────────────────────


def test_creation_refuses_what_it_cannot_do() -> None:
    _fleet(3)
    with pytest.raises(guest_rollout.RolloutRefused) as refused:
        _create()
    assert refused.value.category == "unknown-release"
    _release(health_mask=0)
    with pytest.raises(guest_rollout.RolloutRefused) as refused:
        _create()
    assert refused.value.category == "no-health-leg", "a release without health checks"
    with pytest.raises(guest_rollout.RolloutRefused) as refused:
        _create(scope={})
    assert refused.value.category == "wire", "an empty scope would be every VM"
    with pytest.raises(guest_rollout.RolloutRefused) as refused:
        _create(scope={"vm_ids": []})
    assert refused.value.category == "wire"
    for waves in ([], [25, 25, 100], [50, 25, 100], [25, 50]):
        with pytest.raises(guest_rollout.RolloutRefused):
            _create(scope={"vm_ids": ["vm-00"]}, waves=waves)
    assert _create(scope={"vm_ids": ["vm-00"]}).state == "active", "…is canaries only"


def test_a_vm_without_a_build_is_listed_and_refuses_the_rollout() -> None:
    _fleet(3)
    _release()
    from apps.orchestration.models import LaunchJob

    LaunchJob.objects.filter(vm_id="vm-02").update(
        spec_json={**rz.SPEC, "vm_id": "vm-02", "kernel_sha256_hex": "ef" * 32}
    )
    with pytest.raises(guest_rollout.RolloutRefused) as refused:
        _create()
    assert (refused.value.category, refused.value.missing) == ("missing-builds", ["vm-02"])


def test_a_vm_belongs_to_one_open_rollout() -> None:
    _fleet(2)
    _release()
    first = _create(scope={"vm_ids": ["vm-00"]})
    _tick()
    assert len(_jobs(first)) == 1
    with pytest.raises(guest_rollout.RolloutRefused) as refused:
        _create(scope={"vm_ids": ["vm-00", "vm-01"]})
    assert refused.value.category == "vm-in-rollout"


# ─── claim 2: waves ──────────────────────────────────────────────────


def test_canaries_then_cumulative_percentages_of_the_rest() -> None:
    _fleet(9)
    _release()
    rollout = _create(waves=[25, 100], max_concurrent=10)
    _tick()
    (canary,) = _jobs(rollout)
    assert (canary.vm.vm_id, canary.wave) == ("vm-00", 0)
    _tick()
    assert _r(rollout).current_wave == 0, "the canary is still running"
    _settle(canary, S.DONE)
    _tick(2)  # wave complete → (pause 0) → wave 1 takes ceil(8 * 25%) = 2
    rollout = _r(rollout)
    assert rollout.current_wave == 1 and rollout.population == 8
    assert rollout.members == [f"vm-{i:02d}" for i in range(1, 9)]
    assert rollout.assigned["1"] == ["vm-01", "vm-02"]
    _tick()
    assert [j.vm.vm_id for j in _jobs(rollout, 1)] == ["vm-01", "vm-02"]
    for job in _jobs(rollout, 1):
        _settle(job, S.DONE)
    _tick(3)
    rollout = _r(rollout)
    assert rollout.current_wave == 2
    assert rollout.assigned["2"] == [f"vm-{i:02d}" for i in range(3, 9)]
    for job in _jobs(rollout, 2):
        _settle(job, S.DONE)
    _tick(3)
    assert _r(rollout).state == "done"


def test_members_are_fixed_at_creation() -> None:
    """A VM that joins the selector later is not upgraded by the rollout."""
    _fleet(3)
    _release()
    rollout = _create(scope={"node_ids": ["miner-00", "miner-01", "miner-02", "miner-09"]})
    rz._vm("vm-09", host="miner-09")  # joins after the rollout was created
    assert _r(rollout).members == ["vm-01", "vm-02"]
    _tick()
    _settle(_jobs(rollout)[0], S.DONE)
    _tick(3)
    assert "vm-09" not in _r(rollout).assigned["1"]


def test_the_next_wave_waits_for_the_wave_pause() -> None:
    _fleet(3)
    _release()
    rollout = _create(waves=[100], wave_pause_s=3600)
    _tick()
    _settle(_jobs(rollout)[0], S.DONE)
    _tick(3)
    assert _r(rollout).current_wave == 0
    GuestRollout.objects.filter(pk=rollout.pk).update(
        wave_done_at=timezone.now() - timezone.timedelta(hours=2)
    )
    _tick()
    assert _r(rollout).current_wave == 1


# ─── claim 3: concurrency ────────────────────────────────────────────


def test_at_most_max_concurrent_and_one_per_miner() -> None:
    vms = _fleet(5, same_host=True)
    _release()
    rollout = _create(canary_vm_ids=["vm-00", "vm-01"], waves=[100], max_concurrent=2)
    _tick(2)
    assert len(_jobs(rollout)) == 1, "both canaries are on one miner: one at a time"
    _settle(_jobs(rollout)[0], S.DONE)
    _tick()
    assert len(_jobs(rollout)) == 2
    assert vms


def test_a_pending_job_on_a_stopped_vm_holds_no_slot_and_closes_its_wave() -> None:
    _fleet(3)
    _release()
    rollout = _create(canary_vm_ids=["vm-00", "vm-01"], waves=[100], max_concurrent=1)
    Vm.objects.filter(vm_id="vm-00").update(power_state=VmPowerState.STOPPED)
    _tick()
    (first,) = _jobs(rollout)
    assert first.vm.vm_id == "vm-00" and first.state == S.PENDING
    _tick()
    assert len(_jobs(rollout)) == 2, "the stopped VM's job does not hold the slot"
    _settle(_jobs(rollout)[1], S.DONE)
    _tick(3)
    rollout = _r(rollout)
    assert rollout.current_wave == 1, "a job pending on a stopped VM does not hold the wave"
    _tick(3)
    assert _r(rollout).state == "active", "…but the rollout is not done while it waits"
    assert guest_rollout.serialize_rollout(rollout)["jobs"]["0"] == {
        "pending-stopped": 1,
        "done": 1,
    }


# ─── claim 4: stop / resume / abort ──────────────────────────────────


@pytest.mark.parametrize("outcome", [S.ROLLED_BACK, S.FAILED, S.UPGRADE_BLOCKED, S.CANCELLED])
def test_a_canary_that_is_not_done_stops_the_rollout(outcome: str) -> None:
    _fleet(3)
    _release()
    rollout = _create(waves=[100])
    _tick()
    _settle(_jobs(rollout)[0], outcome)
    _tick(2)
    rollout = _r(rollout)
    assert rollout.state == "paused" and "canary vm-00" in rollout.paused_reason
    assert len(_jobs(rollout)) == 1, "no new job while paused"

    guest_rollout.resume(rollout)
    _tick(3)
    rollout = _r(rollout)
    assert rollout.state == "active", "resume acknowledged it"
    assert rollout.current_wave == 0, "…but no canary was upgraded: nothing else starts"
    assert len(_jobs(rollout)) == 1


def test_too_many_rollbacks_in_a_wave_stop_it() -> None:
    _fleet(11)
    _release()
    rollout = _create(waves=[100], max_concurrent=10, max_failure_ratio=0.1)
    _tick()
    _settle(_jobs(rollout)[0], S.DONE)
    _tick(3)
    jobs = _jobs(rollout, 1)
    assert len(jobs) == 10
    _settle(jobs[0], S.ROLLED_BACK)
    _tick()
    assert _r(rollout).state == "active", "1 of 10 is not above 10%"
    _settle(jobs[1], S.ROLLED_BACK)
    _tick()
    rollout = _r(rollout)
    assert rollout.state == "paused" and "2/10 rolled back" in rollout.paused_reason


def test_abort_cancels_the_pending_jobs_only() -> None:
    _fleet(4)
    _release()
    rollout = _create(
        canary_vm_ids=["vm-00", "vm-01"],
        waves=[100],
        not_before=timezone.now() + timezone.timedelta(days=1),
    )
    _tick()
    jobs = _jobs(rollout)
    assert {j.state for j in jobs} == {S.PENDING}
    GuestUpgradeJob.objects.filter(pk=jobs[0].pk).update(state=S.STOPPING)
    assert guest_rollout.abort(rollout, by="ops") == 1
    states = sorted(j.state for j in _jobs(rollout))
    assert states == [S.CANCELLED, S.STOPPING]
    assert _r(rollout).state == "aborted"


def test_the_tick_is_off_without_the_flag() -> None:
    _fleet(2)
    _release()
    rollout = _create()
    with override_settings(VALI_GUEST_UPGRADE_ENABLED=False):
        assert guest_rollout.tick_guest_rollouts() == 0
    assert _jobs(rollout) == []


# ─── the API ─────────────────────────────────────────────────────────


class TestViews:
    @pytest.fixture
    def client(self):
        from rest_framework.test import APIClient

        from apps.identity.models import ServiceClient

        c = APIClient()
        c.force_authenticate(
            user=ServiceClient.objects.create(name="orchestration-root", scope="operator")
        )
        return c

    @pytest.fixture(autouse=True)
    def _root(self, monkeypatch):
        from apps.orchestration import permissions

        monkeypatch.setattr(permissions.IsOrchestrationRoot, "has_permission", lambda *a: True)

    def test_start_read_pause_resume_abort(self, client) -> None:
        _fleet(3)
        _release()
        r = client.post(
            "/v1/guest-rollouts",
            {
                "release": 4,
                "canary_vm_ids": ["vm-00"],
                "scope": {"vm_ids": ["vm-00", "vm-01", "vm-02"]},
                "waves": [50, 100],
            },
            format="json",
        )
        assert r.status_code == 201, r.content
        rollout_id = r.json()["rollout_id"]
        r = client.get(f"/v1/guest-rollouts/{rollout_id}")
        assert r.status_code == 200 and r.json()["state"] == "active"
        for action, state in (("pause", "paused"), ("resume", "active"), ("abort", "aborted")):
            r = client.post(f"/v1/guest-rollouts/{rollout_id}/{action}")
            assert (r.status_code, r.json()["state"]) == (200, state), r.content
        r = client.post(f"/v1/guest-rollouts/{rollout_id}/resume")
        assert r.status_code == 409

    def test_refusals(self, client) -> None:
        _fleet(3)
        _release()
        from apps.orchestration.models import LaunchJob

        LaunchJob.objects.filter(vm_id="vm-02").update(
            spec_json={**rz.SPEC, "vm_id": "vm-02", "kernel_sha256_hex": "ef" * 32}
        )
        r = client.post(
            "/v1/guest-rollouts",
            {"release": 4, "canary_vm_ids": ["vm-00"], "scope": {"node_ids": ["miner-02"]}},
            format="json",
        )
        assert r.status_code == 409 and r.json()["vm_ids"] == ["vm-02"], r.content
        r = client.post(
            "/v1/guest-rollouts",
            {"release": 4, "canary_vm_ids": ["vm-00"], "scope": None},
            format="json",
        )
        assert (r.status_code, r.json()["category"]) == (400, "wire")
        r = client.post("/v1/guest-rollouts", {"release": 4}, format="json")
        assert (r.status_code, r.json()["category"]) == (400, "wire")
        r = client.post(
            "/v1/guest-rollouts",
            {"release": 4, "canary_vm_ids": ["vm-00"], "scope": {"distro": ["x"]}},
            format="json",
        )
        assert (r.status_code, r.json()["category"]) == (400, "wire")
        assert client.get("/v1/guest-rollouts/nope").status_code == 404


def test_a_parked_job_starts_only_with_the_rollouts_leave() -> None:
    """A job parked on a stopped VM does not start behind a pause, nor next
    to another guest upgrade on its miner."""
    _fleet(2)
    _release()
    rollout = _create(canary_vm_ids=["vm-00"], waves=[100])
    Vm.objects.filter(vm_id="vm-00").update(power_state=VmPowerState.STOPPED)
    _tick()
    (job,) = _jobs(rollout)
    guest_rollout.pause(rollout, "ops")
    job.refresh_from_db()
    assert guest_rollout.may_start(job).endswith("is paused")
    guest_rollout.resume(rollout)
    other = rz._vm("vm-50", host=job.node_id)
    GuestUpgradeJob.objects.create(
        job_id="gu-other",
        vm=other,
        target=job.target,
        previous_prefix="p",
        previous_initrd_sha256="0" * 64,
        node_id=job.node_id,
        prior_power_state="running",
        state=S.VERIFYING,
        not_before=timezone.now(),
        phase_started_at=timezone.now(),
        decided_by=make_service_client(),
    )
    assert "runs another guest upgrade" in guest_rollout.may_start(job)


def test_an_admission_refusal_stops_the_rollout() -> None:
    _fleet(3)
    _release()
    rollout = _create(waves=[100])
    _tick()
    _settle(_jobs(rollout)[0], S.DONE)
    from apps.orchestration.models import LaunchJob

    LaunchJob.objects.filter(vm_id="vm-01").update(
        spec_json={**rz.SPEC, "vm_id": "vm-01", "disk_mode": "legacy_luks"}
    )
    _tick(4)
    rollout = _r(rollout)
    assert rollout.state == "paused" and "vm-01 not admitted" in rollout.paused_reason


def test_a_withdrawn_release_stops_the_rollout() -> None:
    _fleet(2)
    _release()
    rollout = _create()
    from apps.orchestration.models import GuestComponentRelease

    GuestComponentRelease.objects.filter(version=4).update(withdrawn_at=timezone.now())
    _tick()
    rollout = _r(rollout)
    assert rollout.state == "paused" and "withdrawn" in rollout.paused_reason
    assert _jobs(rollout) == []


def test_a_rollout_whose_canaries_are_all_skipped_stops() -> None:
    _fleet(2)
    _release()
    rollout = _create()
    from apps.orchestration.models import LaunchJob

    LaunchJob.objects.filter(vm_id="vm-00").update(
        spec_json={**rz.SPEC, "vm_id": "vm-00", "disk_mode": "legacy_luks"}
    )
    _tick()
    assert _r(rollout).state == "paused"


def test_a_late_rollback_in_a_closed_wave_still_counts() -> None:
    """A job parked on a stopped VM closes its wave, runs later and rolls
    back once the next wave is under way: its wave's ratio still sees it."""
    _fleet(5)
    _release()
    rollout = _create(waves=[50, 100], max_concurrent=4, max_failure_ratio=0.4)
    _tick()
    _settle(_jobs(rollout)[0], S.DONE)  # the canary
    _tick(3)
    assert _r(rollout).assigned["1"] == ["vm-01", "vm-02"]
    Vm.objects.filter(vm_id="vm-01").update(power_state=VmPowerState.STOPPED)
    _tick()
    wave1 = {j.vm.vm_id: j for j in _jobs(rollout, 1)}
    _settle(wave1["vm-02"], S.DONE)
    _tick(3)
    assert _r(rollout).current_wave == 2, "the parked job let wave 1 close"
    _settle(wave1["vm-01"], S.ROLLED_BACK)
    _tick()
    rollout = _r(rollout)
    assert rollout.state == "paused" and rollout.paused_reason == "wave 1: 1/2 rolled back"


def test_a_member_that_left_the_scope_is_skipped() -> None:
    _fleet(3)
    _release()
    rollout = _create(scope={"node_ids": ["miner-00", "miner-01", "miner-02"]}, waves=[100])
    Vm.objects.filter(vm_id="vm-02").update(host="miner-77")
    _tick()
    _settle(_jobs(rollout)[0], S.DONE)
    _tick(4)
    rollout = _r(rollout)
    assert rollout.skipped["vm-02"]["category"] == "left-scope"
    assert rollout.state == "active"
    assert "vm-02" not in [j.vm.vm_id for j in _jobs(rollout)]


def test_one_guest_upgrade_per_miner_holds_for_jobs_outside_rollouts_too() -> None:
    """A standalone job (the backend's) waits while a rollout's job holds a
    VM on the same miner, and the other way round."""
    vms = _fleet(2, same_host=True)
    build = guest_upgrade.build_for_vm(vms[0], _release())
    holder = guest_upgrade.start_guest_upgrade(
        vm=vms[0], build=build, decided_by=make_service_client()
    )
    GuestUpgradeJob.objects.filter(pk=holder.pk).update(state=S.VERIFYING)
    waiting = guest_upgrade.start_guest_upgrade(
        vm=vms[1], build=build, decided_by=make_service_client()
    )
    assert "runs another guest upgrade" in guest_rollout.may_start(waiting)
    _settle(holder, S.DONE)
    assert guest_rollout.may_start(waiting) == ""


def test_a_pending_job_does_not_start_past_a_stop_the_rollout_has_not_seen_yet() -> None:
    _fleet(3)
    _release()
    rollout = _create(canary_vm_ids=["vm-00", "vm-01"], waves=[100])
    _tick()
    jobs = {j.vm.vm_id: j for j in _jobs(rollout)}
    _settle(jobs["vm-00"], S.FAILED)  # this tick's outcome, not yet seen
    assert "must stop" in guest_rollout.may_start(jobs["vm-01"])


def test_rollbacks_stay_counted_across_a_resume() -> None:
    """A resume acknowledges the stop, not the failures: the next rollback
    is judged with the earlier ones."""
    _fleet(11)
    _release()
    rollout = _create(waves=[100], max_concurrent=10, max_failure_ratio=0.15)
    _tick()
    _settle(_jobs(rollout)[0], S.DONE)
    _tick(3)
    jobs = _jobs(rollout, 1)
    _settle(jobs[0], S.ROLLED_BACK)
    _tick()
    assert _r(rollout).state == "active", "1/10 is under 15%"
    guest_rollout.pause(rollout, "ops look")
    guest_rollout.resume(rollout)
    _settle(jobs[1], S.ROLLED_BACK)
    _tick()
    rollout = _r(rollout)
    assert rollout.state == "paused" and "2/10 rolled back" in rollout.paused_reason


def test_a_job_whose_vm_left_the_scope_is_cancelled_as_it_starts_and_does_not_stop() -> None:
    _fleet(3)
    _release()
    rollout = _create(scope={"node_ids": ["miner-00", "miner-01", "miner-02"]}, waves=[100])
    _tick()
    _settle(_jobs(rollout)[0], S.DONE)
    _tick(4)
    job = [j for j in _jobs(rollout, 1) if j.vm.vm_id == "vm-01"][0]
    vm = Vm.objects.get(vm_id="vm-01")
    # The VM's tenant moves it to another selector between admission and
    # its window (a node outside the scope, same host id on the job).
    from apps.orchestration.models import GuestRollout as GR

    GR.objects.filter(pk=rollout.pk).update(scope={"node_ids": ["miner-00", "miner-02"]})
    assert guest_rollout.out_of_scope(job, vm)
    guest_upgrade.advance_guest_upgrade(job)
    job.refresh_from_db()
    assert job.state == S.CANCELLED and job.reason.startswith("left-scope")
    _tick()
    assert _r(rollout).state == "active"


def test_a_moved_canary_stops_the_rollout() -> None:
    """A canary cancelled because its VM moved is no evidence: with no
    canary done, the rollout stops instead of waiting forever."""
    _fleet(2)
    _release()
    rollout = _create()
    _tick()
    (canary,) = _jobs(rollout)
    GuestUpgradeJob.objects.filter(pk=canary.pk).update(
        state=S.CANCELLED,
        reason="vm-changed: vm is active on 'miner-99'",
        finished_at=timezone.now(),
    )
    _tick()
    rollout = _r(rollout)
    assert rollout.state == "paused", rollout.paused_reason
