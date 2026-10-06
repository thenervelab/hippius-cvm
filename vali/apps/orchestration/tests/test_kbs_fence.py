"""§24 KBS decommission fence (`VALI_KBS_FENCE_ENABLED`).

Claims pinned here:

- flag OFF ⇒ not one KBS fence call, and the teardown is otherwise identical;
- flag ON ⇒ the fence lands right after the ticket freeze, BEFORE the
  crypto-erase, and the destroy tombstones the KBS row at the VM generation;
- a failing fence holds the erase back, but only for the (step-timeout
  clamped) window — then the erase proceeds and the job is marked `pending`;
- the hold never applies once the erase already happened;
- the sweep re-drives `pending` (tombstone for a destroyed VM, fence for a
  decommissioning one), spaced out, and never re-drives a `conflict`.
"""

from __future__ import annotations

from datetime import timedelta

import pytest
from django.conf import settings
from django.utils import timezone

from apps.lifecycle.models import VmState
from apps.orchestration import service
from apps.orchestration.models import DecommissionJob, DecommissionState, KbsFence

from .conftest import FakeEffects
from .factories import make_service_client, make_vm

pytestmark = pytest.mark.django_db


@pytest.fixture(autouse=True)
def _fresh_kbs_call_budget() -> None:
    service._reset_kbs_fence_budget()


@pytest.fixture
def fence_on(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "VALI_KBS_FENCE_ENABLED", True)
    monkeypatch.setattr(settings, "VALI_KBS_FENCE_WINDOW_S", 30.0)


@pytest.fixture
def fast_retry(monkeypatch: pytest.MonkeyPatch) -> None:
    """Drop the per-job retry spacing so a test can watch several attempts."""
    monkeypatch.setattr(service, "_KBS_FENCE_RETRY_EVERY_S", 0.0)


def _drive(limit: int = 25) -> None:
    for _ in range(limit):
        service.tick_once()


def _names(fx: FakeEffects) -> list[str]:
    return [c[0] for c in fx.calls]


def _start(vm_id: str = "vm-1", generation: int = 5) -> DecommissionJob:
    vm = make_vm(vm_id, generation=generation, host="node-src")
    return service.start_decommission(vm=vm, decided_by=make_service_client())


def _age_job(job: DecommissionJob, seconds: float) -> None:
    then = timezone.now() - timedelta(seconds=seconds)
    DecommissionJob.objects.filter(id=job.id).update(started_at=then, phase_started_at=then)


def _to_crypto_erasing(job: DecommissionJob) -> None:
    for _ in range(10):
        service.tick_once()
        job.refresh_from_db()
        if job.state == DecommissionState.CRYPTO_ERASING.value:
            return
    raise AssertionError(f"stuck at {job.state}")


# ─── flag off ────────────────────────────────────────────────────────


def test_flag_off_makes_no_kbs_call_and_changes_nothing_else(
    fx: FakeEffects, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(settings, "VALI_KBS_FENCE_ENABLED", False)
    job = _start()
    _drive()
    job.refresh_from_db()
    assert job.state == DecommissionState.DONE.value
    assert job.vm.state == VmState.DESTROYED
    assert not fx.did("kbs_fence_decommission")
    assert not fx.did("kbs_tombstone")
    assert job.kbs_fence == KbsFence.NONE.value
    assert job.kbs_fence_at is None
    off_calls = _names(fx)

    # Same teardown with the flag on: exactly the same effects, plus the KBS
    # calls — the flag only ADDS the fence.
    fx.calls.clear()
    monkeypatch.setattr(settings, "VALI_KBS_FENCE_ENABLED", True)
    job2 = _start("vm-2")
    _drive()
    job2.refresh_from_db()
    assert job2.state == DecommissionState.DONE.value
    assert [n for n in _names(fx) if not n.startswith("kbs_")] == off_calls


def test_flag_off_sweep_is_a_noop_even_with_pending_rows(
    fx: FakeEffects, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(settings, "VALI_KBS_FENCE_ENABLED", False)
    job = _start()
    DecommissionJob.objects.filter(id=job.id).update(kbs_fence=KbsFence.PENDING)
    assert service.sweep_pending_kbs_fences() == 0
    assert not fx.did("kbs_fence_decommission")


# ─── flag on, KBS healthy ────────────────────────────────────────────


@pytest.mark.usefixtures("fence_on")
def test_fence_lands_right_after_the_freeze_and_before_the_erase(fx: FakeEffects) -> None:
    job = _start(generation=7)
    _drive()
    job.refresh_from_db()
    names = _names(fx)
    assert job.state == DecommissionState.DONE.value
    # Draining fences before it even asks the guest to stop.
    assert names.index("kbs_fence_decommission") < names.index("dispatch_graceful_stop")
    assert names.index("kbs_fence_decommission") < names.index("crypto_erase_kek_transit")
    # Exactly one fence: once landed, later handlers only read the column.
    assert names.count("kbs_fence_decommission") == 1
    # The destroy tombstones at the VM's generation, after the erase.
    assert ("kbs_tombstone", "vm-1", 7) in fx.calls
    assert names.index("crypto_erase_kek_transit") < names.index("kbs_tombstone")
    assert job.kbs_fence == KbsFence.TOMBSTONED.value
    assert job.kbs_fence_at is not None


# ─── flag on, fence failing ──────────────────────────────────────────


@pytest.mark.usefixtures("fence_on", "fast_retry")
def test_a_failing_fence_holds_the_erase_back_within_the_window(fx: FakeEffects) -> None:
    fx.fail.add("kbs_fence_decommission")
    job = _start()
    _to_crypto_erasing(job)
    _drive(5)
    job.refresh_from_db()
    assert job.state == DecommissionState.CRYPTO_ERASING.value
    assert not fx.did("crypto_erase_kek_transit"), "erase ran while the fence was retrying"
    assert job.kbs_fence == KbsFence.NONE.value
    # Retried each tick, not given up on.
    assert _names(fx).count("kbs_fence_decommission") >= 3


@pytest.mark.usefixtures("fence_on")
def test_past_the_window_the_erase_proceeds_and_the_job_is_pending(fx: FakeEffects) -> None:
    fx.fail.update({"kbs_fence_decommission", "kbs_tombstone"})
    job = _start()
    _to_crypto_erasing(job)
    _age_job(job, 31)
    _drive()
    job.refresh_from_db()
    assert fx.did("crypto_erase_kek_transit")
    assert job.state == DecommissionState.DONE.value
    assert job.vm.state == VmState.DESTROYED
    assert job.kbs_fence == KbsFence.PENDING.value


@pytest.mark.usefixtures("fence_on")
def test_the_window_is_clamped_to_the_step_timeout_so_the_hold_never_fails_the_job(
    fx: FakeEffects, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A window longer than the step timeout (60 s in the suite) would keep
    # raising past it and the driver would FAIL the job — erase never run.
    monkeypatch.setattr(settings, "VALI_KBS_FENCE_WINDOW_S", 10_000.0)
    fx.fail.update({"kbs_fence_decommission", "kbs_tombstone"})
    job = _start()
    _to_crypto_erasing(job)
    _age_job(job, 61)
    _drive(3)
    job.refresh_from_db()
    assert job.state != DecommissionState.FAILED.value
    assert fx.did("crypto_erase_kek_transit")
    assert job.kbs_fence == KbsFence.PENDING.value


@pytest.mark.usefixtures("fence_on")
def test_the_hold_never_applies_once_the_erase_already_happened(fx: FakeEffects) -> None:
    fx.fail.add("kbs_fence_decommission")
    job = _start()
    _to_crypto_erasing(job)
    # An earlier job (or this one, before a crash) already erased the KEK.
    DecommissionJob.objects.filter(id=job.id).update(kek_erased_at=timezone.now())
    _drive(3)
    job.refresh_from_db()
    assert job.state == DecommissionState.DONE.value


# ─── destroy / tombstone ─────────────────────────────────────────────


@pytest.mark.usefixtures("fence_on")
def test_a_tombstone_failure_never_blocks_the_destroy(fx: FakeEffects) -> None:
    fx.fail.add("kbs_tombstone")
    job = _start()
    _drive()
    job.refresh_from_db()
    assert job.state == DecommissionState.DONE.value
    assert job.vm.state == VmState.DESTROYED
    assert job.kbs_fence == KbsFence.PENDING.value


@pytest.mark.usefixtures("fence_on")
def test_a_generation_conflict_is_recorded_and_never_retried(fx: FakeEffects) -> None:
    fx.tombstone_conflict = True
    job = _start()
    _drive()
    job.refresh_from_db()
    assert job.state == DecommissionState.DONE.value
    assert job.kbs_fence == KbsFence.CONFLICT.value
    before = _names(fx).count("kbs_tombstone")
    DecommissionJob.objects.filter(id=job.id).update(
        kbs_fence_at=timezone.now() - timedelta(hours=1)
    )
    _drive(3)
    assert _names(fx).count("kbs_tombstone") == before


@pytest.mark.usefixtures("fence_on")
def test_a_rerun_of_the_destroy_still_tombstones(fx: FakeEffects) -> None:
    # The VM row reached Destroyed but the process died before the KBS
    # heard: the idempotent early-return path must still tell it.
    job = _start()
    _drive()
    job.refresh_from_db()
    DecommissionJob.objects.filter(id=job.id).update(kbs_fence=KbsFence.FENCED)
    fx.calls.clear()
    service._destroy_vm(job)
    assert fx.did("kbs_tombstone")
    job.refresh_from_db()
    assert job.kbs_fence == KbsFence.TOMBSTONED.value


# ─── sweep ───────────────────────────────────────────────────────────


@pytest.mark.usefixtures("fence_on")
def test_sweep_tombstones_a_pending_destroyed_vm(fx: FakeEffects) -> None:
    fx.fail.add("kbs_tombstone")
    job = _start()
    _drive()
    job.refresh_from_db()
    assert job.kbs_fence == KbsFence.PENDING.value
    fx.fail.clear()
    DecommissionJob.objects.filter(id=job.id).update(
        kbs_fence_at=timezone.now() - timedelta(minutes=5)
    )
    assert service.sweep_pending_kbs_fences() == 0
    job.refresh_from_db()
    assert job.kbs_fence == KbsFence.TOMBSTONED.value


@pytest.mark.usefixtures("fence_on")
def test_sweep_fences_a_pending_decommissioning_vm(fx: FakeEffects) -> None:
    job = _start()
    service.tick_once()  # Draining: ticket frozen (fence succeeds here too)
    job.vm.refresh_from_db()
    assert job.vm.state == VmState.DECOMMISSIONING
    DecommissionJob.objects.filter(id=job.id).update(
        kbs_fence=KbsFence.PENDING, kbs_fence_at=timezone.now() - timedelta(minutes=5)
    )
    fx.calls.clear()
    service.sweep_pending_kbs_fences()
    assert fx.did("kbs_fence_decommission")
    assert not fx.did("kbs_tombstone")
    job.refresh_from_db()
    assert job.kbs_fence == KbsFence.FENCED.value


@pytest.mark.usefixtures("fence_on")
def test_sweep_spaces_out_its_retries(fx: FakeEffects) -> None:
    job = _start()
    service.tick_once()
    DecommissionJob.objects.filter(id=job.id).update(
        kbs_fence=KbsFence.PENDING, kbs_fence_at=timezone.now()
    )
    fx.calls.clear()
    assert service.sweep_pending_kbs_fences() == 1
    assert not fx.did("kbs_fence_decommission")


@pytest.mark.usefixtures("fence_on")
def test_sweep_failure_restamps_so_the_next_try_waits(fx: FakeEffects) -> None:
    job = _start()
    service.tick_once()
    old = timezone.now() - timedelta(minutes=5)
    DecommissionJob.objects.filter(id=job.id).update(kbs_fence=KbsFence.PENDING, kbs_fence_at=old)
    fx.fail.add("kbs_fence_decommission")
    assert service.sweep_pending_kbs_fences() == 1
    job.refresh_from_db()
    assert job.kbs_fence == KbsFence.PENDING.value
    assert job.kbs_fence_at > old


def test_the_flag_ships_off() -> None:
    # The routes 404 on every KBS until the ceremony ships them; a default-on
    # flag would hold every erase back for the full window on a 404.
    import importlib

    import vali.settings as prod_settings

    importlib.reload(prod_settings)
    assert prod_settings.VALI_KBS_FENCE_ENABLED is False


@pytest.mark.usefixtures("fence_on")
def test_a_migrated_vm_is_tombstoned_at_its_live_generation(fx: FakeEffects) -> None:
    # The KBS holds the generation the LAST §25 activate moved it to — the
    # live `generation`, not the baked `signing_generation` the guest signs at.
    vm = make_vm("vm-mig", generation=6, signing_generation=1, host="node-src")
    service.start_decommission(vm=vm, decided_by=make_service_client())
    _drive()
    assert ("kbs_tombstone", "vm-mig", 6) in fx.calls


@pytest.mark.usefixtures("fence_on")
def test_a_failing_fence_is_retried_on_a_spacing_not_every_tick(fx: FakeEffects) -> None:
    # A dead KBS costs one HTTP timeout per attempt; per tick it would stall
    # every other job behind it.
    fx.fail.add("kbs_fence_decommission")
    job = _start()
    _to_crypto_erasing(job)
    _drive(5)
    assert _names(fx).count("kbs_fence_decommission") == 1


@pytest.mark.usefixtures("fence_on")
def test_a_kbs_without_the_route_does_not_hold_the_erase(
    fx: FakeEffects, monkeypatch: pytest.MonkeyPatch
) -> None:
    from apps.orchestration import effects

    def missing(vm_id: str) -> object:
        fx.calls.append(("kbs_fence_decommission", vm_id))
        raise effects.KbsRouteMissing("404")

    monkeypatch.setattr(effects, "kbs_fence_decommission", missing)
    fx.fail.add("kbs_tombstone")
    job = _start()
    _drive()  # no ageing: the window is NOT waited out for a 404
    job.refresh_from_db()
    assert job.state == DecommissionState.DONE.value
    assert job.kbs_fence == KbsFence.PENDING.value


@pytest.mark.usefixtures("fence_on")
def test_giving_up_rearms_the_phase_so_the_erase_gets_a_whole_window(fx: FakeEffects) -> None:
    fx.fail.update({"kbs_fence_decommission", "crypto_erase_kek_transit"})
    job = _start()
    _to_crypto_erasing(job)
    # A slow tick: the hold only looks again past the step timeout (60 s).
    _age_job(job, 70)
    service.tick_once()
    job.refresh_from_db()
    assert job.kbs_fence == KbsFence.PENDING.value
    # The erase failed once, but the phase clock was reset when the hold gave
    # up, so it is retried rather than the job failing on the hold's time.
    assert job.state == DecommissionState.CRYPTO_ERASING.value
    assert (timezone.now() - job.phase_started_at).total_seconds() < 5


@pytest.mark.usefixtures("fence_on")
def test_a_redriven_job_inherits_the_fence_and_does_not_wait_again(fx: FakeEffects) -> None:
    fx.fail.update({"kbs_fence_decommission", "crypto_erase_kek_transit"})
    job = _start()
    _to_crypto_erasing(job)
    _age_job(job, 31)
    service.tick_once()  # hold gives up -> pending; erase fails
    DecommissionJob.objects.filter(id=job.id).update(
        state=DecommissionState.FAILED, finished_at=timezone.now()
    )
    assert service.sweep_stranded_decommissions() == 1
    redriven = DecommissionJob.objects.exclude(id=job.id).get()
    assert redriven.kbs_fence == KbsFence.PENDING.value
    fx.fail.discard("crypto_erase_kek_transit")
    service.advance_decommission_job(redriven)
    assert fx.did("crypto_erase_kek_transit")


@pytest.mark.usefixtures("fence_on")
def test_a_late_fence_never_overwrites_a_pending_tombstone(
    fx: FakeEffects, monkeypatch: pytest.MonkeyPatch
) -> None:
    from apps.orchestration import effects

    job = _start()
    service.tick_once()  # Draining — fence lands
    DecommissionJob.objects.filter(id=job.id).update(kbs_fence=KbsFence.NONE)

    def racing_fence(vm_id: str) -> object:
        # While this call is in flight another ticker destroyed the VM and
        # failed its tombstone.
        DecommissionJob.objects.filter(id=job.id).update(kbs_fence=KbsFence.PENDING)
        return effects.KbsFenceOk(previous="active", state="decommissioning", cached=False)

    monkeypatch.setattr(effects, "kbs_fence_decommission", racing_fence)
    assert service._try_kbs_fence(job, respect_spacing=False) == service._Fence.LANDED
    job.refresh_from_db()
    assert job.kbs_fence == KbsFence.PENDING.value


@pytest.mark.usefixtures("fence_on")
def test_sweep_tombstones_a_destroyed_vm_left_merely_fenced(fx: FakeEffects) -> None:
    job = _start()
    _drive()
    DecommissionJob.objects.filter(id=job.id).update(
        kbs_fence=KbsFence.FENCED, kbs_fence_at=timezone.now() - timedelta(minutes=5)
    )
    fx.calls.clear()
    assert service.sweep_pending_kbs_fences() == 0
    assert fx.did("kbs_tombstone")
    job.refresh_from_db()
    assert job.kbs_fence == KbsFence.TOMBSTONED.value


@pytest.mark.usefixtures("fence_on")
def test_sweep_stops_its_pass_at_the_first_failure(fx: FakeEffects) -> None:
    old = timezone.now() - timedelta(minutes=5)
    for vm_id in ("vm-a", "vm-b", "vm-c"):
        _start(vm_id)
    service.tick_once()  # every ticket frozen: all three decommissioning
    DecommissionJob.objects.update(kbs_fence=KbsFence.PENDING, kbs_fence_at=old)
    fx.fail.add("kbs_fence_decommission")
    fx.calls.clear()
    assert service.sweep_pending_kbs_fences() == 3
    assert _names(fx).count("kbs_fence_decommission") == 1


@pytest.mark.usefixtures("fence_on")
def test_the_hold_gives_up_at_half_the_step_timeout(
    fx: FakeEffects, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Half, so the hold's last raise can never be read by the driver as the
    # step timing out.
    monkeypatch.setattr(settings, "VALI_KBS_FENCE_WINDOW_S", 10_000.0)
    fx.fail.update({"kbs_fence_decommission", "kbs_tombstone"})
    job = _start()
    _to_crypto_erasing(job)
    _age_job(job, 31)  # past 60/2, well short of 60
    service.tick_once()
    job.refresh_from_db()
    assert job.kbs_fence == KbsFence.PENDING.value
    assert fx.did("crypto_erase_kek_transit")


@pytest.mark.usefixtures("fence_on", "fast_retry")
def test_the_fence_is_retried_while_waiting_for_the_ack(fx: FakeEffects) -> None:
    fx.eol_ack = None  # the guest never acks: the job sits in AwaitingEolAck
    fx.fail.add("kbs_fence_decommission")
    job = _start()
    service.tick_once()  # Draining: the fence fails
    fx.fail.clear()
    service.tick_once()
    job.refresh_from_db()
    assert job.state == DecommissionState.AWAITING_EOL_ACK.value
    assert job.kbs_fence == KbsFence.FENCED.value


@pytest.mark.usefixtures("fence_on")
def test_an_unreachable_kbs_spends_the_whole_tick_budget(
    fx: FakeEffects, monkeypatch: pytest.MonkeyPatch
) -> None:
    from apps.orchestration import effects

    def blackhole(vm_id: str) -> object:
        fx.calls.append(("kbs_fence_decommission", vm_id))
        raise effects.EffectUnavailable("kbs-admin:decommission: peer unreachable")

    monkeypatch.setattr(effects, "kbs_fence_decommission", blackhole)
    for vm_id in ("vm-a", "vm-b", "vm-c"):
        _start(vm_id)
    service.tick_once()
    # One timeout, not one per job.
    assert _names(fx).count("kbs_fence_decommission") == 1


@pytest.mark.usefixtures("fence_on", "fast_retry")
def test_the_per_tick_budget_caps_calls_across_jobs(
    fx: FakeEffects, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(service, "_KBS_FENCE_CALLS_PER_TICK", 2)
    fx.fail.add("kbs_fence_decommission")
    for vm_id in ("vm-a", "vm-b", "vm-c", "vm-d"):
        _start(vm_id)
    service.tick_once()
    assert _names(fx).count("kbs_fence_decommission") == 2


@pytest.mark.usefixtures("fence_on")
def test_giving_up_never_downgrades_a_fence_that_landed_meanwhile(
    fx: FakeEffects, monkeypatch: pytest.MonkeyPatch
) -> None:
    from apps.orchestration import effects

    job = _start()
    fx.fail.add("kbs_fence_decommission")
    _to_crypto_erasing(job)
    _age_job(job, 31)

    def lands_elsewhere(vm_id: str) -> object:
        # Another worker's fence lands while this attempt fails.
        DecommissionJob.objects.filter(id=job.id).update(kbs_fence=KbsFence.TOMBSTONED)
        raise effects.EffectError("injected")

    monkeypatch.setattr(effects, "kbs_fence_decommission", lands_elsewhere)
    monkeypatch.setattr(service, "_KBS_FENCE_RETRY_EVERY_S", 0.0)
    job.refresh_from_db()
    service._hold_erase_for_kbs_fence(job)
    job.refresh_from_db()
    assert job.kbs_fence == KbsFence.TOMBSTONED.value


@pytest.mark.usefixtures("fence_on")
def test_giving_up_bumps_the_version_so_a_stale_worker_cannot_fail_the_job(
    fx: FakeEffects,
) -> None:
    fx.fail.add("kbs_fence_decommission")
    job = _start()
    _to_crypto_erasing(job)
    _age_job(job, 31)
    job.refresh_from_db()
    stale = DecommissionJob.objects.get(id=job.id)
    service._hold_erase_for_kbs_fence(job)
    assert DecommissionJob.objects.get(id=job.id).version == stale.version + 1
    service._fail_decommission(stale, reason="stale worker")
    assert DecommissionJob.objects.get(id=job.id).state != DecommissionState.FAILED.value
