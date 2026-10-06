"""Full-e2e state machine — the self-cleaning / no-leak guarantee.

These tests prove the harness NEVER leaves a synthetic VM behind: the
`finally` teardown runs on failure, is a no-op when already clean, and
force-destroys when the §24 API can't finish.
"""

from __future__ import annotations

import secrets

import pytest
from django.conf import settings
from django.utils import timezone

from apps.lifecycle.models import VmState
from apps.orchestration.models import LaunchJob, LaunchJobState
from apps.orchestration.tests.factories import make_service_client, make_vm
from apps.synthetic import e2e


def _make_synth_launch_job(vm_id: str, *, state: str) -> LaunchJob:
    """A synthetic-tenant LaunchJob in `state` for the reconcile/reaper
    tests (mirrors what `start_launch` commits at POST)."""
    return LaunchJob.objects.create(
        job_id=secrets.token_hex(8),
        vm_id=vm_id,
        tenant_id=settings.VALI_SYNTHETIC_TENANT_ID,
        flavor="small",
        spec_json={"vm_id": vm_id, "disk_mode": "golden_verity_overlay"},
        userdata_vault_path=f"x/{vm_id}/userdata-pending",
        userdata_vault_version=1,
        kek_vault_path=f"x/{vm_id}/luks-kek",
        state=state,
        phase_started_at=timezone.now(),
        decided_by=make_service_client(),
    )


# ── pure helpers ──────────────────────────────────────────────────────


def test_distro_rotation_is_deterministic_and_cycles() -> None:
    period = e2e._ROTATION_PERIOD_S
    seq = [e2e.distro_for(i * period) for i in range(len(e2e.DISTRO_ROTATION) * 2)]
    assert seq[: len(e2e.DISTRO_ROTATION)] == list(e2e.DISTRO_ROTATION)
    # Wraps around.
    assert seq[len(e2e.DISTRO_ROTATION)] == e2e.DISTRO_ROTATION[0]


def test_build_launch_body_refuses_an_unblessed_distro(db) -> None:
    """No catalog entry ⇒ loud refusal. There is deliberately no private
    bake list to fall back on: falling back is what let the monitor test a
    superseded image while reporting green."""
    with pytest.raises(e2e.ConfigError):
        e2e.build_launch_body("ubuntu", "synmon-ubuntu-1")


def test_build_launch_body_shape(blessed_ubuntu) -> None:
    body = e2e.build_launch_body("ubuntu", "synmon-ubuntu-1")
    assert body["bake_id"] == "bake-ubuntu-9"
    assert body["disk_mode"] == "golden_verity_overlay"
    assert body["platform_id"] == ""
    assert body["tenant_id"] == settings.VALI_SYNTHETIC_TENANT_ID
    assert body["enable_netbird"] is True
    assert "{{NETBIRD_SETUP_KEY}}" in body["userdata"]
    assert "hippius.kbs_url=vsock://2:19266" in body["cmdline"]


def test_apiclient_refuses_empty_token() -> None:
    with pytest.raises(e2e.ConfigError):
        e2e.ApiClient(base="http://x", token="", timeout_s=1.0)


# ── teardown unit tests ───────────────────────────────────────────────


class _FakeApi:
    """A stand-in ApiClient whose behaviour each test wires up."""

    def __init__(self, **behaviour):
        self.calls: list[str] = []
        self._b = behaviour

    def launch(self, body):
        self.calls.append("launch")
        return self._b.get("launch", {"job_id": "j1", "state": "queued"})

    def poll_launch(self, job_id):
        self.calls.append("poll_launch")
        return self._b.get("poll_launch", {"job_id": job_id, "state": "succeeded"})

    def decommission(self, vm_id):
        self.calls.append("decommission")
        b = self._b.get("decommission")
        if isinstance(b, Exception):
            raise b
        return b or {"job_id": "d1", "state": "draining"}

    def poll_decommission(self, vm_id, job_id):
        self.calls.append("poll_decommission")
        fn = self._b.get("poll_decommission")
        return fn(vm_id, job_id) if callable(fn) else {"job_id": job_id, "state": "done"}


@pytest.mark.django_db
def test_teardown_noop_when_already_destroyed(monkeypatch) -> None:
    make_vm("synmon-x", state=VmState.DESTROYED)
    called = []
    monkeypatch.setattr(e2e, "_force_destroy", lambda vm_id: called.append(vm_id) or "forced")
    detail, forced = e2e._teardown(_FakeApi(), "synmon-x")
    assert forced is False
    assert "already destroyed" in detail
    assert called == []  # never force-destroys a clean VM


@pytest.mark.django_db
def test_teardown_noop_when_no_row() -> None:
    detail, forced = e2e._teardown(_FakeApi(), "does-not-exist")
    assert forced is False
    assert "nothing to clean" in detail


@pytest.mark.django_db
def test_teardown_via_api_when_decommission_succeeds(monkeypatch) -> None:
    make_vm("synmon-y", state=VmState.ACTIVE)

    def poll(vm_id, job_id):
        # Simulate the real §24 effect: the VM is now destroyed.
        from apps.lifecycle.models import Vm

        Vm.objects.filter(vm_id=vm_id).update(state=VmState.DESTROYED)
        return {"job_id": job_id, "state": "done"}

    api = _FakeApi(poll_decommission=poll)
    forced_spy = []
    monkeypatch.setattr(e2e, "_force_destroy", lambda vm_id: forced_spy.append(vm_id) or "x")
    detail, forced = e2e._teardown(api, "synmon-y")
    assert forced is False
    assert "§24 API" in detail
    assert forced_spy == []  # API path succeeded → no force fallback


@pytest.mark.django_db
def test_teardown_forces_destroy_when_api_fails(monkeypatch) -> None:
    make_vm("synmon-z", state=VmState.ACTIVE)
    erase_calls, destroy_calls = [], []
    from apps.orchestration import effects

    monkeypatch.setattr(
        effects, "crypto_erase_kek_transit", lambda vm: erase_calls.append(vm.vm_id)
    )
    monkeypatch.setattr(effects, "dispatch_destroy", lambda vm: destroy_calls.append(vm.vm_id))

    api = _FakeApi(decommission=e2e.ApiError("kbs unreachable"))
    detail, forced = e2e._teardown(api, "synmon-z")

    assert forced is True
    assert "forced teardown" in detail
    assert erase_calls == ["synmon-z"]  # KEK was crypto-erased
    assert destroy_calls == ["synmon-z"]  # domain was destroyed
    from apps.lifecycle.models import Vm

    row = Vm.objects.get(vm_id="synmon-z")
    assert row.state == VmState.DESTROYED  # no leak
    assert row.power_state == "off" and row.power_state_at is not None


# ── the whole state machine ALWAYS tears down ─────────────────────────


@pytest.mark.django_db
def test_run_e2e_tears_down_on_boot_failure(monkeypatch) -> None:
    """Launch succeeds (VM exists) then boot fails — the VM MUST still be
    destroyed by the finally teardown, and never leak."""
    monkeypatch.setattr(e2e, "_synthetic_vm_id", lambda distro: "synmon-boot-fail")
    monkeypatch.setattr(e2e, "_sleep", lambda *_: None)
    make_vm("synmon-boot-fail", state=VmState.ACTIVE)

    # Boot never advances → the release stage raises.
    def boot_boom(vm_id, target, deadline):
        raise e2e.ApiError("boot never reached")

    monkeypatch.setattr(e2e, "_await_boot_phase", boot_boom)

    from apps.orchestration import effects

    monkeypatch.setattr(effects, "crypto_erase_kek_transit", lambda vm: None)
    monkeypatch.setattr(effects, "dispatch_destroy", lambda vm: None)

    # The §24 API path fails → force fallback kicks in.
    api = _FakeApi(decommission=e2e.ApiError("decommission unavailable"))
    outcome = e2e.run_e2e(api=api, distro="ubuntu", budget_s=30)

    assert outcome.success is False
    assert outcome.teardown_forced is True
    from apps.lifecycle.models import Vm

    assert Vm.objects.get(vm_id="synmon-boot-fail").state == VmState.DESTROYED


@pytest.mark.django_db
def test_run_e2e_launch_failure_still_safe(monkeypatch) -> None:
    """The launch API itself fails → no VM was created → teardown is a
    clean no-op (nothing to leak)."""
    monkeypatch.setattr(e2e, "_synthetic_vm_id", lambda distro: "synmon-never")
    # A launch that returns no job_id fails the launch stage cleanly.
    api = _FakeApi(launch={"job_id": ""})
    outcome = e2e.run_e2e(api=api, distro="ubuntu", budget_s=30)
    assert outcome.success is False
    # launch stage recorded as failed.
    assert outcome.stages[0].name == "launch"
    assert outcome.stages[0].ok is False


# ── FINDING 1: committed-but-lost-response launch → reconcile ─────────


@pytest.mark.django_db
def test_teardown_reconciles_committed_but_lost_launch(monkeypatch) -> None:
    """The launch POST committed a QUEUED LaunchJob but its HTTP response
    was LOST (ApiError) → no Vm row exists yet → the finally teardown MUST
    reconcile against the LaunchJob and cancel it before the async worker
    can place + boot it. Proves no VM leaks + no KEK is left un-erased."""
    vm_id = "synmon-lost-response"
    monkeypatch.setattr(e2e, "_synthetic_vm_id", lambda distro: vm_id)
    monkeypatch.setattr(e2e, "_sleep", lambda *_: None)
    # start_launch committed the job; the response never came back.
    job = _make_synth_launch_job(vm_id, state=LaunchJobState.QUEUED.value)

    class _LostResponseApi(_FakeApi):
        def launch(self, body):
            self.calls.append("launch")
            raise e2e.ApiError("connection timed out after POST committed")

    outcome = e2e.run_e2e(api=_LostResponseApi(), distro="ubuntu", budget_s=30)

    assert outcome.success is False
    # The committed queued job was cancelled → the worker will NEVER place it.
    job.refresh_from_db()
    assert job.state == LaunchJobState.FAILED.value
    assert "no leak" in outcome.teardown_detail
    assert outcome.teardown_forced is False
    # No VM was ever materialized.
    from apps.lifecycle.models import Vm

    assert not Vm.objects.filter(vm_id=vm_id).exists()


@pytest.mark.django_db
def test_reconcile_running_launch_drives_full_teardown(monkeypatch) -> None:
    """The launch was already CLAIMED (running) and the worker materialized
    a booted VM before teardown ran (the cancel CAS loses). Reconcile must
    poll the VM in and drive decommission → force-erase, so a booted VM is
    still erased + destroyed (no leak)."""
    vm_id = "synmon-claimed"
    _make_synth_launch_job(vm_id, state=LaunchJobState.RUNNING.value)
    make_vm(vm_id, state=VmState.ACTIVE)  # worker already booted it

    from apps.orchestration import effects

    erase, destroy = [], []
    monkeypatch.setattr(effects, "crypto_erase_kek_transit", lambda vm: erase.append(vm.vm_id))
    monkeypatch.setattr(effects, "dispatch_destroy", lambda vm: destroy.append(vm.vm_id))

    api = _FakeApi(decommission=e2e.ApiError("§24 API down"))
    detail, forced = e2e._reconcile_pending_launch(api, vm_id)

    assert forced is True
    assert "reconciled pending launch" in detail
    assert erase == [vm_id]  # KEK crypto-erased
    assert destroy == [vm_id]  # domain destroyed
    from apps.lifecycle.models import Vm

    assert Vm.objects.get(vm_id=vm_id).state == VmState.DESTROYED


@pytest.mark.django_db
def test_reconcile_no_job_no_vm_is_clean() -> None:
    """No Vm AND no pending LaunchJob → genuinely nothing to clean."""
    detail, forced = e2e._reconcile_pending_launch(_FakeApi(), "synmon-ghost")
    assert forced is False
    assert "nothing to clean" in detail


# ── FINDING 2: the reaper backstop (SIGKILL/OOM/eviction) ─────────────


def _age_vm(vm, *, tenant: str, age_s: int) -> None:
    from apps.lifecycle.models import Vm

    Vm.objects.filter(pk=vm.pk).update(
        tenant_id=tenant,
        created_at=timezone.now() - timezone.timedelta(seconds=age_s),
    )


@pytest.mark.django_db
def test_reaper_force_destroys_stale_synthetic_vm(monkeypatch) -> None:
    """A synthetic VM older than the reap age (a killed run leaked it) is
    force-erased + destroyed by the reaper."""
    from apps.lifecycle.models import Vm
    from apps.orchestration import effects

    vm = make_vm("synmon-leaked", state=VmState.ACTIVE)
    _age_vm(vm, tenant=settings.VALI_SYNTHETIC_TENANT_ID, age_s=7200)

    erase, destroy = [], []
    monkeypatch.setattr(effects, "crypto_erase_kek_transit", lambda vm: erase.append(vm.vm_id))
    monkeypatch.setattr(effects, "dispatch_destroy", lambda vm: destroy.append(vm.vm_id))

    res = e2e.run_reaper()

    assert res.reaped_vms == ["synmon-leaked"]
    assert res.reaped_total == 1
    assert erase == ["synmon-leaked"] and destroy == ["synmon-leaked"]
    assert Vm.objects.get(vm_id="synmon-leaked").state == VmState.DESTROYED


@pytest.mark.django_db
def test_reaper_cancels_stale_pending_synthetic_launch() -> None:
    """A stale non-terminal synthetic LaunchJob with no VM is cancelled so
    a stuck/orphaned worker never places it."""
    vm_id = "synmon-orphan-job"
    job = _make_synth_launch_job(vm_id, state=LaunchJobState.QUEUED.value)
    LaunchJob.objects.filter(pk=job.pk).update(
        phase_started_at=timezone.now() - timezone.timedelta(seconds=7200)
    )

    res = e2e.run_reaper()

    assert res.cancelled_jobs == [vm_id]
    job.refresh_from_db()
    assert job.state == LaunchJobState.FAILED.value


@pytest.mark.django_db
def test_reaper_never_touches_real_tenant_or_fresh_synthetic(monkeypatch) -> None:
    """HARD invariant: the reaper only ever targets the synthetic tenant,
    and never a fresh in-flight synthetic VM."""
    from apps.lifecycle.models import Vm
    from apps.orchestration import effects

    # An OLD real-tenant VM — must be untouched.
    real = make_vm("real-tenant-vm", state=VmState.ACTIVE)
    _age_vm(real, tenant="acme-corp", age_s=7200)
    # An OLD real-tenant pending launch — must be untouched.
    real_job = LaunchJob.objects.create(
        job_id=secrets.token_hex(8),
        vm_id="real-tenant-vm-2",
        tenant_id="acme-corp",
        flavor="small",
        spec_json={"vm_id": "real-tenant-vm-2"},
        userdata_vault_path="x/real/userdata",
        userdata_vault_version=1,
        kek_vault_path="x/real/luks-kek",
        state=LaunchJobState.RUNNING.value,
        phase_started_at=timezone.now() - timezone.timedelta(seconds=7200),
        decided_by=make_service_client(),
    )
    # A FRESH synthetic VM (in-flight) — must not be reaped.
    fresh = make_vm("synmon-fresh", state=VmState.ACTIVE)
    _age_vm(fresh, tenant=settings.VALI_SYNTHETIC_TENANT_ID, age_s=60)

    calls = []
    monkeypatch.setattr(effects, "crypto_erase_kek_transit", lambda vm: calls.append(vm.vm_id))
    monkeypatch.setattr(effects, "dispatch_destroy", lambda vm: calls.append(vm.vm_id))

    res = e2e.run_reaper()

    assert res.reaped_total == 0
    assert calls == []
    assert Vm.objects.get(vm_id="real-tenant-vm").state == VmState.ACTIVE
    assert Vm.objects.get(vm_id="synmon-fresh").state == VmState.ACTIVE
    real_job.refresh_from_db()
    assert real_job.state == LaunchJobState.RUNNING.value  # untouched


@pytest.mark.django_db
def test_force_destroy_does_not_tombstone_when_the_kek_survives(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A failed crypto-erase must NOT mark the VM Destroyed.

    The unconditional tombstone inverted §24's guarantee: an erase failure
    was a `log.warning` and the row was marked dead anyway, so data-death
    would be RECORDED as kept while `kek-<vm_id>` stayed live in Vault. A
    fleet audit found 37 such VMs — none from this path, which is rewritten
    so that it never can produce one.

    It lands in DECOMMISSIONING, not ACTIVE: that frees the capacity slot
    via the existing `vm-terminal` drain without claiming data death, and
    the reaper re-picks anything non-DESTROYED so it keeps retrying and
    re-alarming. An unfulfilled erase is a real alarm."""
    from apps.lifecycle.models import Vm, VmState
    from apps.orchestration import effects
    from apps.synthetic import e2e as e2e_mod

    Vm.objects.filter(vm_id="synmon-x").delete()
    Vm.objects.create(
        vm_id="synmon-x", tenant_id="t", state=VmState.ACTIVE, host="m1", generation=1
    )

    def boom(_vm: object) -> None:
        raise RuntimeError("vault unreachable")

    monkeypatch.setattr(effects, "crypto_erase_kek_transit", boom)
    monkeypatch.setattr(effects, "dispatch_destroy", lambda _vm: None)

    detail = e2e_mod._force_destroy("synmon-x")

    assert "NOT-tombstoned(kek-still-live)" in detail
    state = Vm.objects.get(vm_id="synmon-x").state
    assert state != VmState.DESTROYED, "data death must not be recorded"
    assert state == VmState.DECOMMISSIONING, "but the capacity slot must free"


@pytest.mark.django_db
def test_force_destroy_tombstones_once_the_kek_is_gone(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The happy path is unchanged: a successful erase still tombstones, so
    the reaper stops re-picking a VM that is genuinely dead."""
    from apps.lifecycle.models import Vm, VmState
    from apps.orchestration import effects
    from apps.synthetic import e2e as e2e_mod

    Vm.objects.filter(vm_id="synmon-y").delete()
    Vm.objects.create(
        vm_id="synmon-y", tenant_id="t", state=VmState.ACTIVE, host="m1", generation=1
    )
    monkeypatch.setattr(effects, "crypto_erase_kek_transit", lambda _vm: None)
    monkeypatch.setattr(effects, "dispatch_destroy", lambda _vm: None)

    detail = e2e_mod._force_destroy("synmon-y")

    assert "crypto-erased" in detail
    assert Vm.objects.get(vm_id="synmon-y").state == VmState.DESTROYED


def _synmon_vm(vm_id: str) -> None:
    from apps.lifecycle.models import Vm, VmState

    Vm.objects.filter(vm_id=vm_id).delete()
    Vm.objects.create(vm_id=vm_id, tenant_id="t", state=VmState.ACTIVE, host="m1", generation=1)


@pytest.mark.django_db
def test_force_destroy_revokes_the_netbird_peer_after_the_erase(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Tenant peers are persistent: the forced teardown bypasses the §24 job
    (which revokes), so it must revoke itself — after the erase."""
    from apps.orchestration import effects
    from apps.synthetic import e2e as e2e_mod

    _synmon_vm("synmon-nb")
    order: list[str] = []
    monkeypatch.setattr(effects, "crypto_erase_kek_transit", lambda _vm: order.append("erase"))
    monkeypatch.setattr(effects, "revoke_netbird", lambda vm: order.append(f"revoke:{vm.vm_id}"))
    monkeypatch.setattr(effects, "dispatch_destroy", lambda _vm: None)

    detail = e2e_mod._force_destroy("synmon-nb")

    assert order == ["erase", "revoke:synmon-nb"]
    assert "netbird-revoked" in detail


@pytest.mark.django_db
def test_force_destroy_keeps_the_peer_when_the_erase_failed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from apps.orchestration import effects
    from apps.synthetic import e2e as e2e_mod

    _synmon_vm("synmon-nb2")

    def boom(_vm: object) -> None:
        raise RuntimeError("vault unreachable")

    revoked: list[str] = []
    monkeypatch.setattr(effects, "crypto_erase_kek_transit", boom)
    monkeypatch.setattr(effects, "revoke_netbird", lambda vm: revoked.append(vm.vm_id))
    monkeypatch.setattr(effects, "dispatch_destroy", lambda _vm: None)

    e2e_mod._force_destroy("synmon-nb2")

    assert revoked == []


@pytest.mark.django_db
def test_a_failed_forced_revoke_still_tombstones(monkeypatch: pytest.MonkeyPatch) -> None:
    """Best-effort: data death is the erase; the janitor collects the peer."""
    from apps.lifecycle.models import Vm, VmState
    from apps.orchestration import effects
    from apps.synthetic import e2e as e2e_mod

    _synmon_vm("synmon-nb3")

    def nb_down(_vm: object) -> None:
        raise effects.EffectUnavailable("netbird down")

    monkeypatch.setattr(effects, "crypto_erase_kek_transit", lambda _vm: None)
    monkeypatch.setattr(effects, "revoke_netbird", nb_down)
    monkeypatch.setattr(effects, "dispatch_destroy", lambda _vm: None)

    detail = e2e_mod._force_destroy("synmon-nb3")

    assert "netbird-revoke-failed" in detail
    assert Vm.objects.get(vm_id="synmon-nb3").state == VmState.DESTROYED


# ── a forced teardown never leaves a running zombie ──────────────────


def _synmon_with_launch(vm_id: str):
    from apps.lifecycle.models import Vm, VmState

    Vm.objects.filter(vm_id=vm_id).delete()
    vm = Vm.objects.create(
        vm_id=vm_id, tenant_id="t", state=VmState.ACTIVE, host="m1", generation=1
    )
    _make_synth_launch_job(vm_id, state="queued")
    return vm


@pytest.mark.django_db
def test_an_undeliverable_destroy_erases_nothing_and_hands_off_to_the_tick(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Seen live on two miners: the reaper pod could not reach the Edge;
    the KEK was erased and the row tombstoned while the domain ran on — a
    zombie. Now nothing is erased or tombstoned in-process; the tick gets a
    forced §24 job, which destroys over its own path first."""
    from apps.lifecycle.models import Vm, VmState
    from apps.orchestration import effects
    from apps.orchestration.models import DecommissionJob, DecommissionState
    from apps.synthetic import e2e as e2e_mod

    _synmon_with_launch("synmon-z")
    erased: list[str] = []
    monkeypatch.setattr(effects, "crypto_erase_kek_transit", lambda vm: erased.append(vm.vm_id))

    def unreachable(_vm: object) -> None:
        raise effects.EffectUnavailable("edge-order: peer unreachable")

    monkeypatch.setattr(effects, "dispatch_destroy", unreachable)

    detail = e2e_mod._force_destroy("synmon-z")

    assert erased == [], "no erase before the domain is proven stopped"
    assert "handed-to-tick" in detail
    assert Vm.objects.get(vm_id="synmon-z").state == VmState.DECOMMISSIONING
    job = DecommissionJob.objects.get(vm__vm_id="synmon-z")
    assert job.state == DecommissionState.CRYPTO_ERASING.value
    assert job.forced is True


@pytest.mark.django_db
def test_the_next_reap_leaves_the_handed_off_job_alone(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from apps.orchestration import effects
    from apps.orchestration.models import DecommissionJob
    from apps.synthetic import e2e as e2e_mod

    _synmon_with_launch("synmon-z2")
    monkeypatch.setattr(effects, "crypto_erase_kek_transit", lambda vm: None)

    def unreachable(_vm: object) -> None:
        raise effects.EffectUnavailable("edge-order: peer unreachable")

    monkeypatch.setattr(effects, "dispatch_destroy", unreachable)
    e2e_mod._force_destroy("synmon-z2")
    detail = e2e_mod._force_destroy("synmon-z2")

    assert "left-to-in-flight-job" in detail
    assert DecommissionJob.objects.filter(vm__vm_id="synmon-z2").count() == 1


@pytest.mark.django_db
def test_the_destroy_goes_out_before_the_erase(monkeypatch: pytest.MonkeyPatch) -> None:
    from apps.orchestration import effects
    from apps.synthetic import e2e as e2e_mod

    _synmon_with_launch("synmon-z3")
    order: list[str] = []
    monkeypatch.setattr(effects, "dispatch_destroy", lambda vm: order.append("destroy"))
    monkeypatch.setattr(effects, "crypto_erase_kek_transit", lambda vm: order.append("erase"))
    monkeypatch.setattr(effects, "revoke_netbird", lambda vm: order.append("revoke"))

    e2e_mod._force_destroy("synmon-z3")
    assert order[0] == "destroy"
