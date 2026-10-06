"""A launch refused at PLACEMENT must not leave a live KEK behind.

## The defect, live 2026-08-13

`vm-fedora-3` was refused by the scheduler — `no-eligible-miner`. It
never reached a miner, so no measured cmdline was ever baked and the row
carries no `hippius.eol_nonce`. Its per-VM Vault-Transit KEK, however,
was provisioned at API INTAKE (`launch_jobs._provision_golden_overlay_kek`
runs inside `start_launch`, long before placement), so it was alive:

    Vm: state=active  host=''  boot_phase=''  generation=1  eol_nonce: None
        launch_abandoned_at = 2026-08-13 15:52:01  outcome='no-eligible-miner'
    DecommissionJob: state=failed
        reason = "draining:vm has no eol_nonce (launch did not bake
                  hippius.eol_nonce) — cannot decommission"
    Vault: transit/keys/kek-vm-fedora-3  ->  LIVE

A VM the control plane believed was `active`, that no host was running,
holding a live KEK — and §24, the ONLY automated path that erases a KEK,
refused to run on it. Four independent gates had to be crossed and every
one of them refused:

  1. `sweep_abandoned_launches` skipped the whole PRE-register class;
  2. `_abandoned_reap_veto` returned a flat `no-eol-nonce`;
  3. `never_ran_veto` answered `domain-unproven` forever — there was no
     miner to probe, because none was ever chosen;
  4. `_decommission_vm` refused the ticket-freeze outright.

## How this differs from #968 — the distinction IS the fix

#968 fixed the ADJACENT case: a dispatch that failed AFTER the KBS
register. There the cmdline HAD been baked, so `eol_nonce` exists, §24
runs, and the bug was only that it burned the 600 s ack window. Its
`never_ran_veto` shortcut is untouched here (`test_968_*` below).

This case is refused BEFORE any miner sees the VM. #968's shortcut never
gets a chance to apply, because the job fails four steps earlier.

## ⛔ What these tests exist to protect

The `eol_nonce` requirement is there because a guest-signed StoppedAck is
what proves a clean stop. Nothing here weakens it for a VM that DID run —
the relaxation is ANDed with `never_ran_veto`, and the anti-overshoot
section is the one that matters most.
"""

from __future__ import annotations

from datetime import timedelta

import pytest
from django.utils import timezone

from apps.identity.models import PrincipalScope, ServiceClient
from apps.lifecycle.models import Vm, VmBootPhase, VmState
from apps.orchestration import effects, service
from apps.orchestration.models import (
    DecommissionJob,
    DecommissionState,
    LaunchJob,
    LaunchJobState,
    RebootRecovery,
)

pytestmark = pytest.mark.django_db

VM_ID = "vm-fedora-3"


# ── builders ─────────────────────────────────────────────────────────


def _actor(name: str) -> ServiceClient:
    return ServiceClient.objects.create(
        scope=PrincipalScope.OPERATOR.value, name=name
    )


def _never_placed_vm(vm_id: str = VM_ID, **fields) -> Vm:
    """`vm-fedora-3` exactly: active, no host, NO `eol_nonce` (no
    cmdline was ever baked), marked abandoned with `no-eligible-miner`
    and `registered=False` (it never reached the KBS register either)."""
    fields.setdefault("launch_abandoned_at", timezone.now() - timedelta(hours=3))
    fields.setdefault("launch_abandoned_outcome", "no-eligible-miner")
    fields.setdefault("launch_abandoned_registered", False)
    return Vm.objects.create(
        vm_id=vm_id,
        lease_id=f"lease-{vm_id}",
        tenant_id="t-stamp",
        state=VmState.ACTIVE.value,
        generation=fields.pop("generation", 1),
        signing_generation=fields.pop("signing_generation", 1),
        host=fields.pop("host", ""),
        lifecycle_vk=bytes(32),
        eol_nonce=fields.pop("eol_nonce", None),
        **fields,
    )


def _placement_refused_launch_job(vm_id: str = VM_ID) -> LaunchJob:
    """The real row: the async worker finished FAILED with
    `no-eligible-miner` and — the load-bearing part — `miner_id=""`,
    because the scheduler never chose one."""
    now = timezone.now()
    return LaunchJob.objects.create(
        job_id=f"job-{vm_id}",
        vm_id=vm_id,
        tenant_id="t-stamp",
        flavor="small",
        spec_json={"vm_id": vm_id},
        userdata_vault_path=f"x/{vm_id}/userdata",
        userdata_vault_version=1,
        kek_vault_path=f"x/{vm_id}/luks-kek",
        state=LaunchJobState.FAILED.value,
        reason="no-eligible-miner",
        miner_id="",
        phase_started_at=now,
        finished_at=now,
        decided_by=_actor(f"worker-{vm_id}"),
    )


def _ran_vm(vm_id: str = "tenant-1", **fields) -> Vm:
    """A VM that DID run: a miner accepted its dispatch (`host` stamped),
    it reported `running`, it spoke from inside the guest, and the
    reconcile loop saw its domain up."""
    vm = Vm.objects.create(
        vm_id=vm_id,
        lease_id=f"lease-{vm_id}",
        tenant_id="t-real",
        state=VmState.ACTIVE.value,
        generation=1,
        signing_generation=1,
        host="miner-a",
        lifecycle_vk=bytes(32),
        eol_nonce=fields.pop("eol_nonce", b"\x11" * 32),
        boot_phase=VmBootPhase.RUNNING.value,
        boot_phase_at=timezone.now(),
        guest_signal_at=timezone.now(),
        guest_signal_kind="served_receipt",
        **fields,
    )
    RebootRecovery.objects.create(vm=vm, host="miner-a", seen_running=True)
    now = timezone.now()
    LaunchJob.objects.create(
        job_id=f"job-{vm_id}-ok",
        vm_id=vm_id,
        tenant_id="t-real",
        flavor="small",
        spec_json={"vm_id": vm_id},
        userdata_vault_path=f"x/{vm_id}/userdata",
        userdata_vault_version=1,
        kek_vault_path=f"x/{vm_id}/luks-kek",
        state=LaunchJobState.SUCCEEDED.value,
        reason="",
        miner_id="miner-a",
        phase_started_at=now,
        finished_at=now,
        decided_by=_actor(f"worker-{vm_id}"),
    )
    return vm


@pytest.fixture
def no_probe_allowed(monkeypatch) -> None:
    """There is no miner to ask, so nothing may ask one. Any call to the
    live domain probe fails the test — proving the clearance comes from
    `no_miner_was_ever_chosen`, never from a probe that happened to time
    out into a permissive answer."""

    def _explode(vm, node_id_arg):  # pragma: no cover - the assertion IS this
        raise AssertionError(
            f"probed {node_id_arg!r} for a VM no miner was ever chosen for"
        )

    monkeypatch.setattr(effects, "poll_domain_running_on", _explode)


@pytest.fixture
def domain_down(monkeypatch) -> list:
    """The miner AFFIRMATIVELY reports no live domain."""
    seen: list[str] = []

    def _probe(vm, node_id_arg):
        seen.append(node_id_arg)
        return False

    monkeypatch.setattr(effects, "poll_domain_running_on", _probe)
    return seen


def _tick_without_ever_expiring_the_phase(times: int = 6) -> None:
    """Drive the jobs WITHOUT touching `phase_started_at`, so anything
    that happens happened on the evidence, not on a timeout."""
    for _ in range(times):
        service.tick_once()


# ══ 1. a launch refused at placement leaves no active VM with a KEK ═══


def test_a_launch_refused_at_placement_leaves_no_active_vm_with_a_live_kek(
    fx, no_probe_allowed
) -> None:
    """THE defect, end to end and with NO operator in the loop: build
    `vm-fedora-3`'s exact live shape, run the orchestration tick, and
    the row must end up `destroyed` with its per-VM Vault-Transit key
    destroyed."""
    vm = _never_placed_vm()
    _placement_refused_launch_job()
    fx.eol_ack = None  # there is no guest, so there is never an ack

    _tick_without_ever_expiring_the_phase()

    vm.refresh_from_db()
    assert vm.state == VmState.DESTROYED
    assert fx.did("crypto_erase_kek_transit")
    job = DecommissionJob.objects.get(vm=vm)
    assert job.state == DecommissionState.DONE.value
    # Not a forced reclaim: nothing failed to ack, there was nothing to
    # ack — and no miner is quarantined for a VM it was never told about.
    assert job.forced is False
    assert job.eol_ack_verified is False
    assert job.quarantine_node_id == ""


def test_the_kek_dies_before_the_row_is_tombstoned(fx, no_probe_allowed) -> None:
    """The ordering the 37-orphan sweep was caused by getting wrong. §24
    sequences erase-then-tombstone and this path inherits it unchanged —
    observed from INSIDE the erase, which is the only place that can tell
    a tombstone-first implementation from a tombstone-last one."""
    vm = _never_placed_vm()
    _placement_refused_launch_job()
    fx.eol_ack = None
    seen_state: list[str] = []

    real_erase = fx.crypto_erase_kek_transit

    def _record(vm_arg):
        seen_state.append(Vm.objects.get(vm_id=vm_arg.vm_id).state)
        return real_erase(vm_arg)

    effects.crypto_erase_kek_transit = _record
    try:
        _tick_without_ever_expiring_the_phase()
    finally:
        effects.crypto_erase_kek_transit = real_erase

    # The row was still FENCED (`decommissioning`), never `destroyed`,
    # at the instant the KEK died — and never `active` either, so no
    # window exists in which a dead KEK is advertised as a live VM.
    assert seen_state == [VmState.DECOMMISSIONING.value]
    vm.refresh_from_db()
    assert vm.state == VmState.DESTROYED


def test_no_miner_was_ever_chosen_is_an_answer_not_an_unanswered_question(
    no_probe_allowed,
) -> None:
    """`_abandoned_probe_target` is `""` because the scheduler never
    picked a host — so there is nowhere a guest could be running. That
    emptiness is the same fact §24's crypto-erase already acts on
    (`destroy-skipped:no-miner-ever-recorded`)."""
    vm = _never_placed_vm()
    _placement_refused_launch_job()

    assert service._abandoned_probe_target(vm) == ""
    assert service.no_miner_was_ever_chosen(vm) is True
    assert service.cmdline_was_baked(vm) is False
    assert service.never_ran_veto(vm) is None


# ══ 2. ⛔ a VM that DID run still requires its ack ════════════════════


def test_a_vm_that_DID_run_is_refused_the_ticket_freeze_without_a_nonce(
    fx, domain_down
) -> None:
    """THE anti-overshoot test. The no-nonce relaxation is ANDed with
    `never_ran_veto`, so a VM with positive evidence that a guest existed
    is still refused at `Draining` — the ack requirement is intact for
    every VM it was ever meant to protect."""
    vm = _ran_vm(eol_nonce=None)

    job = service.start_decommission(vm=vm, decided_by=_actor("dec-ran"))
    _tick_without_ever_expiring_the_phase()

    vm.refresh_from_db()
    assert vm.state == VmState.ACTIVE  # never fenced, never erased
    assert not fx.did("crypto_erase_kek_transit")
    job.refresh_from_db()
    assert job.state == DecommissionState.DRAINING.value  # stuck, loudly

    # And the refusal NAMES the evidence, so an operator reading it can
    # see it was refused BECAUSE a guest existed.
    with pytest.raises(service.EffectError) as exc:
        service._decommission_vm(job)
    assert "cannot prove no guest was ever created" in str(exc.value)
    assert "host-bound:miner-a" in str(exc.value)


@pytest.mark.parametrize(
    "field,value,expected",
    [
        ("host", "miner-a", "host-bound:miner-a"),
        ("boot_phase", VmBootPhase.KEK_RELEASED.value, "boot-phase:kek_released"),
        ("generation", 2, "generation:2"),
    ],
)
def test_each_sign_of_a_guest_alone_refuses_the_no_nonce_freeze(
    fx, domain_down, field, value, expected
) -> None:
    """One positive record of a guest is enough on its own. Each of these
    is a fix that went too far if it ever stops refusing."""
    vm = _never_placed_vm(**{field: value})
    _placement_refused_launch_job()

    assert service.never_ran_veto(vm) == expected
    service.start_decommission(vm=vm, decided_by=_actor(f"dec-{field}"))
    _tick_without_ever_expiring_the_phase()

    vm.refresh_from_db()
    assert vm.state == VmState.ACTIVE
    assert not fx.did("crypto_erase_kek_transit")


def test_a_running_vm_is_never_swept_even_with_no_nonce(fx, domain_down) -> None:
    """And the reap does not reach it either — a VM that ran is not an
    abandoned launch, whatever its nonce column says."""
    _ran_vm(eol_nonce=None)

    assert service.sweep_abandoned_launches() == 0
    assert DecommissionJob.objects.count() == 0


# ══ 3. #968's case is untouched ══════════════════════════════════════


def test_968_a_vm_with_a_nonce_but_no_ack_still_takes_the_existing_path(
    fx, domain_down
) -> None:
    """The ADJACENT case: dispatch failed AFTER the register, so a
    cmdline WAS baked and `eol_nonce` is present. `_decommission_vm`'s
    precondition is satisfied and never consults the new branch; #968's
    `never_ran_veto` shortcut is what carries it to the crypto-erase, and
    it still probes the miner its order was sent to."""
    vm = _never_placed_vm(
        vm_id="vm-fed-1",
        eol_nonce=b"\x11" * 32,
        launch_abandoned_outcome="dispatch-failed-after-register",
        launch_abandoned_registered=True,
    )
    now = timezone.now()
    LaunchJob.objects.create(
        job_id="job-vm-fed-1",
        vm_id="vm-fed-1",
        tenant_id="t-stamp",
        flavor="small",
        spec_json={"vm_id": "vm-fed-1"},
        userdata_vault_path="x/vm-fed-1/userdata",
        userdata_vault_version=1,
        kek_vault_path="x/vm-fed-1/luks-kek",
        state=LaunchJobState.FAILED.value,
        reason="dispatch-failed-after-register",
        miner_id="miner-c",
        phase_started_at=now,
        finished_at=now,
        decided_by=_actor("worker-vm-fed-1"),
    )
    fx.eol_ack = None

    _tick_without_ever_expiring_the_phase()

    vm.refresh_from_db()
    assert vm.state == VmState.DESTROYED
    job = DecommissionJob.objects.get(vm=vm)
    assert job.reason == "never-ran:no-guest-was-ever-created"
    # #968's evidence path, not this PR's: the miner WAS asked.
    assert set(domain_down) == {"miner-c"}


def test_968_a_dark_miner_still_blocks_the_post_register_phantom(
    fx, monkeypatch
) -> None:
    """And the probe still vetoes when a miner exists but does not
    answer. Only the "no miner was ever chosen" emptiness is an answer."""
    vm = _never_placed_vm(
        vm_id="vm-fed-2",
        eol_nonce=b"\x11" * 32,
        launch_abandoned_outcome="dispatch-failed-after-register",
        launch_abandoned_registered=True,
    )
    now = timezone.now()
    LaunchJob.objects.create(
        job_id="job-vm-fed-2",
        vm_id="vm-fed-2",
        tenant_id="t-stamp",
        flavor="small",
        spec_json={"vm_id": "vm-fed-2"},
        userdata_vault_path="x/vm-fed-2/userdata",
        userdata_vault_version=1,
        kek_vault_path="x/vm-fed-2/luks-kek",
        state=LaunchJobState.FAILED.value,
        reason="dispatch-failed-after-register",
        miner_id="miner-c",
        phase_started_at=now,
        finished_at=now,
        decided_by=_actor("worker-vm-fed-2"),
    )
    monkeypatch.setattr(effects, "poll_domain_running_on", lambda vm, n: None)

    assert service.never_ran_veto(vm) == "domain-unproven"
    assert service.sweep_abandoned_launches() == 1
    assert DecommissionJob.objects.count() == 0


# ══ 4. the reap reaches it WITHOUT an operator ═══════════════════════


def test_the_sweep_opens_the_teardown_itself(fx, no_probe_allowed) -> None:
    """A fix that only works when an operator remembers to call §24 by
    hand is not a fix. `sweep_abandoned_launches` — the orchestration
    tick's own sweep — must open the job."""
    vm = _never_placed_vm()
    _placement_refused_launch_job()

    assert DecommissionJob.objects.count() == 0
    assert service.sweep_abandoned_launches() == 1

    job = DecommissionJob.objects.get(vm=vm)
    assert job.state == DecommissionState.DRAINING.value
    assert job.decided_by.name == service._ABANDONED_REAP_ACTOR


def test_a_previously_FAILED_teardown_does_not_strand_it(fx, no_probe_allowed) -> None:
    """The live row's compounding shape: `vm-fedora-3` already carries
    a `failed` DecommissionJob from the refusal this PR removes.

    Two things have to hold for that not to be an operator DB fixup. The
    VM must still be `state=active` — the old refusal raised BEFORE the
    Active→Decommissioning CAS, so it is (a failure at a LATER §24 step
    would leave it `decommissioning`, outside the sweep's filter AND
    refused by `start_decommission`). And a TERMINAL job must not read as
    in-flight, or `_has_active_job` would veto forever."""
    vm = _never_placed_vm()
    _placement_refused_launch_job()
    DecommissionJob.objects.create(
        job_id="dead-job",
        vm=vm,
        state=DecommissionState.FAILED.value,
        reason=(
            "draining:vm has no eol_nonce (launch did not bake "
            "hippius.eol_nonce) — cannot decommission"
        ),
        phase_started_at=timezone.now() - timedelta(hours=2),
        finished_at=timezone.now() - timedelta(hours=2),
        decided_by=_actor("dec-old"),
    )
    fx.eol_ack = None

    assert vm.state == VmState.ACTIVE
    assert service._abandoned_reap_veto(vm) is None
    _tick_without_ever_expiring_the_phase()

    vm.refresh_from_db()
    assert vm.state == VmState.DESTROYED
    assert fx.did("crypto_erase_kek_transit")
    assert DecommissionJob.objects.filter(vm=vm).count() == 2


def test_the_reap_still_honours_the_grace_window_and_the_kill_switch(
    fx, no_probe_allowed, monkeypatch
) -> None:
    """Widening WHICH rows the reap may touch must not widen WHEN. The
    grace window and the operator kill switch are unchanged."""
    from django.conf import settings

    vm = _never_placed_vm(launch_abandoned_at=timezone.now())
    _placement_refused_launch_job()

    assert service.sweep_abandoned_launches() == 1  # in grace
    assert DecommissionJob.objects.count() == 0

    Vm.objects.filter(id=vm.id).update(
        launch_abandoned_at=timezone.now() - timedelta(hours=3)
    )
    monkeypatch.setattr(settings, "VALI_ABANDONED_LAUNCH_REAP_ENABLED", False)

    assert service.sweep_abandoned_launches() == 1  # reap disabled
    assert DecommissionJob.objects.count() == 0


def test_an_unmarked_never_baked_row_is_never_touched(fx, no_probe_allowed) -> None:
    """A launch still in flight has the SAME `active host='' eol_nonce=
    None` shape for its whole preflight — the nonce is not stamped until
    step 4b. Only the abandoned marker separates the two, and without it
    this must stay invisible to the reap."""
    vm = _never_placed_vm(launch_abandoned_at=None, launch_abandoned_outcome="")

    assert service.never_ran_veto(vm) == "no-abandoned-launch-record"
    assert service.sweep_abandoned_launches() == 0
    assert DecommissionJob.objects.count() == 0
