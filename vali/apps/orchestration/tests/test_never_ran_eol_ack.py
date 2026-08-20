"""§24 must not wait for an EOL ack it can PROVE cannot come.

## The defect, measured live 2026-08-13

A fedora launch failed `dispatch-failed-after-register` on miner-3
(miner-side `class=libvirt-driver/create` — the domain was never
created), leaving the phantom this repo already knows: `state=active`,
`host=''`, a live per-VM Vault-Transit KEK, no guest anywhere. Its §24
teardown then sat in `awaiting_eol_ack`:

    stamp-fed-1 decomm: awaiting_eol_ack | forced: False | ack: False
    Vm: state=decommissioning boot_phase=''
    phase_started_at 13:55:55  →  ack_timeout 600 s  →  forced 14:05:55

Ten minutes of a live KEK, waiting for a guest-signed `StoppedAck` from
a guest that was never created — and vali held the proof throughout:
`boot_phase=''`, no guest signal, never bound to a host, the launch's own
`dispatch-failed-after-register`, and miner-3 answering `running: false`
to the live domain probe. The wait then ends in a "forced reclaim" that
records `forced=True` and §13-quarantines the host for failing to ack for
a guest it never managed to start.

That is this repo's recurring shape: treating "no ack yet" as "the guest
might still ack" while holding positive evidence that no guest ever ran.

## The one thing these tests exist to protect

⛔ The ack requirement for a VM that DID run. The guest-signed ack is the
proof of a clean stop; skipping it for a real guest would be a security
regression, and it is a far worse outcome than the slow teardown above.
So the tests below are deliberately lopsided: ONE pins the shortcut, and
the rest pin every independent reason the shortcut must NOT apply. Each
`_still_waits` case is a fix that went too far.
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

VM_ID = "stamp-fed-1"


# ── builders ─────────────────────────────────────────────────────────


def _actor(name: str = "operator") -> ServiceClient:
    return ServiceClient.objects.create(
        scope=PrincipalScope.OPERATOR.value, name=name
    )


def _never_ran_vm(vm_id: str = VM_ID, **fields) -> Vm:
    """The live shape: a launch that failed AFTER the KBS register, so the
    row is `active` with no host, no boot milestone, and a live KEK."""
    fields.setdefault("launch_abandoned_at", timezone.now())
    fields.setdefault("launch_abandoned_outcome", "dispatch-failed-after-register")
    fields.setdefault("launch_abandoned_registered", True)
    return Vm.objects.create(
        vm_id=vm_id,
        lease_id=f"lease-{vm_id}",
        tenant_id="t-stamp",
        state=VmState.ACTIVE.value,
        generation=fields.pop("generation", 1),
        signing_generation=fields.pop("signing_generation", 1),
        host=fields.pop("host", ""),
        lifecycle_vk=bytes(32),
        eol_nonce=b"\x11" * 32,
        **fields,
    )


def _ran_vm(vm_id: str = "realtenant-1") -> Vm:
    """A VM that DID run: a miner accepted its dispatch (so `host` is
    stamped), it reported `running`, it spoke from inside the guest, and
    the reconcile loop saw its domain up."""
    vm = Vm.objects.create(
        vm_id=vm_id,
        lease_id=f"lease-{vm_id}",
        tenant_id="t-real",
        state=VmState.ACTIVE.value,
        generation=1,
        signing_generation=1,
        host="miner-1",
        lifecycle_vk=bytes(32),
        eol_nonce=b"\x11" * 32,
        boot_phase=VmBootPhase.RUNNING.value,
        boot_phase_at=timezone.now(),
        guest_signal_at=timezone.now(),
        guest_signal_kind="served_receipt",
    )
    RebootRecovery.objects.create(vm=vm, host="miner-1", seen_running=True)
    _launch_job(vm_id, state=LaunchJobState.SUCCEEDED.value, miner_id="miner-1")
    return vm


def _launch_job(
    vm_id: str = VM_ID,
    *,
    state: str = LaunchJobState.FAILED.value,
    miner_id: str = "miner-3",
) -> LaunchJob:
    now = timezone.now()
    return LaunchJob.objects.create(
        job_id=f"job-{vm_id}-{state}",
        vm_id=vm_id,
        tenant_id="t-stamp",
        flavor="small",
        spec_json={"vm_id": vm_id},
        userdata_vault_path=f"x/{vm_id}/userdata",
        userdata_vault_version=1,
        kek_vault_path=f"x/{vm_id}/luks-kek",
        state=state,
        reason="dispatch-failed-after-register",
        miner_id=miner_id,
        phase_started_at=now,
        finished_at=now if state in ("succeeded", "failed") else None,
        decided_by=_actor(f"worker-{vm_id}-{state}"),
    )


@pytest.fixture
def domain_down(monkeypatch) -> list:
    """The miner AFFIRMATIVELY reports no live domain — the only answer
    that may unblock the shortcut. Returns the probed targets."""
    seen: list[str] = []

    def _probe(vm, node_id_arg):
        seen.append(node_id_arg)
        return False

    monkeypatch.setattr(effects, "poll_domain_running_on", _probe)
    return seen


def _decommission(vm: Vm) -> DecommissionJob:
    """Open §24 and run its `Draining` step — exactly what an operator's
    `/decommission` (or the abandoned-launch reap) does."""
    job = service.start_decommission(vm=vm, decided_by=_actor(f"dec-{vm.vm_id}"))
    service.tick_once()
    job.refresh_from_db()
    assert job.state == DecommissionState.AWAITING_EOL_ACK.value
    return job


def _tick_without_ever_expiring_the_phase(times: int = 5) -> None:
    """Drive the job WITHOUT touching `phase_started_at`. Anything that
    happens here happened because of the evidence, not the timeout."""
    for _ in range(times):
        service.tick_once()


# ══ 1. the shortcut — only on PROOF that no guest ever existed ════════


def test_a_vm_that_never_ran_is_erased_without_waiting_the_ack_timeout(
    fx, domain_down
) -> None:
    """THE defect. A post-register dispatch failure never created a
    domain, so no `StoppedAck` can ever be signed. §24 must reach the
    crypto-erase on evidence, not by burning the 600 s ack window."""
    vm = _never_ran_vm()
    _launch_job()
    fx.eol_ack = None  # no guest ⇒ no ack, ever

    job = _decommission(vm)
    _tick_without_ever_expiring_the_phase()

    job.refresh_from_db()
    assert job.state == DecommissionState.DONE.value
    assert fx.did("crypto_erase_kek_transit")
    vm.refresh_from_db()
    assert vm.state == VmState.DESTROYED
    # It asked the one miner that could have been running it.
    assert domain_down == ["miner-3"]


def test_the_shortcut_is_recorded_as_never_ran_not_as_a_forced_reclaim(
    fx, domain_down
) -> None:
    """`forced=True` means "the miner never acked" — a statement about a
    host that had a guest to stop, and the signal §13 quarantines on.
    Recording it here would blame a miner for a guest that was never
    created. And `eol_ack_verified` must stay False: no ack was seen."""
    vm = _never_ran_vm()
    _launch_job()
    fx.eol_ack = None

    job = _decommission(vm)
    _tick_without_ever_expiring_the_phase()

    job.refresh_from_db()
    assert job.forced is False
    assert job.eol_ack_verified is False
    assert job.quarantine_node_id == ""
    assert job.reason == "never-ran:no-guest-was-ever-created"


def test_a_real_ack_still_wins_over_the_shortcut(fx, domain_down) -> None:
    """The ack is polled FIRST. If one is somehow present it is verified
    and takes the clean path, whatever the evidence says."""
    vm = _never_ran_vm()
    _launch_job()
    fx.eol_ack = b"an-ack"

    job = _decommission(vm)
    service.tick_once()

    job.refresh_from_db()
    assert job.eol_ack_verified is True
    assert job.reason != "never-ran:no-guest-was-ever-created"


# ══ 2. ⛔ a VM that DID run still requires its ack ════════════════════


def test_a_vm_that_DID_run_still_requires_its_ack(fx, domain_down) -> None:
    """THE test that matters. A real tenant VM's guest-signed ack is what
    proves a clean stop; a fix that skipped it for a running guest would
    be a security regression, not a speed-up.

    Note `domain_down` is active — the miner says no domain is up (the
    guest has just been stopped by §24's graceful stop, which is the
    NORMAL state of this phase). Liveness alone must never license the
    skip; the VM ran, so its ack is required."""
    vm = _ran_vm()
    fx.eol_ack = None

    job = _decommission(vm)
    _tick_without_ever_expiring_the_phase()

    job.refresh_from_db()
    assert job.state == DecommissionState.AWAITING_EOL_ACK.value
    assert not fx.did("crypto_erase_kek_transit")
    vm.refresh_from_db()
    assert vm.state == VmState.DECOMMISSIONING


def test_a_vm_that_DID_run_takes_the_forced_reclaim_path_untouched(
    fx, domain_down
) -> None:
    """And when its ack really never comes, the ONLY thing that releases
    it is the timeout — still `forced`, still quarantining the host."""
    vm = _ran_vm()
    fx.eol_ack = None
    job = _decommission(vm)

    _tick_without_ever_expiring_the_phase(2)
    job.refresh_from_db()
    assert job.state == DecommissionState.AWAITING_EOL_ACK.value

    DecommissionJob.objects.filter(id=job.id).update(
        phase_started_at=timezone.now() - timedelta(seconds=10_000)
    )
    service.tick_once()

    job.refresh_from_db()
    assert job.forced is True
    assert job.quarantine_node_id == "miner-1"
    assert job.reason == "eol-ack-timeout:forced-reclaim"


def test_a_vm_that_ran_and_ACKS_completes_on_the_verified_ack(fx, domain_down) -> None:
    """The clean path is unchanged: the ack arrives, is verified, and the
    job advances with `eol_ack_verified` and `forced=False`."""
    vm = _ran_vm()
    fx.eol_ack = None
    job = _decommission(vm)
    _tick_without_ever_expiring_the_phase(2)

    fx.eol_ack = b"the-guest-signed-ack"
    service.tick_once()

    job.refresh_from_db()
    assert job.eol_ack_verified is True
    assert job.forced is False


# ══ 3. every INDEPENDENT reason the shortcut must not fire ═══════════


def _apply(vm: Vm, evidence: str) -> None:
    """One positive record that a guest existed, applied to an otherwise
    never-ran-looking row."""
    if evidence == "host-bound":
        Vm.objects.filter(id=vm.id).update(host="miner-3")
    elif evidence == "boot-phase":
        Vm.objects.filter(id=vm.id).update(boot_phase=VmBootPhase.BOOTING.value)
    elif evidence == "guest-signal":
        Vm.objects.filter(id=vm.id).update(guest_signal_at=timezone.now())
    elif evidence == "seen-running":
        RebootRecovery.objects.create(vm=vm, host="miner-3", seen_running=True)
    elif evidence == "generation":
        Vm.objects.filter(id=vm.id).update(generation=2, signing_generation=2)
    elif evidence == "launch-in-flight":
        _launch_job(state=LaunchJobState.RUNNING.value)
    elif evidence == "launch-succeeded":
        _launch_job(state=LaunchJobState.SUCCEEDED.value)
    elif evidence == "no-abandoned-launch-record":
        Vm.objects.filter(id=vm.id).update(launch_abandoned_at=None)
    else:  # pragma: no cover — a typo in the parametrisation
        raise AssertionError(f"unknown evidence {evidence!r}")


@pytest.mark.parametrize(
    "evidence",
    [
        "host-bound",
        "boot-phase",
        "guest-signal",
        "seen-running",
        "generation",
        "launch-in-flight",
        "launch-succeeded",
        "no-abandoned-launch-record",
    ],
)
def test_any_single_positive_record_keeps_the_ack_wait(
    fx, domain_down, evidence
) -> None:
    """Each of these is, on its own, a record that a guest existed (or —
    for the last two — that this launch is not yet known to have given
    up). Any one of them must restore the full ack wait, because the
    conjunction is what makes the proof a proof."""
    vm = _never_ran_vm()
    _launch_job()
    _apply(vm, evidence)
    fx.eol_ack = None

    job = _decommission(vm)
    _tick_without_ever_expiring_the_phase()

    job.refresh_from_db()
    assert job.state == DecommissionState.AWAITING_EOL_ACK.value
    assert not fx.did("crypto_erase_kek_transit")


def test_a_milestone_landing_DURING_the_ack_poll_cancels_the_shortcut(
    fx, domain_down, monkeypatch
) -> None:
    """The evidence is re-read from the database AFTER the ack poll, not
    taken from `job.vm`.

    `job.vm` is the FK instance the handler already dereferenced to make
    the `poll_eol_ack` call — i.e. a snapshot from BEFORE that network
    round-trip. A `booting` milestone landing while the poll is in flight
    is exactly the signal that must cancel the shortcut, and it is
    invisible to the cached instance. This test makes the guest announce
    itself inside the poll."""
    vm = _never_ran_vm()
    _launch_job()

    def _ack_poll_during_which_the_guest_announces_itself(vm_arg):
        Vm.objects.filter(id=vm.id).update(boot_phase=VmBootPhase.BOOTING.value)
        return None

    job = _decommission(vm)
    monkeypatch.setattr(
        effects, "poll_eol_ack", _ack_poll_during_which_the_guest_announces_itself
    )
    _tick_without_ever_expiring_the_phase()

    job.refresh_from_db()
    assert job.state == DecommissionState.AWAITING_EOL_ACK.value
    assert not fx.did("crypto_erase_kek_transit")


def test_a_LIVE_domain_keeps_the_ack_wait(fx, monkeypatch) -> None:
    """THE timed-out-but-actually-started window. A launch can report
    `dispatch-failed-after-register` (Edge 502 at 30 s / vali 45 s) while
    the guest goes on to boot — and its first milestone has not landed
    yet. The miner saying a domain IS up outranks every DB read."""
    vm = _never_ran_vm()
    _launch_job()
    fx.eol_ack = None
    monkeypatch.setattr(effects, "poll_domain_running_on", lambda vm_, n: True)

    job = _decommission(vm)
    _tick_without_ever_expiring_the_phase()

    job.refresh_from_db()
    assert job.state == DecommissionState.AWAITING_EOL_ACK.value
    assert not fx.did("crypto_erase_kek_transit")


def test_an_UNREACHABLE_miner_keeps_the_ack_wait(fx, monkeypatch) -> None:
    """A dark miner tells us NOTHING. `None` must never be read as "no
    domain" — fail closed, wait, let the timeout decide."""
    vm = _never_ran_vm()
    _launch_job()
    fx.eol_ack = None
    monkeypatch.setattr(effects, "poll_domain_running_on", lambda vm_, n: None)

    job = _decommission(vm)
    _tick_without_ever_expiring_the_phase()

    job.refresh_from_db()
    assert job.state == DecommissionState.AWAITING_EOL_ACK.value
    assert not fx.did("crypto_erase_kek_transit")
    # …and the timeout still resolves it, so nothing is stuck forever.
    DecommissionJob.objects.filter(id=job.id).update(
        phase_started_at=timezone.now() - timedelta(seconds=10_000)
    )
    service.tick_once()
    job.refresh_from_db()
    assert job.forced is True


# ══ 4. the predicate itself ══════════════════════════════════════════


def test_never_ran_veto_names_the_evidence(domain_down) -> None:
    """The veto string is the operator's explanation, and the two callers
    (the reap + §24) share it — so it is pinned directly."""
    vm = _never_ran_vm()
    _launch_job()
    assert service.never_ran_veto(vm) is None

    Vm.objects.filter(id=vm.id).update(host="miner-3")
    vm.refresh_from_db()
    assert service.never_ran_veto(vm) == "host-bound:miner-3"


def test_the_reap_and_the_ack_wait_agree_on_the_same_vm(domain_down) -> None:
    """One definition of "never ran", two consumers. If they could
    disagree, a VM could be reaped as a phantom by the sweep while §24
    still waited for its ack — or the reverse."""
    vm = _never_ran_vm()
    _launch_job()

    assert service.never_ran_veto(vm) is None
    assert service._abandoned_reap_veto(vm) is None

    Vm.objects.filter(id=vm.id).update(boot_phase=VmBootPhase.KEK_RELEASED.value)
    vm.refresh_from_db()
    assert service.never_ran_veto(vm) == "boot-phase:kek_released"
    assert service._abandoned_reap_veto(vm) == "boot-phase:kek_released"
