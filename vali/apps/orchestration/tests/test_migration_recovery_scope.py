"""§25 — reboot-recovery bookkeeping is scoped to the host it describes.

The defect: `orchestration.RebootRecovery` is a per-VM row holding
HOST-scoped state — the relaunch cap, the backoff window, the down/wedged
debounces — and no migration path touched any of it. A VM that burned its
relaunch budget on a flaky SOURCE arrived at a healthy DESTINATION
already at the cap, `last_outcome="attempts-exhausted"`, and could never
be reboot-recovered there. The VM runs fine until the destination
reboots, at which point the recovery that exists for exactly that event
refuses to act. Migration is the remedy for a bad host, and the counter
that says "give up on this VM" survived the remedy.

These drive the REAL `start_migration` → `tick_once` choreography and
then the REAL reboot-recovery scan, so a fix that never reaches the
migration path — or that re-scopes the wrong fields — fails here. The
scan's own host bookkeeping is pinned in `test_reboot_recovery.py`.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any

import pytest
from django.test import override_settings
from django.utils import timezone

from apps.lifecycle.models import Vm, VmState
from apps.miners.models import MinerIdentity, MinerStatus
from apps.orchestration import service
from apps.orchestration.models import MigrationJob, MigrationState, RebootRecovery

from .conftest import FakeEffects
from .factories import make_service_client, make_vm

pytestmark = pytest.mark.django_db

SRC_NODE = "aa" * 32
DST_NODE = "bb" * 32


@pytest.fixture(autouse=True)
def _registered_miners():
    """Source + destination registered, ALIVE (on-chain Active + a fresh
    heartbeat) and of one CPU generation — everything the §25 same-gen
    gate and the reboot-recovery alive-gate need."""
    for miner_id, chain_node_id, pubkey in (
        ("node-src", SRC_NODE, "11" * 32),
        ("node-dst", DST_NODE, "22" * 32),
    ):
        MinerIdentity.objects.get_or_create(
            miner_id=miner_id,
            defaults={
                "pubkey_hex": pubkey,
                "platform_id": chain_node_id * 2,
                "chain_node_id": chain_node_id,
                "last_seen_at": timezone.now(),
                "status": MinerStatus.ACTIVE,
            },
        )


def _rec(vm: Vm) -> RebootRecovery:
    return RebootRecovery.objects.get(vm=vm)


def _exhausted(vm: Vm, *, host: str = "node-src", attempts: int = 2) -> RebootRecovery:
    """The state a flaky SOURCE host leaves behind: seen running once,
    relaunch budget spent, backoff armed, given up on."""
    now = timezone.now()
    return RebootRecovery.objects.create(
        vm=vm,
        host=host,
        seen_running=True,
        consecutive_down=4,
        consecutive_wedged=1,
        attempts=attempts,
        last_relaunch_at=now - timedelta(minutes=5),
        next_attempt_at=now + timedelta(hours=1),
        last_outcome="attempts-exhausted",
    )


def _start(vm: Vm) -> MigrationJob:
    return service.start_migration(
        vm=vm, dest_node_id="node-dst", decided_by=make_service_client()
    )


def _drive(job: MigrationJob, ticks: int = 25) -> MigrationJob:
    for _ in range(ticks):
        service.tick_once()
        job.refresh_from_db()
        if job.state in (MigrationState.DONE.value, MigrationState.FAILED.value):
            break
    return job


def _to_awaiting_ack(job: MigrationJob) -> None:
    """Drive the job up to (not through) the activation CAS."""
    for _ in range(10):
        service.tick_once()
        job.refresh_from_db()
        if job.state == MigrationState.AWAITING_SOURCE_ACK.value:
            return
    raise AssertionError(f"job stuck in {job.state!r}")


# ─── the fix ─────────────────────────────────────────────────────────


def test_a_completed_migration_re_scopes_the_recovery_state(
    fx: FakeEffects,
) -> None:
    vm = make_vm(generation=5, host="node-src")
    before = _exhausted(vm)

    job = _drive(_start(vm))

    assert job.state == MigrationState.DONE.value
    vm.refresh_from_db()
    assert vm.host == "node-dst"
    rec = _rec(vm)
    # The host-scoped half is back to zero, and the row now NAMES the
    # host its counters describe.
    assert rec.host == "node-dst"
    assert rec.attempts == 0
    assert rec.next_attempt_at is None
    assert rec.consecutive_down == 0
    assert rec.consecutive_wedged == 0
    assert rec.last_relaunch_at is None
    # Recorded, not blanked: the audit line for WHY the budget reset —
    # and it clears the "attempts-exhausted" log-once latch.
    assert rec.last_outcome == service.RESCOPED_OUTCOME
    # The version bump is what fences an in-flight relaunch claim.
    assert rec.version > before.version


def test_a_vm_at_the_cap_is_recoverable_on_its_new_host(
    fx: FakeEffects, monkeypatch
) -> None:
    """The whole point, end to end: the destination reboots and the VM
    comes back. Before the fix this VM was permanently un-recoverable —
    the cap it hit on the source followed it."""
    vm = make_vm(generation=5, host="node-src")
    _exhausted(vm)
    assert _drive(_start(vm)).state == MigrationState.DONE.value

    relaunched: list[tuple[str, str]] = []
    monkeypatch.setattr(
        service,
        "_reboot_recovery_relaunch",
        lambda vm, node_id: relaunched.append((vm.vm_id, node_id)) or True,
    )
    monkeypatch.setattr(service.effects, "poll_domain_running", lambda vm: False)

    with override_settings(
        VALI_REBOOT_RECOVERY_ENABLED=True,
        VALI_REBOOT_RECOVERY_DEBOUNCE_POLLS=1,
        VALI_REBOOT_RECOVERY_MAX_ATTEMPTS=2,
    ):
        assert service.reboot_recovery_once() == 1

    assert relaunched == [(vm.vm_id, "node-dst")]


# ─── seen_running is PRESERVED, and that is load-bearing ─────────────


def test_the_move_preserves_seen_running(fx: FakeEffects) -> None:
    """`seen_running` is a fact about the VM's PAST (its domain was once
    observed running), not host-scoped policy, so the move does not
    falsify it."""
    vm = make_vm(generation=5, host="node-src")
    _exhausted(vm)

    assert _drive(_start(vm)).state == MigrationState.DONE.value

    assert _rec(vm).seen_running is True


def test_a_destination_that_never_comes_up_is_still_recovered(
    fx: FakeEffects, monkeypatch
) -> None:
    """WHY `seen_running` must survive the move — the case that decides
    it. The migration reports `Done` but the destination's domain never
    reads `running` (§25's done-gate is "domain launched", not "guest
    unlocked"). Clearing `seen_running` would re-arm ONLY by observing
    the destination running — i.e. exactly when recovery is NOT needed —
    so this VM would be down forever with no automated remedy: the same
    availability defect this change closes, pointed the other way.

    The zombie hazard `seen_running` guards against does not apply here:
    §25 activation is reached only after a verified source-stopped ack,
    which a LIVE source guest signs from inside itself.
    """
    vm = make_vm(generation=5, host="node-src")
    RebootRecovery.objects.create(vm=vm, host="node-src", seen_running=True)
    assert _drive(_start(vm)).state == MigrationState.DONE.value

    relaunched: list[str] = []
    monkeypatch.setattr(
        service,
        "_reboot_recovery_relaunch",
        lambda vm, node_id: relaunched.append(node_id) or True,
    )
    # The destination is DOWN from the very first poll — it is never
    # observed running on its new host.
    monkeypatch.setattr(service.effects, "poll_domain_running", lambda vm: False)

    with override_settings(
        VALI_REBOOT_RECOVERY_ENABLED=True, VALI_REBOOT_RECOVERY_DEBOUNCE_POLLS=2
    ):
        assert service.reboot_recovery_once() == 0
        assert service.reboot_recovery_once() == 1

    assert relaunched == ["node-dst"]


# ─── nothing is re-scoped unless the CAS actually moved the VM ───────


def test_a_failed_migration_re_scopes_nothing(fx: FakeEffects) -> None:
    """The destination reports its restore/boot FAILED. §25 fails closed:
    the VM is never activated (it stays fenced on the source), so its
    relaunch budget must stay exactly as the source left it."""
    fx.dest_activation_status = "failed"
    vm = make_vm(generation=5, host="node-src")
    before = _exhausted(vm)

    job = _drive(_start(vm))

    assert job.state != MigrationState.DONE.value
    vm.refresh_from_db()
    assert vm.state == VmState.MIGRATING
    rec = _rec(vm)
    assert (rec.host, rec.attempts, rec.version) == (
        "node-src",
        before.attempts,
        before.version,
    )
    assert rec.last_outcome == "attempts-exhausted"
    assert rec.next_attempt_at is not None


def test_an_aborted_activation_re_scopes_nothing(fx: FakeEffects) -> None:
    """The dest never even accepts the order — the VM stays fenced on the
    source, so the source's bookkeeping still describes where it runs."""
    fx.fail.add("dispatch_migrate_activate")
    vm = make_vm(generation=5, host="node-src")
    before = _exhausted(vm)

    _drive(_start(vm), ticks=10)

    vm.refresh_from_db()
    assert vm.state == VmState.MIGRATING
    rec = _rec(vm)
    assert (rec.host, rec.attempts, rec.version) == (
        "node-src",
        before.attempts,
        before.version,
    )


def test_a_lost_cas_re_scopes_nothing(fx: FakeEffects, monkeypatch) -> None:
    """The re-scope rides INSIDE the activation CAS. When the CAS loses
    (the row moved under us) the VM did not activate here, so its
    relaunch budget must not be re-issued either."""
    vm = make_vm(generation=5, host="node-src")
    before = _exhausted(vm)
    job = _start(vm)
    _to_awaiting_ack(job)

    original = service._mop_up_boot_phase

    def _steal_the_row():
        Vm.objects.filter(id=vm.id).update(version=vm.version + 99)
        return original()

    monkeypatch.setattr(service, "_mop_up_boot_phase", _steal_the_row)

    with pytest.raises(service.EffectError):
        service._activate_dest_vm(MigrationJob.objects.get(id=job.id))

    vm.refresh_from_db()
    assert vm.host == "node-src"
    rec = _rec(vm)
    assert (rec.host, rec.attempts, rec.version) == (
        "node-src",
        before.attempts,
        before.version,
    )


def test_the_recovery_state_rolls_back_with_a_failed_sibling(
    fx: FakeEffects, monkeypatch
) -> None:
    """Half of the atomicity claim: when a LATER statement in the
    activation transaction fails, the re-scope rolls back with `Vm.host`.
    Written in a transaction of its own the two could disagree — a VM
    whose counters name a host it does not run on is the very defect this
    closes."""
    from apps.scheduler import service as sched

    vm = make_vm(generation=5, host="node-src")
    before = _exhausted(vm)
    job = _start(vm)
    _to_awaiting_ack(job)

    def _boom(*args: Any, **kwargs: Any):
        raise sched.PlacementMoveConflict("injected")

    monkeypatch.setattr(sched, "move_placement_to_node", _boom)

    with pytest.raises(service.EffectError):
        service._activate_dest_vm(MigrationJob.objects.get(id=job.id))

    vm.refresh_from_db()
    assert vm.host == "node-src"
    assert vm.state == VmState.MIGRATING
    rec = _rec(vm)
    assert (rec.host, rec.attempts, rec.version) == (
        "node-src",
        before.attempts,
        before.version,
    )


def test_a_failing_re_scope_rolls_the_host_back(
    fx: FakeEffects, monkeypatch
) -> None:
    """The other half, and the one that pins the re-scope INSIDE the CAS:
    if it cannot be written, `Vm.host` does not move either. Written after
    the transaction closes, the host would already be committed to the
    destination while the counters still named the source — exactly the
    disagreement the atomicity is for."""
    vm = make_vm(generation=5, host="node-src")
    _exhausted(vm)
    job = _start(vm)
    _to_awaiting_ack(job)

    def _boom(*args: Any, **kwargs: Any) -> bool:
        raise RuntimeError("injected")

    monkeypatch.setattr(service, "rescope_reboot_recovery_to_host", _boom)

    with pytest.raises(RuntimeError):
        service._activate_dest_vm(MigrationJob.objects.get(id=job.id))

    vm.refresh_from_db()
    assert vm.host == "node-src"
    assert vm.state == VmState.MIGRATING


# ─── idempotence + the in-flight relaunch it must fence ──────────────


def test_a_re_driven_activation_re_scopes_once(fx: FakeEffects) -> None:
    vm = make_vm(generation=5, host="node-src")
    _exhausted(vm)
    job = _drive(_start(vm))
    settled = _rec(vm).version

    service._activate_dest_vm(MigrationJob.objects.get(id=job.id))
    service._activate_dest_vm(MigrationJob.objects.get(id=job.id))

    rec = _rec(vm)
    assert rec.host == "node-dst"
    assert rec.version == settled  # no churn, no re-issued budget


def test_an_in_flight_relaunch_claim_is_fenced_by_the_move(
    fx: FakeEffects, monkeypatch
) -> None:
    """A reboot-recovery tick that read the row BEFORE the move must not
    dispatch: its stale read would both resurrect the pre-move `attempts`
    count and aim the relaunch at the host the VM just left. The version
    bump in the re-scope is what makes it lose the claim."""
    vm = make_vm(generation=5, host="node-src")
    # A row with NOTHING else holding the fire back — no spent budget, no
    # armed backoff — so the CAS is the only thing that can stop it.
    RebootRecovery.objects.create(vm=vm, host="node-src", seen_running=True)
    stale = _rec(vm)  # the tick's pre-move read

    assert _drive(_start(vm)).state == MigrationState.DONE.value

    relaunched: list[str] = []
    monkeypatch.setattr(
        service,
        "_reboot_recovery_relaunch",
        lambda vm, node_id: relaunched.append(node_id) or True,
    )

    with override_settings(VALI_REBOOT_RECOVERY_MAX_ATTEMPTS=2):
        fired = service._reboot_recovery_fire(
            vm, stale, "node-src", now=timezone.now(), reason="DOWN", polls=3
        )

    assert fired is False
    assert relaunched == []
    assert _rec(vm).attempts == 0


def test_a_move_to_the_host_already_named_records_nothing() -> None:
    """The guard that keeps the cap CAPPING. Reboot-recovery's own
    relaunch re-runs `launch_on_miner` on the SAME host; a "move" to the
    host the counters already name must be a no-op, or the budget would be
    re-issued between attempts and the cap never reached."""
    vm = make_vm(generation=5, host="node-src")
    before = _exhausted(vm)

    assert service.rescope_reboot_recovery_to_host(vm, new_host="node-src") is False

    rec = _rec(vm)
    assert (rec.attempts, rec.version, rec.last_outcome) == (
        before.attempts,
        before.version,
        "attempts-exhausted",
    )


def test_a_vm_with_no_recovery_row_is_left_alone(fx: FakeEffects) -> None:
    """Nothing to re-scope ⇒ no row is invented. The scan creates it
    lazily, stamped with the host it first sees."""
    vm = make_vm(generation=5, host="node-src")

    assert _drive(_start(vm)).state == MigrationState.DONE.value

    assert not RebootRecovery.objects.filter(vm=vm).exists()


# ─── the backfill (migration 0012) ───────────────────────────────────


def _run_backfill() -> None:
    """Run migration 0012's data pass against the CURRENT models.

    Imported by path because the module name starts with a digit. The
    historical models 0012 sees are field-identical to these, so calling
    it with the live app registry exercises the same code the deploy runs.
    """
    import importlib

    from django.apps import apps as django_apps

    importlib.import_module(
        "apps.orchestration.migrations.0012_rebootrecovery_host"
    )._forward(django_apps, None)


def _pre_fix_migration(vm: Vm, *, finished_at: Any) -> MigrationJob:
    """The record a migration completed BEFORE this fix leaves behind:
    a Done job onto the host the VM now runs on."""
    return MigrationJob.objects.create(
        job_id=f"job-{vm.vm_id}",
        vm=vm,
        source_node_id="node-src",
        dest_node_id="node-dst",
        source_gen=5,
        new_gen=6,
        state=MigrationState.DONE.value,
        phase_started_at=finished_at,
        finished_at=finished_at,
        decided_by=make_service_client(),
    )


def test_the_backfill_repairs_a_vm_migrated_before_the_fix() -> None:
    """Without it the fix reaches only FUTURE migrations, and every VM
    already moved stays un-recoverable on the host it now runs on."""
    vm = make_vm(generation=6, host="node-dst")
    before = _exhausted(vm, host="")  # pre-fix rows carry no host stamp
    _pre_fix_migration(vm, finished_at=timezone.now())

    _run_backfill()

    rec = _rec(vm)
    assert rec.host == "node-dst"
    assert rec.attempts == 0
    assert rec.next_attempt_at is None
    assert rec.consecutive_down == 0
    assert rec.consecutive_wedged == 0
    assert rec.last_outcome == "host-changed:backfill"
    assert rec.version > before.version
    assert rec.seen_running is True  # never touched


def test_the_backfill_keeps_a_cap_it_cannot_prove_belongs_elsewhere() -> None:
    """The attempts were burned AFTER the migration finished — on the
    host the VM runs on NOW. Under uncertainty the fail-safe direction
    for an attempt cap is to KEEP it: a wrongly-kept cap is one VM an
    operator clears by hand, a wrongly-cleared one is a relaunch budget
    silently re-issued fleet-wide."""
    vm = make_vm(generation=6, host="node-dst")
    before = _exhausted(vm, host="")
    _pre_fix_migration(vm, finished_at=timezone.now() - timedelta(days=1))

    _run_backfill()

    rec = _rec(vm)
    assert rec.host == "node-dst"  # stamped, so the scan can act later
    assert rec.attempts == before.attempts
    assert rec.last_outcome == "attempts-exhausted"
    assert rec.version == before.version


def test_the_backfill_leaves_a_never_migrated_vm_alone() -> None:
    vm = make_vm(generation=5, host="node-src")
    before = _exhausted(vm, host="")

    _run_backfill()

    rec = _rec(vm)
    assert rec.host == "node-src"
    assert (rec.attempts, rec.version) == (before.attempts, before.version)
