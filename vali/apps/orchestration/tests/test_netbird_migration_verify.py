"""P9/#17 — post-§25 NetBird overlay verification.

What these pin, and why the failure they defend against is silent:

A §25 COLD migration moves the guest-keyed overlay INTACT, so the guest's
own NetBird identity (`/var/lib/netbird/`) survives the move. The
MANAGEMENT-side peer record does not: `mint_netbird_setup_key` mints
every tenant key `ephemeral: True`, and NetBird deletes an ephemeral peer
after ~10 min offline — a window a cold move routinely exceeds (the
dest-activation poll alone budgets 20 min). The destination cannot
re-enrol: cloud-init re-runs `netbird up` every boot (per-boot
instance-id) but with the LAUNCH-time key, which is `usage_limit=1` and
consumed.

Before this sweep NOTHING noticed: `netbird_ip` is carried across the
activation verbatim, the served-receipt self-heal only re-resolves while
that field is EMPTY and the VM is < 30 min old, and tenant telemetry
rides vsock (not the overlay) so the guest keeps reporting `running`.
The migration reported Done over a tenant who could not reach their
machine.
"""

from __future__ import annotations

from datetime import timedelta

import pytest
from django.conf import settings
from django.utils import timezone

from apps.lifecycle.models import Vm, VmNetbirdStatus, VmState
from apps.orchestration import effects, service
from apps.orchestration.models import MigrationJob, MigrationState

from .conftest import FakeEffects
from .factories import make_service_client, make_vm

pytestmark = pytest.mark.django_db


@pytest.fixture(autouse=True)
def _same_gen_miners():
    """§25's same-CPU-gen gate resolves the source/dest generation from the
    registered CHIP_ID length — register both hosts as one generation."""
    from apps.miners.models import MinerIdentity

    MinerIdentity.objects.get_or_create(
        miner_id="node-src",
        defaults={"pubkey_hex": "aa" * 32, "platform_id": "11" * 64},
    )
    MinerIdentity.objects.get_or_create(
        miner_id="node-dst",
        defaults={"pubkey_hex": "bb" * 32, "platform_id": "22" * 64},
    )


def _enrolled_vm(**kwargs) -> Vm:
    """An Active VM that IS on the overlay (a resolved `netbird_ip`)."""
    vm = make_vm(**kwargs)
    Vm.objects.filter(id=vm.id).update(netbird_ip="100.1.2.3")
    vm.refresh_from_db()
    return vm


def _migrate_to_done(vm: Vm) -> MigrationJob:
    """Drive a REAL §25 migration of `vm` to Done via `tick_once`."""
    job = service.start_migration(
        vm=vm, dest_node_id="node-dst", decided_by=make_service_client()
    )
    for _ in range(25):
        service.tick_once()
        job.refresh_from_db()
        if job.state == MigrationState.DONE.value:
            return job
    raise AssertionError(f"migration stuck at {job.state!r}")


# ─── the check is ARMED by the real migration path ───────────────────


def test_migration_arms_the_overlay_check_for_an_enrolled_vm(
    fx: FakeEffects,
) -> None:
    """The end-to-end claim: a §25 migration that reports Done leaves the
    overlay check ARMED. Not tested in isolation — driven through the real
    `start_migration` → `tick_once` choreography, so a fix that never
    reaches the migration path fails here."""
    # The peer is present but not yet connected (the dest guest is still
    # booting) — the sweep must therefore leave the check pending, which
    # is what makes the armed state observable.
    fx.netbird_peer = effects.NetbirdPeer(ip="100.1.2.3", connected=False)
    vm = _enrolled_vm(generation=5, host="node-src")

    job = _migrate_to_done(vm)

    assert job.state == MigrationState.DONE.value
    vm.refresh_from_db()
    assert vm.state == VmState.ACTIVE
    assert vm.host == "node-dst"
    assert vm.netbird_status == VmNetbirdStatus.PENDING.value
    assert vm.netbird_verify_deadline is not None


def test_migration_does_not_arm_a_vm_that_was_never_on_the_overlay(
    fx: FakeEffects,
) -> None:
    """A netbird-DISABLED VM (no resolved `netbird_ip`) has no peer to look
    for — arming it would flag it `lost` forever on the first sweep."""
    fx.netbird_peer = None
    vm = make_vm(generation=5, host="node-src")  # no netbird_ip
    assert vm.netbird_ip == ""

    _migrate_to_done(vm)

    vm.refresh_from_db()
    assert vm.netbird_status == ""
    assert vm.netbird_verify_deadline is None
    # And the sweep never even asked NetBird about it.
    assert not fx.did("resolve_netbird_peer")


def test_a_failed_activation_arms_nothing(fx: FakeEffects) -> None:
    """The marker rides the SAME CAS that flips the row to Active, so a
    migration that never activates cannot leave a stray `pending`."""
    fx.fail.add("dispatch_migrate_activate")
    vm = _enrolled_vm(generation=5, host="node-src")
    job = service.start_migration(
        vm=vm, dest_node_id="node-dst", decided_by=make_service_client()
    )
    for _ in range(10):
        service.tick_once()
        job.refresh_from_db()

    vm.refresh_from_db()
    assert vm.state == VmState.MIGRATING  # never activated
    assert vm.netbird_status == ""
    assert vm.netbird_verify_deadline is None


# ─── the sweep's verdicts ────────────────────────────────────────────


def _armed_vm(*, deadline_delta: timedelta = timedelta(minutes=15)) -> Vm:
    """An Active VM with the post-migration check armed."""
    vm = _enrolled_vm(vm_id="vm-armed", host="node-dst")
    Vm.objects.filter(id=vm.id).update(
        netbird_status=VmNetbirdStatus.PENDING.value,
        netbird_verify_deadline=timezone.now() + deadline_delta,
    )
    vm.refresh_from_db()
    return vm


def test_a_deleted_peer_record_is_lost_immediately(fx: FakeEffects) -> None:
    """The ephemeral-GC case — the peer record is GONE. Terminal the moment
    it is observed: the guest's one-off launch key is consumed, so no
    later boot can re-register it. NOT deferred to the deadline."""
    fx.netbird_peer = None
    vm = _armed_vm()

    service.verify_netbird_enrolments()

    vm.refresh_from_db()
    assert vm.netbird_status == VmNetbirdStatus.LOST.value
    assert vm.netbird_verify_deadline is None
    # The last known address is PRESERVED — it is the only forensic handle
    # an operator has on where the tenant used to be.
    assert vm.netbird_ip == "100.1.2.3"


def test_a_connected_peer_is_ok_and_refreshes_the_ip(fx: FakeEffects) -> None:
    """The must-not-false-flag claim: a VM that IS back on the overlay
    settles `ok`, and its address is refreshed from the live peer."""
    fx.netbird_peer = effects.NetbirdPeer(ip="100.5.5.5", connected=True)
    vm = _armed_vm()

    service.verify_netbird_enrolments()

    vm.refresh_from_db()
    assert vm.netbird_status == VmNetbirdStatus.OK.value
    assert vm.netbird_verify_deadline is None
    assert vm.netbird_ip == "100.5.5.5"


def test_a_booting_peer_stays_pending_inside_the_grace_window(
    fx: FakeEffects,
) -> None:
    """A present-but-disconnected peer is a guest that has not finished
    booting. Flagging it would be a false positive — wait."""
    fx.netbird_peer = effects.NetbirdPeer(ip="100.1.2.3", connected=False)
    vm = _armed_vm(deadline_delta=timedelta(minutes=15))

    service.verify_netbird_enrolments()
    service.verify_netbird_enrolments()  # repeated ticks must not settle it

    vm.refresh_from_db()
    assert vm.netbird_status == VmNetbirdStatus.PENDING.value
    assert vm.netbird_verify_deadline is not None


def test_a_peer_that_never_reconnects_is_lost_after_the_deadline(
    fx: FakeEffects,
) -> None:
    fx.netbird_peer = effects.NetbirdPeer(ip="100.1.2.3", connected=False)
    vm = _armed_vm(deadline_delta=timedelta(minutes=-1))  # already expired

    service.verify_netbird_enrolments()

    vm.refresh_from_db()
    assert vm.netbird_status == VmNetbirdStatus.LOST.value


def test_a_netbird_outage_is_never_laundered_into_lost(fx: FakeEffects) -> None:
    """The API being unreachable is NOT evidence of absence. A NetBird
    outage must not mark every migrated tenant off the overlay — not even
    past the deadline."""
    fx.fail.add("resolve_netbird_peer")
    vm = _armed_vm(deadline_delta=timedelta(minutes=-1))  # deadline blown

    service.verify_netbird_enrolments()

    vm.refresh_from_db()
    assert vm.netbird_status == VmNetbirdStatus.PENDING.value
    assert vm.netbird_verify_deadline is not None


def test_a_vm_that_left_active_is_disarmed_not_flagged(fx: FakeEffects) -> None:
    """A decommissioned / re-migrating VM has no steady state to verify.
    Disarm rather than hold a `pending` that ages into a bogus `lost`."""
    fx.netbird_peer = None
    vm = _armed_vm()
    Vm.objects.filter(id=vm.id).update(state=VmState.DESTROYED)

    service.verify_netbird_enrolments()

    vm.refresh_from_db()
    assert vm.netbird_status == ""
    assert vm.netbird_verify_deadline is None
    assert not fx.did("resolve_netbird_peer")


def test_a_settled_vm_is_not_re_checked(fx: FakeEffects) -> None:
    """The sweep is bounded by the `pending` set — an `ok` / `lost` row is
    never re-probed, so the NetBird API is not polled per-tick forever."""
    fx.netbird_peer = effects.NetbirdPeer(ip="100.1.2.3", connected=True)
    _armed_vm()

    service.verify_netbird_enrolments()
    fx.calls.clear()
    assert service.verify_netbird_enrolments() == 0
    assert not fx.did("resolve_netbird_peer")


def test_settling_is_cas_guarded_on_pending(
    fx: FakeEffects, caplog: pytest.LogCaptureFixture, monkeypatch
) -> None:
    """`_settle_netbird` writes only from `pending`.

    Two tick processes are not a supported topology, but the guard is what
    stops a stale in-memory row (or a re-armed check from a NEWER
    migration that already settled) from overwriting a live verdict — and
    from re-emitting the ERROR every tick."""
    import logging

    monkeypatch.setattr(logging.getLogger("apps"), "propagate", True)
    vm = _armed_vm()
    # Someone else settled it `ok` between our read and our write.
    Vm.objects.filter(id=vm.id).update(
        netbird_status=VmNetbirdStatus.OK.value, netbird_verify_deadline=None
    )

    with caplog.at_level(logging.ERROR, logger="apps.orchestration.service"):
        service._settle_netbird(
            vm, VmNetbirdStatus.LOST.value, reason="stale decision"
        )

    vm.refresh_from_db()
    assert vm.netbird_status == VmNetbirdStatus.OK.value  # not clobbered
    assert not [r for r in caplog.records if r.levelno >= logging.ERROR]


# ─── wiring ──────────────────────────────────────────────────────────


def test_the_sweep_runs_from_the_orchestration_tick(fx: FakeEffects) -> None:
    """Wired into `tick_once` — not merely callable. Without this the
    verdict would only exist in a test."""
    fx.netbird_peer = None
    vm = _armed_vm()

    report = service.tick_once()

    vm.refresh_from_db()
    assert vm.netbird_status == VmNetbirdStatus.LOST.value
    assert report.netbird_checks == 1


def test_the_grace_window_is_operator_tunable(
    fx: FakeEffects, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(settings, "VALI_NETBIRD_VERIFY_GRACE_S", 60.0)
    fx.netbird_peer = effects.NetbirdPeer(ip="100.1.2.3", connected=False)
    vm = _enrolled_vm(generation=5, host="node-src")
    before = timezone.now()

    _migrate_to_done(vm)

    after = timezone.now()
    vm.refresh_from_db()
    assert vm.netbird_verify_deadline is not None
    # The deadline is armed at some instant in [before, after]; with the
    # grace tuned to 60 s it must land exactly 60 s past that instant
    # (the 900 s default would overshoot `after + 60 s`), however long
    # the tick itself took.
    grace = timedelta(seconds=60)
    assert before + grace <= vm.netbird_verify_deadline <= after + grace


# ─── the signal reaches an operator ──────────────────────────────────


def test_lost_is_logged_at_error(
    fx: FakeEffects,
    caplog: pytest.LogCaptureFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`lost` is the ONLY signal this failure produces — it must be loud."""
    import logging

    # `LOGGING` pins `apps` with `propagate: False`; caplog installs its
    # handler on the ROOT logger, so let this one record through.
    monkeypatch.setattr(logging.getLogger("apps"), "propagate", True)
    fx.netbird_peer = None
    vm = _armed_vm()
    with caplog.at_level(logging.ERROR, logger="apps.orchestration.service"):
        service.verify_netbird_enrolments()

    errors = [r for r in caplog.records if r.levelno >= logging.ERROR]
    assert errors, "a tenant dropped off the overlay must log at ERROR"
    assert vm.vm_id in errors[0].getMessage()
    assert "OFF the overlay" in errors[0].getMessage()
