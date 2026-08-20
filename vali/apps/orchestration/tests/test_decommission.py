"""§24 decommission orchestrator tests."""

from __future__ import annotations

from datetime import timedelta

import pytest
from django.utils import timezone

from apps.lifecycle.models import VmState
from apps.orchestration import service
from apps.orchestration.models import DecommissionJob, DecommissionState
from apps.scheduler.models import Placement, PlacementStatus

from .conftest import FakeEffects
from .factories import make_launch_record, make_service_client, make_vm

pytestmark = pytest.mark.django_db


@pytest.fixture(autouse=True)
def _same_gen_miners():
    """Register the source/dest miners same-generation so §25's same-CPU-gen
    gate in `start_migration` passes (see test_migration for the rationale)."""
    from apps.miners.models import MinerIdentity

    MinerIdentity.objects.get_or_create(
        miner_id="node-src",
        defaults={"pubkey_hex": "aa" * 32, "platform_id": "11" * 64},
    )
    MinerIdentity.objects.get_or_create(
        miner_id="node-dst",
        defaults={"pubkey_hex": "bb" * 32, "platform_id": "22" * 64},
    )


def _drive_until(job: DecommissionJob, target: str, *, limit: int = 25) -> None:
    for _ in range(limit):
        service.tick_once()
        job.refresh_from_db()
        if job.state == target:
            return
    raise AssertionError(f"job stuck at {job.state!r}, never reached {target!r}")


def _drive(limit: int = 25) -> None:
    for _ in range(limit):
        service.tick_once()


def _backdate_phase(job: DecommissionJob) -> None:
    DecommissionJob.objects.filter(id=job.id).update(
        phase_started_at=timezone.now() - timedelta(hours=1)
    )


# ─── happy path ──────────────────────────────────────────────────────


def test_decommission_happy_path_end_to_end(fx: FakeEffects) -> None:
    vm = make_vm(generation=5, host="node-src")
    job = service.start_decommission(vm=vm, decided_by=make_service_client())
    assert job.state == DecommissionState.DRAINING.value

    _drive()
    job.refresh_from_db()
    vm.refresh_from_db()
    assert job.state == DecommissionState.DONE.value
    assert job.eol_ack_verified is True
    assert job.forced is False
    assert job.finished_at is not None
    # The VM is a permanent Destroyed tombstone.
    assert vm.state == VmState.DESTROYED
    # §24 draining GRACEFULLY stopped the guest (so its EOL hook fires + signs
    # the ack) — the verified-ack, non-forced, non-quarantining path.
    assert fx.did("dispatch_graceful_stop")
    # The erasable KEK was destroyed (data death) + NetBird revoked.
    assert fx.did("crypto_erase_kek_transit")
    assert fx.did("revoke_netbird")


def test_decommission_graceful_stop_failure_is_best_effort(fx: FakeEffects) -> None:
    # A FAILING graceful EOL stop must NOT block decommission — draining
    # catches it (best-effort) and still advances to AWAITING_EOL_ACK, so the
    # ack-timeout forced reclaim + crypto-erase remain the data-death backstop
    # (§24 data death never depends on the guest ack).
    fx.fail.add("dispatch_graceful_stop")
    vm = make_vm(generation=5, host="node-src")
    job = service.start_decommission(vm=vm, decided_by=make_service_client())
    _drive_until(job, DecommissionState.AWAITING_EOL_ACK.value)
    job.refresh_from_db()
    assert job.state == DecommissionState.AWAITING_EOL_ACK.value
    assert fx.did("dispatch_graceful_stop")  # attempted, raised, swallowed


def test_decommission_freezes_the_ticket_at_draining(fx: FakeEffects) -> None:
    vm = make_vm()
    job = service.start_decommission(vm=vm, decided_by=make_service_client())
    _drive_until(job, DecommissionState.AWAITING_EOL_ACK.value)
    vm.refresh_from_db()
    # §24 `ticket_frozen`: the VM is Decommissioning; the launch-baked EOL
    # nonce is preserved (GAP 3 — NOT re-minted at decommission) so the
    # guest's stopped-ack verifies against the value it actually signed.
    assert vm.state == VmState.DECOMMISSIONING
    assert vm.eol_nonce is not None


# ─── §13 capacity leak: destroy releases the VM's placements ─────────


def _bound_placement_for(vm) -> Placement:
    """A `Bound` `Placement` pinning `vm` to a miner (as launch would)."""
    from apps.scheduler.tests.factories import make_placement, node_id

    return make_placement(
        vm, node_id(1), status=PlacementStatus.BOUND.value
    )


def test_destroy_releases_the_vms_bound_placement(fx: FakeEffects) -> None:
    # A destroyed VM must not leave a `Bound` placement pinning the miner's
    # capacity slot forever (§13 leak): `_destroy_vm` releases it → FAILED.
    vm = make_vm(generation=5, host="node-src")
    placement = _bound_placement_for(vm)

    job = service.start_decommission(vm=vm, decided_by=make_service_client())
    _drive()

    job.refresh_from_db()
    vm.refresh_from_db()
    placement.refresh_from_db()
    assert job.state == DecommissionState.DONE.value
    assert vm.state == VmState.DESTROYED
    # The capacity slot is freed: the placement is FAILED with the reason.
    assert placement.status == PlacementStatus.FAILED
    assert placement.reason == "released:vm-destroyed"
    assert placement.failed_at is not None
    assert placement.version == 2
    # No active placement remains against the miner → slot reclaimed.
    assert (
        Placement.objects.filter(
            status__in=[PlacementStatus.PENDING, PlacementStatus.BOUND]
        ).count()
        == 0
    )


# ─── §24: data death is unconditional ────────────────────────────────


def test_eol_ack_timeout_forces_reclaim_and_still_crypto_erases(
    fx: FakeEffects,
) -> None:
    # The miner never produces an EOL ack.
    fx.eol_ack = None
    vm = make_vm(generation=5, host="node-src")
    job = service.start_decommission(vm=vm, decided_by=make_service_client())
    _drive_until(job, DecommissionState.AWAITING_EOL_ACK.value)

    # Age the ack-wait past its timeout → forced reclaim.
    _backdate_phase(job)
    _drive()

    job.refresh_from_db()
    vm.refresh_from_db()
    # The job still COMPLETES — §24 data death does not depend on the
    # ack. It is marked `forced` and §13-quarantines the host.
    assert job.state == DecommissionState.DONE.value
    assert job.forced is True
    assert job.eol_ack_verified is False
    assert job.quarantine_node_id == "node-src"
    # The KEK was destroyed even though the miner never acked.
    assert fx.did("crypto_erase_kek_transit")
    assert vm.state == VmState.DESTROYED


def test_invalid_eol_ack_falls_through_to_forced_reclaim(fx: FakeEffects) -> None:
    # An ack is delivered but fails verification — fail-closed: the
    # job waits, then the timeout forces the reclaim.
    fx.ack_valid = False
    vm = make_vm()
    job = service.start_decommission(vm=vm, decided_by=make_service_client())
    _drive_until(job, DecommissionState.AWAITING_EOL_ACK.value)
    _backdate_phase(job)
    _drive()
    job.refresh_from_db()
    assert job.state == DecommissionState.DONE.value
    assert job.forced is True
    assert fx.did("crypto_erase_kek_transit")


# ─── best-effort teardown + the one failure path ─────────────────────


def test_netbird_revoke_failure_does_not_block_completion(
    fx: FakeEffects,
) -> None:
    # NetBird revoke is best-effort graceful teardown (§24) — a
    # failure must NOT block decommission (data death already done).
    fx.fail.add("revoke_netbird")
    vm = make_vm()
    job = service.start_decommission(vm=vm, decided_by=make_service_client())
    _drive()
    job.refresh_from_db()
    vm.refresh_from_db()
    assert job.state == DecommissionState.DONE.value
    assert vm.state == VmState.DESTROYED
    assert fx.did("crypto_erase_kek_transit")


def test_crypto_erase_failure_eventually_fails_the_job(fx: FakeEffects) -> None:
    # Crypto-erase is the data-death guarantee — if it cannot be
    # completed, the job fails (operator escalation), it never
    # silently "completes".
    fx.fail.add("crypto_erase_kek_transit")
    vm = make_vm()
    job = service.start_decommission(vm=vm, decided_by=make_service_client())
    _drive_until(job, DecommissionState.CRYPTO_ERASING.value)
    _backdate_phase(job)
    service.tick_once()
    job.refresh_from_db()
    vm.refresh_from_db()
    assert job.state == DecommissionState.FAILED.value
    assert "crypto_erasing" in job.reason
    # The VM is still Decommissioning — NOT a Destroyed tombstone,
    # because data death was not confirmed.
    assert vm.state == VmState.DECOMMISSIONING


# ─── GOLDEN decommission: Vault-Transit crypto-erase + destroy order ─


def test_golden_decommission_erases_transit_key_and_dispatches_destroy(
    fx: FakeEffects,
) -> None:
    # A GOLDEN VM's KEK is a Vault-Transit key with NO KBS record. §24 must
    # (1) crypto-erase via the Transit-key destroy path (NOT the KBS admin
    # crypto-erase, which would 404 → terminal-fail the job), and (2)
    # dispatch an explicit destroy order (golden guests don't self-poweroff).
    vm = make_vm(generation=5, host="node-src")
    make_launch_record(vm, disk_mode="golden_verity_overlay")

    job = service.start_decommission(vm=vm, decided_by=make_service_client())
    _drive()

    job.refresh_from_db()
    vm.refresh_from_db()
    assert job.state == DecommissionState.DONE.value
    assert vm.state == VmState.DESTROYED
    # Golden crypto-erase ran; the legacy KBS crypto-erase did NOT (no record
    # → it would 404). The domain was explicitly force-stopped.
    assert fx.did("crypto_erase_kek_transit")
    assert fx.did("dispatch_destroy")
    # The destroy order targeted the correct bound miner (no misroute).
    destroy = next(c for c in fx.calls if c[0] == "dispatch_destroy")
    assert destroy[1] == vm.vm_id
    assert destroy[2] == "node-src"


def test_golden_decommission_crypto_erase_failure_fails_closed(
    fx: FakeEffects,
) -> None:
    # The Transit-key destroy is the data-death guarantee. If it cannot be
    # completed, the job FAILS (operator escalation) — the VM is NEVER marked
    # Destroyed as if erased, and no destroy order is sent.
    fx.fail.add("crypto_erase_kek_transit")
    vm = make_vm(generation=5, host="node-src")
    make_launch_record(vm, disk_mode="golden_verity_overlay")

    job = service.start_decommission(vm=vm, decided_by=make_service_client())
    _drive_until(job, DecommissionState.CRYPTO_ERASING.value)
    _backdate_phase(job)
    service.tick_once()

    job.refresh_from_db()
    vm.refresh_from_db()
    assert job.state == DecommissionState.FAILED.value
    assert "crypto_erasing" in job.reason
    # Fail-closed: still Decommissioning, NOT a Destroyed tombstone.
    assert vm.state == VmState.DECOMMISSIONING
    assert not fx.did("dispatch_destroy")


def test_golden_decommission_destroy_order_failure_fails_the_job(
    fx: FakeEffects,
) -> None:
    # The explicit destroy order is retryable within the phase window; a
    # persistently-unreachable miner fails the job LOUDLY rather than
    # tombstoning a still-running (zombie) domain. Crypto-erase already ran.
    fx.fail.add("dispatch_destroy")
    vm = make_vm(generation=5, host="node-src")
    make_launch_record(vm, disk_mode="golden_verity_overlay")

    job = service.start_decommission(vm=vm, decided_by=make_service_client())
    _drive_until(job, DecommissionState.CRYPTO_ERASING.value)
    _backdate_phase(job)
    service.tick_once()

    job.refresh_from_db()
    vm.refresh_from_db()
    assert job.state == DecommissionState.FAILED.value
    assert "crypto_erasing" in job.reason
    assert vm.state == VmState.DECOMMISSIONING
    # The data-death crypto-erase DID run (before the destroy order).
    assert fx.did("crypto_erase_kek_transit")


def test_golden_decommission_crypto_erase_runs_exactly_once_across_retries(
    fx: FakeEffects,
) -> None:
    # Idempotency: while the destroy order retries (transient miner blip), the
    # already-done crypto-erase must NOT re-run — the §14 guard dedups it.
    fx.fail.add("dispatch_destroy")
    vm = make_vm(generation=5, host="node-src")
    make_launch_record(vm, disk_mode="golden_verity_overlay")

    job = service.start_decommission(vm=vm, decided_by=make_service_client())
    _drive_until(job, DecommissionState.CRYPTO_ERASING.value)
    # Several ticks in CRYPTO_ERASING with the destroy order failing.
    for _ in range(3):
        service.tick_once()
    erases = [c for c in fx.calls if c[0] == "crypto_erase_kek_transit"]
    assert len(erases) == 1, "crypto-erase must run exactly once (idempotent)"

    # Miner recovers → the destroy order succeeds and the job completes
    # WITHOUT re-erasing.
    fx.fail.discard("dispatch_destroy")
    _drive()
    job.refresh_from_db()
    vm.refresh_from_db()
    assert job.state == DecommissionState.DONE.value
    assert vm.state == VmState.DESTROYED
    erases = [c for c in fx.calls if c[0] == "crypto_erase_kek_transit"]
    assert len(erases) == 1


def test_legacy_decommission_uses_the_same_transit_erase_as_golden(
    fx: FakeEffects,
) -> None:
    # A VM whose launch record is `legacy_luks` takes the SAME Transit
    # crypto-erase (+ explicit destroy order) as a golden one. It used to
    # branch to the KBS admin `crypto-erase`, but that route was never
    # implemented — it 404'd forever, so §24 data-death was non-functional
    # for every legacy VM. Post-KEK-HSM every VM's KEK is wrapped under its
    # own per-VM Transit key, so one path is correct for both.
    vm = make_vm(generation=5, host="node-src")
    make_launch_record(vm, disk_mode="legacy_luks")

    job = service.start_decommission(vm=vm, decided_by=make_service_client())
    _drive()

    job.refresh_from_db()
    vm.refresh_from_db()
    assert job.state == DecommissionState.DONE.value
    assert vm.state == VmState.DESTROYED
    assert fx.did("crypto_erase_kek_transit")
    assert fx.did("dispatch_destroy")


# ─── concurrency / preconditions ─────────────────────────────────────


def test_concurrent_decommission_for_same_vm_is_rejected() -> None:
    vm = make_vm()
    actor = make_service_client()
    service.start_decommission(vm=vm, decided_by=actor)
    with pytest.raises(service.StartError) as exc:
        service.start_decommission(vm=vm, decided_by=actor)
    assert exc.value.category == "job-in-flight"
    assert DecommissionJob.objects.filter(vm=vm).count() == 1


def test_decommission_and_migration_are_mutually_exclusive() -> None:
    vm = make_vm()
    actor = make_service_client()
    service.start_migration(vm=vm, dest_node_id="node-dst", decided_by=actor)
    # A VM already being migrated cannot also be decommissioned.
    with pytest.raises(service.StartError) as exc:
        service.start_decommission(vm=vm, decided_by=actor)
    assert exc.value.category == "job-in-flight"


def test_decommission_rejected_when_vm_not_active() -> None:
    vm = make_vm(state=VmState.DESTROYED)
    with pytest.raises(service.StartError) as exc:
        service.start_decommission(vm=vm, decided_by=make_service_client())
    assert exc.value.category == "vm-not-active"


@pytest.mark.django_db
def test_decommission_destroys_via_a_failed_launch_jobs_miner(
    fx: FakeEffects,
) -> None:
    """THE LIVE SHAPE. A launch that fails at dispatch leaves `vm.host`
    empty and no SUCCEEDED LaunchJob — but the FAILED LaunchJob still names
    the miner the order was sent to, and that miner may be holding a
    running domain. §24 must route the force-stop there rather than skip
    it; skipping would tombstone a live CVM as Destroyed.

    `migproof-1` is exactly this: launch failed with a miner 500 (SEV ASID
    exhaustion), LaunchJob `failed` naming `miner-2`."""
    from apps.orchestration.models import LaunchJob, LaunchJobState

    vm = make_vm(host="")
    LaunchJob.objects.create(
        job_id="lj-failed-1",
        vm_id=vm.vm_id,
        tenant_id=vm.tenant_id,
        flavor="small",
        spec_json={},
        userdata_vault_path="",
        userdata_vault_version=0,
        kek_vault_path="",
        state=LaunchJobState.FAILED.value,
        miner_id="node-src",
        phase_started_at=timezone.now(),
        finished_at=timezone.now(),  # DB CHECK: terminal ⇒ finished_at set
        decided_by=make_service_client(name="launcher"),
    )
    job = service.start_decommission(vm=vm, decided_by=make_service_client())

    _drive_until(job, DecommissionState.DONE.value)

    assert fx.did("crypto_erase_kek_transit")
    assert fx.did("dispatch_destroy"), (
        "a failed launch's miner may hold a live domain — the destroy must "
        "be routed there, not skipped"
    )


@pytest.mark.django_db
def test_decommission_completes_when_no_miner_was_ever_recorded(
    fx: FakeEffects,
) -> None:
    """Bounded escape hatch: with NO vali record naming any miner (a
    placement that never dispatched at all) there is genuinely nowhere to
    send the destroy. Without this the job raises every tick until the step
    window elapses, `_fail_decommission` fires, and the Vm row is pinned in
    `Decommissioning` with no API-reachable recovery — `start_decommission`
    refuses a non-Active VM, so only an operator DB fixup clears it.

    Data death is unaffected: the KEK destroy is unconditional and is what
    §24 actually guarantees. The job records WHY it completed unproven."""
    vm = make_vm(host="")
    job = service.start_decommission(vm=vm, decided_by=make_service_client())

    _drive_until(job, DecommissionState.DONE.value)

    assert fx.did("crypto_erase_kek_transit")
    assert not fx.did("dispatch_destroy")
    job.refresh_from_db()
    assert job.reason == "destroy-skipped:no-miner-ever-recorded"
    vm.refresh_from_db()
    assert vm.state == "destroyed"


@pytest.mark.django_db
def test_decommission_still_destroys_the_domain_for_a_bound_vm(
    fx: FakeEffects,
) -> None:
    """The skip above must not weaken the normal path: a VM that IS bound
    to a miner still gets the force-stop, so a §24 never tombstones a live
    zombie domain as Destroyed."""
    vm = make_vm(host="node-src")
    job = service.start_decommission(vm=vm, decided_by=make_service_client())

    _drive_until(job, DecommissionState.DONE.value)

    assert fx.did("dispatch_destroy")
