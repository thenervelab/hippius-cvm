"""§24 decommission orchestrator tests."""

from __future__ import annotations

from datetime import timedelta

import pytest
from django.utils import timezone

from apps.lifecycle.models import Vm, VmPowerState, VmState
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
    Vm.objects.filter(pk=vm.pk).update(updated_at=timezone.now() - timedelta(days=2))
    job = service.start_decommission(vm=vm, decided_by=make_service_client())
    assert job.state == DecommissionState.DRAINING.value

    _drive()
    job.refresh_from_db()
    vm.refresh_from_db()
    assert job.state == DecommissionState.DONE.value
    assert job.eol_ack_verified is True
    assert job.forced is False
    assert job.finished_at is not None
    # The VM is a permanent Destroyed tombstone — on the power axis too,
    # and its row says when it died.
    assert vm.state == VmState.DESTROYED
    assert vm.power_state == VmPowerState.OFF
    assert vm.power_state_at is not None and vm.power_stop_proof is None
    assert vm.updated_at >= vm.power_state_at
    # §24 draining GRACEFULLY stopped the guest (so its EOL hook fires + signs
    # the ack) — the verified-ack, non-forced, non-quarantining path.
    assert fx.did("dispatch_graceful_stop")
    # The erasable KEK was destroyed (data death) + NetBird revoked.
    assert fx.did("crypto_erase_kek_transit")
    assert ("revoke_netbird", vm.vm_id) in fx.calls


def test_an_upgraded_in_flight_job_still_runs_the_expanded_erase(
    fx: FakeEffects,
) -> None:
    """The erase step grew: it destroys TWO per-VM Transit keys and
    deletes FOUR KV paths, where it used to destroy one and delete one.

    A job already in flight across that upgrade carries an idempotency
    record from the OLD implementation. Keyed the same, `_guarded` would
    skip the expanded step and walk the VM to `Destroyed` with the
    tenant's cloud-init still readable — re-opening, for exactly the VMs
    being decommissioned as it ships, the hole this change closes. The
    step is therefore keyed `crypto-erase-v2`.
    """
    from apps.orchestration import idempotency

    vm = make_vm(generation=5, host="node-src")
    job = service.start_decommission(vm=vm, decided_by=make_service_client())
    # Simulate the pre-upgrade record for this job.
    stale = f"decommission:{job.job_id}:crypto-erase"
    idempotency.record(stale, idempotency.marker_hash(stale))

    _drive()
    job.refresh_from_db()
    assert job.state == DecommissionState.DONE.value
    assert fx.did("crypto_erase_kek_transit"), (
        "the erase was skipped because a pre-upgrade idempotency record "
        "claimed a step that did far less had already run"
    )


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


def test_an_ack_is_not_accepted_when_the_decommission_never_stopped_the_guest(
    fx: FakeEffects,
) -> None:
    """#1154. The freeze consumed every earlier ack, but a guest can sign a
    new one on its own after it (an in-guest poweroff/reboot runs the same
    EOL hook — and the reboot-watcher restarts a reboot). If §24's own
    graceful stop never reached the miner, that ack does not answer this
    decommission: accepting it would record a clean, non-quarantining stop
    for a guest nobody stopped."""
    fx.fail.add("dispatch_graceful_stop")
    fx.eol_ack = b"ack-signed-by-an-in-guest-reboot"
    vm = make_vm(generation=5, host="node-src")
    job = service.start_decommission(vm=vm, decided_by=make_service_client())
    _drive_until(job, DecommissionState.AWAITING_EOL_ACK.value)
    for _ in range(5):
        service.tick_once()
    job.refresh_from_db()
    assert job.state == DecommissionState.AWAITING_EOL_ACK.value
    assert job.eol_ack_verified is False


def test_the_ack_is_accepted_once_the_decommission_stop_was_delivered(
    fx: FakeEffects,
) -> None:
    vm = make_vm(generation=5, host="node-src")
    job = service.start_decommission(vm=vm, decided_by=make_service_client())
    _drive()
    job.refresh_from_db()
    assert job.eol_ack_verified is True
    assert job.state == DecommissionState.DONE.value


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


def test_the_ticket_freeze_consumes_a_stopped_ack_left_over_from_a_migration(
    fx: FakeEffects,
) -> None:
    # The guest signs every stopped-ack at its constant `signing_generation`
    # with its per-launch `eol_nonce`, so the ack a recent §25 ingested would
    # verify as this decommission's EOL ack and record a clean stop that
    # never happened. The Active → Decommissioning CAS must consume it.
    from apps.lifecycle.models import StoppedAckIngest
    from apps.orchestration import effects

    vm = make_vm()
    StoppedAckIngest.objects.create(
        vm_id=vm.vm_id, generation=vm.signing_generation, signed_ack=b"migration"
    )
    job = service.start_decommission(vm=vm, decided_by=make_service_client())
    _drive_until(job, DecommissionState.AWAITING_EOL_ACK.value)

    vm.refresh_from_db()
    assert vm.state == VmState.DECOMMISSIONING
    # The real store read behind `poll_eol_ack` (which `fx` fakes).
    assert effects._poll_stored_ack(vm.vm_id, vm.signing_generation) is None


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
    # Tenant peers are persistent: the forced path must revoke too, or
    # the peer outlives the VM.
    assert ("revoke_netbird", vm.vm_id) in fx.calls


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
    assert ("revoke_netbird", vm.vm_id) in fx.calls


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
    # No erase happened, so nothing may call this guest a zombie.
    assert job.kek_erased_at is None


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


def test_a_destroy_failure_after_the_erase_never_fails_the_job(
    fx: FakeEffects,
) -> None:
    # The KEK is erased first, so the data is dead; only the domain destroy
    # keeps failing. That used to FAIL the job — and a failed job stranded
    # the VM in `Decommissioning` for good (nothing retried the destroy,
    # the API refuses a non-Active VM). Live, three erased guests kept
    # RUNNING for 13 days. The job must stay open and keep retrying.
    fx.fail.add("dispatch_destroy")
    vm = make_vm(generation=5, host="node-src")
    make_launch_record(vm, disk_mode="golden_verity_overlay")

    job = service.start_decommission(vm=vm, decided_by=make_service_client())
    _drive_until(job, DecommissionState.CRYPTO_ERASING.value)
    service.tick_once()  # the erase runs; the destroy fails
    _backdate_phase(job)
    service.tick_once()  # the window elapses

    job.refresh_from_db()
    vm.refresh_from_db()
    assert job.state == DecommissionState.CRYPTO_ERASING.value
    assert job.reason.startswith("destroy-pending:")
    assert job.finished_at is None
    # The window was re-armed, so the ERROR repeats once per window.
    assert timezone.now() - job.phase_started_at < timedelta(minutes=1)
    assert vm.state == VmState.DECOMMISSIONING
    assert fx.did("crypto_erase_kek_transit")
    # The erase is recorded durably — the zombie detector keys on it.
    assert job.kek_erased_at is not None
    first_stamp = job.kek_erased_at
    service.tick_once()  # another retry of the step
    job.refresh_from_db()
    assert job.kek_erased_at == first_stamp  # set once, never moved

    # The miner comes back: the same job finishes the teardown.
    fx.fail.discard("dispatch_destroy")
    _drive_until(job, DecommissionState.DONE.value)
    vm.refresh_from_db()
    assert vm.state == VmState.DESTROYED


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

    `vm-migrate-1` is exactly this: launch failed with a miner 500 (SEV ASID
    exhaustion), LaunchJob `failed` naming `miner-b`."""
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


# ─── stranded decommissions (a FAILED job left behind) ──────────────


def _stranded(vm_id: str, *, host: str = "node-src") -> tuple:
    """A VM in `Decommissioning` behind a FAILED §24 job — the live shape
    of vm-0001-722298ff & co."""
    vm = make_vm(vm_id, state=VmState.DECOMMISSIONING, host=host)
    old = DecommissionJob.objects.create(
        job_id=f"old-{vm_id}",
        vm=vm,
        state=DecommissionState.FAILED.value,
        finished_at=timezone.now(),
        phase_started_at=timezone.now(),
        decided_by=make_service_client(),
        forced=True,
        quarantine_node_id=host,
        reason="crypto_erasing:decommission-destroy: edge-order: peer unreachable",
    )
    return vm, old


def test_the_sweep_redrives_a_vm_stranded_behind_a_failed_job() -> None:
    vm, old = _stranded("vm-stranded")
    assert service.sweep_stranded_decommissions() == 1

    new = DecommissionJob.objects.filter(vm=vm).exclude(id=old.id).get()
    assert new.state == DecommissionState.CRYPTO_ERASING.value
    assert new.reason == f"redrive:{old.job_id}"
    assert new.decided_by_id == old.decided_by_id
    assert new.forced is True
    # One in-flight job at a time: a second sweep opens nothing.
    assert service.sweep_stranded_decommissions() == 0


def test_the_sweep_leaves_every_other_vm_alone() -> None:
    active = make_vm("vm-active")
    destroyed = make_vm("vm-destroyed", state=VmState.DESTROYED)
    migrating = make_vm("vm-migrating")
    type(migrating).objects.filter(id=migrating.id).update(
        state=VmState.MIGRATING, migration_dest="node-dst", new_generation=6
    )
    # Decommissioning, but nobody ever opened a §24 job for it.
    make_vm("vm-no-job", state=VmState.DECOMMISSIONING)
    # Decommissioning with a job still in flight.
    inflight = make_vm("vm-inflight", state=VmState.DECOMMISSIONING)
    DecommissionJob.objects.create(
        job_id="inflight",
        vm=inflight,
        state=DecommissionState.CRYPTO_ERASING.value,
        phase_started_at=timezone.now(),
        decided_by=make_service_client(),
    )
    # Failed jobs on VMs that are NOT Decommissioning.
    for vm in (active, destroyed, migrating):
        DecommissionJob.objects.create(
            job_id=f"failed-{vm.vm_id}",
            vm=vm,
            state=DecommissionState.FAILED.value,
            finished_at=timezone.now(),
            phase_started_at=timezone.now(),
            decided_by=make_service_client(),
        )
    before = DecommissionJob.objects.count()
    assert service.sweep_stranded_decommissions() == 0
    assert DecommissionJob.objects.count() == before


def test_the_sweep_stops_redriving_a_vm_that_keeps_failing(settings) -> None:
    settings.VALI_DECOMMISSION_REDRIVE_MAX = 2
    vm, _ = _stranded("vm-hopeless")
    for i in range(2):
        DecommissionJob.objects.create(
            job_id=f"again-{i}",
            vm=vm,
            state=DecommissionState.FAILED.value,
            finished_at=timezone.now(),
            phase_started_at=timezone.now() - timedelta(minutes=10 - i),
            decided_by=make_service_client(),
        )
    assert service.sweep_stranded_decommissions() == 0


def test_a_redriven_decommission_completes_and_tombstones_the_vm(
    fx: FakeEffects,
) -> None:
    vm, old = _stranded("vm-redrive")
    make_launch_record(vm, disk_mode="golden_verity_overlay")

    _drive()  # sweep opens the job, the next ticks advance it
    vm.refresh_from_db()
    new = DecommissionJob.objects.filter(vm=vm).exclude(id=old.id).get()
    assert new.state == DecommissionState.DONE.value
    assert vm.state == VmState.DESTROYED
    assert fx.did("crypto_erase_kek_transit")
    destroy = next(c for c in fx.calls if c[0] == "dispatch_destroy")
    assert destroy[1] == vm.vm_id
    # The re-driven job (entering at CRYPTO_ERASING) still revokes.
    assert ("revoke_netbird", vm.vm_id) in fx.calls


# ─── reachability is cut right after the erase ────────────────────────


def _vm_with_public_ip():
    from apps.network import service as network
    from apps.network.tests.conftest import make_edge

    make_edge()
    vm = make_vm(generation=5, host="node-src")
    make_launch_record(vm, disk_mode="golden_verity_overlay")
    ip, _ = network.attach(vm, region_hint="FR")
    return vm, ip


def _call_index(fx: FakeEffects, name: str) -> int:
    return next(i for i, c in enumerate(fx.calls) if c[0] == name)


def test_the_erase_revokes_the_netbird_peer_before_the_destroy(
    fx: FakeEffects,
) -> None:
    # The destroy needs the miner; while it is unreachable the job waits in
    # `destroy-pending` and never reaches `RevokingNetbird`. The erased
    # guest must still lose its network on the first pass after the erase.
    from apps.network import service as network
    from apps.network.models import PublicIpState

    fx.fail.add("dispatch_destroy")
    vm, ip = _vm_with_public_ip()
    job = service.start_decommission(vm=vm, decided_by=make_service_client())
    _drive_until(job, DecommissionState.CRYPTO_ERASING.value)
    service.tick_once()

    job.refresh_from_db()
    assert job.state == DecommissionState.CRYPTO_ERASING.value
    assert fx.did("revoke_netbird")
    assert (
        _call_index(fx, "crypto_erase_kek_transit")
        < _call_index(fx, "revoke_netbird")
        < _call_index(fx, "dispatch_destroy")
    )
    # The public IP went earlier still: `network.reconcile` withdraws it as
    # soon as the VM leaves Active.
    assert network.get_attached(vm) is None
    ip.refresh_from_db()
    assert ip.state == PublicIpState.QUARANTINED


def test_the_early_revoke_is_not_repeated_across_retries_or_by_the_later_step(
    fx: FakeEffects,
) -> None:
    fx.fail.add("dispatch_destroy")
    vm, _ = _vm_with_public_ip()
    job = service.start_decommission(vm=vm, decided_by=make_service_client())
    _drive_until(job, DecommissionState.CRYPTO_ERASING.value)
    for _ in range(3):
        service.tick_once()
    fx.fail.discard("dispatch_destroy")
    _drive_until(job, DecommissionState.DONE.value)

    revokes = [c for c in fx.calls if c[0] == "revoke_netbird"]
    assert len(revokes) == 1


def test_a_failed_early_revoke_never_blocks_the_teardown(fx: FakeEffects) -> None:
    fx.fail.add("revoke_netbird")
    vm, _ = _vm_with_public_ip()
    job = service.start_decommission(vm=vm, decided_by=make_service_client())
    _drive_until(job, DecommissionState.DONE.value)

    vm.refresh_from_db()
    assert vm.state == VmState.DESTROYED
    # The early revoke failed, so `RevokingNetbird` tried again.
    assert len([c for c in fx.calls if c[0] == "revoke_netbird"]) == 2


def test_a_vm_whose_erase_failed_keeps_its_netbird_peer(fx: FakeEffects) -> None:
    # Not erased ⇒ not dead: the early revoke runs only after the erase.
    fx.fail.add("crypto_erase_kek_transit")
    vm, _ = _vm_with_public_ip()
    job = service.start_decommission(vm=vm, decided_by=make_service_client())
    _drive_until(job, DecommissionState.CRYPTO_ERASING.value)
    for _ in range(3):
        service.tick_once()

    assert not fx.did("revoke_netbird")


def test_an_unreadable_idempotency_store_proves_no_delivery(
    fx: FakeEffects, monkeypatch
) -> None:
    from apps.orchestration import idempotency

    vm = make_vm(generation=5, host="node-src")
    job = service.start_decommission(vm=vm, decided_by=make_service_client())

    def _down(_key):
        raise idempotency.IdempotencyUnavailable("store down")

    monkeypatch.setattr(idempotency, "recall", _down)
    assert service._eol_stop_delivered(job) is False


def test_a_stop_that_failed_transiently_in_draining_is_re_asked(fx: FakeEffects) -> None:
    """Draining's stop failed (best-effort), the ack arrives later: re-asking
    the SAME stop from AwaitingEolAck gives the clean path its second chance
    instead of forcing a quarantining reclaim."""
    fx.fail.add("dispatch_graceful_stop")
    vm = make_vm(generation=5, host="node-src")
    job = service.start_decommission(vm=vm, decided_by=make_service_client())
    _drive_until(job, DecommissionState.AWAITING_EOL_ACK.value)
    fx.fail.discard("dispatch_graceful_stop")
    _drive()
    job.refresh_from_db()
    assert job.eol_ack_verified is True
    assert job.state == DecommissionState.DONE.value


def test_a_stop_that_found_the_guest_not_running_does_not_count(fx: FakeEffects) -> None:
    """`not-running`: the guest was already down (it powered itself off
    after the freeze), so this decommission stopped nothing — an ack it
    signed on its way down does not answer §24."""
    fx.graceful_stop_outcome = "not-running"
    vm = make_vm(generation=5, host="node-src")
    job = service.start_decommission(vm=vm, decided_by=make_service_client())
    _drive_until(job, DecommissionState.AWAITING_EOL_ACK.value)
    for _ in range(5):
        service.tick_once()
    job.refresh_from_db()
    assert job.state == DecommissionState.AWAITING_EOL_ACK.value
    assert job.eol_ack_verified is False


def test_a_lost_marker_after_a_delivered_stop_is_repaired(
    fx: FakeEffects, monkeypatch
) -> None:
    """The stop was delivered but `_guarded`'s record failed (logged, not
    fatal). Refusing the guest's clean ack forever would quarantine an honest
    miner; the re-ask replays the stop and records the marker."""
    from apps.orchestration import idempotency

    real_record = idempotency.record
    failed = {"n": 0}

    def _record_fails_once(key, value):
        if key.endswith(":eol-stop") and failed["n"] == 0:
            failed["n"] += 1
            raise idempotency.IdempotencyUnavailable("store hiccup")
        return real_record(key, value)

    monkeypatch.setattr(idempotency, "record", _record_fails_once)
    vm = make_vm(generation=5, host="node-src")
    job = service.start_decommission(vm=vm, decided_by=make_service_client())
    _drive()
    job.refresh_from_db()
    assert failed["n"] == 1
    assert job.eol_ack_verified is True
    assert job.state == DecommissionState.DONE.value


def test_a_bare_replay_from_an_older_agent_does_not_count(fx: FakeEffects) -> None:
    """An older miner-agent replays any finished order as `idempotent-replay`,
    hiding whether it stopped a guest or found it `not-running`."""
    fx.graceful_stop_outcome = "idempotent-replay"
    vm = make_vm(generation=5, host="node-src")
    job = service.start_decommission(vm=vm, decided_by=make_service_client())
    _drive_until(job, DecommissionState.AWAITING_EOL_ACK.value)
    for _ in range(5):
        service.tick_once()
    job.refresh_from_db()
    assert job.eol_ack_verified is False


def test_the_stop_is_re_asked_at_most_once_per_job(fx: FakeEffects) -> None:
    """The re-ask runs inside the orchestration tick; a hanging Edge must cost
    one bounded dispatch, not one per tick until the ack timeout."""
    fx.fail.add("dispatch_graceful_stop")
    vm = make_vm(generation=5, host="node-src")
    job = service.start_decommission(vm=vm, decided_by=make_service_client())
    _drive_until(job, DecommissionState.AWAITING_EOL_ACK.value)
    for _ in range(6):
        service.tick_once()
    stops = [c for c in fx.calls if c[0] == "dispatch_graceful_stop"]
    assert len(stops) == 2, f"draining + ONE re-ask, got {len(stops)}"



def test_each_decommission_job_stops_the_guest_under_its_own_order_id() -> None:
    """The miner answers a replayed order_id with its ORIGINAL outcome without
    acting. A §24 job reopened at the same generation must stop the guest
    itself — not be told `stopped` about the previous job's stop."""
    from types import SimpleNamespace

    vm = SimpleNamespace(vm_id="vm-x", generation=3)
    a = service._eol_stop_order_id(SimpleNamespace(vm=vm, job_id="a" * 32))
    b = service._eol_stop_order_id(SimpleNamespace(vm=vm, job_id="b" * 32))
    assert a != b
    assert a.startswith("dec-eol-stop-vm-x-3-")
    assert len(a) <= 128  # the miner-agent's MAX_ORDER_ID_LEN


def test_the_draining_stop_uses_the_job_scoped_id(fx: FakeEffects, monkeypatch) -> None:
    seen: list[dict] = []
    real = fx.dispatch_graceful_stop

    def _spy(vm, **kw):
        seen.append(kw)
        return real(vm, **kw)

    monkeypatch.setattr(service.effects, "dispatch_graceful_stop", _spy)
    vm = make_vm(generation=5, host="node-src")
    job = service.start_decommission(vm=vm, decided_by=make_service_client())
    _drive_until(job, DecommissionState.AWAITING_EOL_ACK.value)
    assert seen and seen[0]["order_id"] == service._eol_stop_order_id(job)


# ── a VM the tenant stopped decommissions clean (#1162) ─────────────


_BOOT_NONCE = b"\x05" * 32


def _stopped_vm(proof: bytes | None, **kw):
    from datetime import timedelta

    vm = make_vm(generation=5, host="node-src", **kw)
    Vm.objects.filter(pk=vm.pk).update(
        power_state=VmPowerState.STOPPED,
        power_state_at=timezone.now() - timedelta(days=2),
        eol_nonce=_BOOT_NONCE,
        power_stop_proof=proof,
    )
    vm.refresh_from_db()
    return vm


def test_a_stopped_vm_with_a_proven_stop_decommissions_clean(fx: FakeEffects) -> None:
    """No guest left to stop (`not-running`) nor to sign, and its power-stop
    ack — days old — could no longer verify: the proof recorded when it did
    verify is the EOL ack. Clean, not forced, the miner not quarantined."""
    fx.graceful_stop_outcome = "not-running"
    fx.eol_ack = None
    vm = _stopped_vm(_BOOT_NONCE)
    job = service.start_decommission(vm=vm, decided_by=make_service_client())
    _drive()
    job.refresh_from_db()
    assert job.state == DecommissionState.DONE.value
    assert job.eol_ack_verified is True
    assert job.forced is False
    assert not job.quarantine_node_id


@pytest.mark.parametrize(
    ("power", "proof"),
    [
        (VmPowerState.STOPPED, None),  # the stop was never proven
        (VmPowerState.STOPPED, b"\x06" * 32),  # proven for another boot
        (VmPowerState.RUNNING, _BOOT_NONCE),  # not stopped at all
    ],
)
def test_no_proof_of_this_boots_stop_still_forces_the_reclaim(
    fx: FakeEffects, power: str, proof: bytes | None
) -> None:
    fx.graceful_stop_outcome = "not-running"
    fx.eol_ack = None
    vm = _stopped_vm(proof)
    Vm.objects.filter(pk=vm.pk).update(power_state=power)
    vm.refresh_from_db()
    job = service.start_decommission(vm=vm, decided_by=make_service_client())
    _drive_until(job, DecommissionState.AWAITING_EOL_ACK.value)
    _drive()
    _backdate_phase(job)
    _drive()
    job.refresh_from_db()
    assert job.eol_ack_verified is not True
    assert job.forced is True
