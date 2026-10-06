"""P9/#15 — §25 SOURCE-side reclaim.

## What is being defended

A §25 migration is a **copy**. `quiesce` stops the source guest and
`snapshot` uploads its volume, but nothing ever removed the source's

  * `overlay/<vm_id>.img`  — the tenant's LUKS ciphertext,
  * `state/<vm_id>.raw`    — the boot-counter anti-rollback disk,
  * `staging/<vm_id>/`     — the staged kernel / initrd / rootfs,

so they stay on a host that no longer runs the VM and is UNTRUSTED.
`source_node_id` was, before this change, referenced only by the log line
and the ack-timeout quarantine — no §25 code path ever spoke to the
source again after the snapshot.

## The two ways this can go wrong, and which one is worse

Leaking ciphertext on a fenced host is bad. Deleting the tenant's only
good copy is CATASTROPHIC — `_fail_migration` documents forward-only
recovery as "an operator relaunch of the intact (never crypto-erased)
source disk at `source_gen`", which the reclaim would make impossible.
Every test below therefore pins the same asymmetry: anything short of a
positive, unforgeable proof that the DESTINATION obtained the KEK leaves
the source artifacts exactly where they are.
"""

from __future__ import annotations

from datetime import timedelta

import pytest
from django.utils import timezone

from apps.lifecycle.models import Vm, VmState
from apps.orchestration import effects, service
from apps.orchestration.models import MigrationJob, MigrationState, SourceReclaimState
from apps.orders.models import OrderTicketIntake

from .factories import make_migration_job, make_vm

pytestmark = pytest.mark.django_db

_DEST_PLATFORM = "22" * 64
_SRC_PLATFORM = "11" * 64


@pytest.fixture(autouse=True)
def _miners():
    from apps.miners.models import MinerIdentity

    MinerIdentity.objects.get_or_create(
        miner_id="node-src",
        defaults={
            "pubkey_hex": "aa" * 32,
            "platform_id": _SRC_PLATFORM,
            "netbird_ip": "100.0.0.1",
        },
    )
    MinerIdentity.objects.get_or_create(
        miner_id="node-dst",
        defaults={
            "pubkey_hex": "bb" * 32,
            "platform_id": _DEST_PLATFORM,
            "netbird_ip": "100.0.0.2",
        },
    )


class _Dispatches:
    """Records every source-reclaim dispatch so a test can assert BOTH
    that it happened and WHICH miner it was aimed at."""

    def __init__(self, *, fail: Exception | None = None):
        self.calls: list[tuple[str, str, str]] = []
        self.fail = fail

    def __call__(self, vm, *, source_node_id, job_id):
        self.calls.append((vm.vm_id, source_node_id, job_id))
        if self.fail is not None:
            raise self.fail


def _done_migration(**vm_kwargs) -> tuple[Vm, MigrationJob]:
    """A §25 migration that reached `Done`: the VM is Active on the dest at
    `new_gen`, exactly as `_activate_dest_vm` leaves it."""
    vm = make_vm(host="node-src", generation=1, **vm_kwargs)
    job = make_migration_job(vm, state=MigrationState.DONE.value)
    Vm.objects.filter(id=vm.id).update(
        state=VmState.ACTIVE.value, host="node-dst", generation=job.new_gen
    )
    vm.refresh_from_db()
    return vm, job


def _grant_evidence(monkeypatch, job: MigrationJob, *, vm_id: str) -> None:
    """Wire the KBS evidence read + vali's own ticket record so the
    destination is PROVEN: the KBS granted a KEK release against the
    dest ticket, minted at `new_gen` and bound to the dest chip."""
    OrderTicketIntake.objects.create(
        ticket_id="tk-mig-proven",
        vm_id=vm_id,
        tenant_id="t",
        user_id="u",
        lease_id="l",
        vm_generation=job.new_gen,
        issue_time=0,
        expiry=0,
        node_id="node-dst",
        platform_id=_DEST_PLATFORM,
        resource_class="small",
        kid_hex="00",
        cose_blob=b"",
        received_from="system:migration-remint",
    )
    _stub_evidence(
        monkeypatch,
        {
            "ticket_id": "tk-mig-proven",
            "granted_at_unix": int(timezone.now().timestamp()) + 5,
        },
    )
    _dest_alive(job)


def _dest_alive(job: MigrationJob, *, after_s: float = 3600.0) -> None:
    """The destination GUEST proved it runs: an in-guest signal `after_s`
    after the migration finished (the finish is backdated to allow it)."""
    now = timezone.now()
    MigrationJob.objects.filter(id=job.id).update(
        finished_at=now - timedelta(seconds=after_s)
    )
    Vm.objects.filter(id=job.vm_id).update(guest_signal_at=now)
    job.refresh_from_db()


def _stub_evidence(monkeypatch, bundle):
    from apps.orchestration.services import kbs_evidence

    monkeypatch.setattr(kbs_evidence, "fetch_evidence", lambda vm_id: bundle)


# ── the happy path ───────────────────────────────────────────────────


def test_reclaims_the_source_once_the_kbs_proves_the_dest_got_the_key(
    monkeypatch,
):
    vm, job = _done_migration()
    _grant_evidence(monkeypatch, job, vm_id=vm.vm_id)
    spy = _Dispatches()
    monkeypatch.setattr(effects, "dispatch_source_reclaim", spy)

    assert service.reclaim_migrated_sources() == 1

    # THE routing assertion. `vm.host` is the DESTINATION by now — a
    # reclaim that read the VM instead of the job would aim the destroy at
    # the host the tenant is live on (the #880 shape: a read from a handle
    # the caller's own earlier step had already moved on).
    assert spy.calls == [(vm.vm_id, "node-src", job.job_id)]
    job.refresh_from_db()
    assert job.source_reclaim_state == SourceReclaimState.RECLAIMED.value
    assert job.source_reclaim_at is not None


def test_a_settled_job_is_never_swept_again(monkeypatch):
    vm, job = _done_migration()
    _grant_evidence(monkeypatch, job, vm_id=vm.vm_id)
    spy = _Dispatches()
    monkeypatch.setattr(effects, "dispatch_source_reclaim", spy)

    service.reclaim_migrated_sources()
    service.reclaim_migrated_sources()

    assert len(spy.calls) == 1, "a reclaimed source must not be re-dispatched"


# ── fail-safe: the destination is NOT proven ─────────────────────────


def test_no_kbs_evidence_leaves_the_source_alone(monkeypatch):
    # The KBS evidence sink is an emptyDir — a KBS restart erases bundles,
    # so absence is AMBIGUOUS between "never attested" and "attested but
    # unrecorded". It must never authorise a deletion.
    vm, job = _done_migration()
    _stub_evidence(monkeypatch, None)
    spy = _Dispatches()
    monkeypatch.setattr(effects, "dispatch_source_reclaim", spy)

    service.reclaim_migrated_sources()

    assert spy.calls == []
    job.refresh_from_db()
    assert job.source_reclaim_state == SourceReclaimState.PENDING.value


def test_evidence_for_the_wrong_generation_leaves_the_source_alone(
    monkeypatch,
):
    # The latest KBS grant is the SOURCE's launch-generation release, not
    # the destination's. This is exactly the recorded live failure: the
    # dest booted, 403'd on the release, and the migration still said Done.
    vm, job = _done_migration()
    OrderTicketIntake.objects.create(
        ticket_id="tk-launch",
        vm_id=vm.vm_id,
        tenant_id="t",
        user_id="u",
        lease_id="l",
        vm_generation=job.source_gen,  # NOT new_gen
        issue_time=0,
        expiry=0,
        node_id="node-src",
        platform_id=_SRC_PLATFORM,
        resource_class="small",
        kid_hex="00",
        cose_blob=b"",
        received_from="l1",
    )
    _stub_evidence(
        monkeypatch,
        {
            "ticket_id": "tk-launch",
            "granted_at_unix": int(timezone.now().timestamp()) + 5,
        },
    )
    spy = _Dispatches()
    monkeypatch.setattr(effects, "dispatch_source_reclaim", spy)

    service.reclaim_migrated_sources()

    assert spy.calls == []
    job.refresh_from_db()
    assert job.source_reclaim_state == SourceReclaimState.PENDING.value


def test_evidence_from_an_earlier_generation_on_the_same_dest_is_not_proof(
    monkeypatch,
):
    # Isolates the GENERATION check specifically: this ticket matches the
    # destination miner AND the destination chip, and differs only in the
    # generation (a VM that has lived on this dest before — a re-migration,
    # or a migrate-back). Without the generation check the residency-level
    # match would read as proof that THIS migration's guest unlocked.
    vm, job = _done_migration()
    OrderTicketIntake.objects.create(
        ticket_id="tk-earlier-gen",
        vm_id=vm.vm_id,
        tenant_id="t",
        user_id="u",
        lease_id="l",
        vm_generation=job.new_gen - 1,
        issue_time=0,
        expiry=0,
        node_id="node-dst",
        platform_id=_DEST_PLATFORM,
        resource_class="small",
        kid_hex="00",
        cose_blob=b"",
        received_from="system:migration-remint",
    )
    _stub_evidence(
        monkeypatch,
        {
            "ticket_id": "tk-earlier-gen",
            "granted_at_unix": int(timezone.now().timestamp()) + 5,
        },
    )
    spy = _Dispatches()
    monkeypatch.setattr(effects, "dispatch_source_reclaim", spy)

    service.reclaim_migrated_sources()

    assert spy.calls == []


def test_evidence_bound_to_another_chip_leaves_the_source_alone(monkeypatch):
    # A grant at the right generation but against a ticket bound to a
    # different platform_id is not a proof about THIS destination.
    vm, job = _done_migration()
    OrderTicketIntake.objects.create(
        ticket_id="tk-elsewhere",
        vm_id=vm.vm_id,
        tenant_id="t",
        user_id="u",
        lease_id="l",
        vm_generation=job.new_gen,
        issue_time=0,
        expiry=0,
        node_id="node-dst",
        platform_id="99" * 64,
        resource_class="small",
        kid_hex="00",
        cose_blob=b"",
        received_from="system:migration-remint",
    )
    _stub_evidence(
        monkeypatch,
        {
            "ticket_id": "tk-elsewhere",
            "granted_at_unix": int(timezone.now().timestamp()) + 5,
        },
    )
    spy = _Dispatches()
    monkeypatch.setattr(effects, "dispatch_source_reclaim", spy)

    service.reclaim_migrated_sources()

    assert spy.calls == []


def test_evidence_predating_the_migration_leaves_the_source_alone(monkeypatch):
    vm, job = _done_migration()
    _grant_evidence(monkeypatch, job, vm_id=vm.vm_id)
    _stub_evidence(
        monkeypatch,
        {
            "ticket_id": "tk-mig-proven",
            "granted_at_unix": int(job.started_at.timestamp()) - 60,
        },
    )
    spy = _Dispatches()
    monkeypatch.setattr(effects, "dispatch_source_reclaim", spy)

    service.reclaim_migrated_sources()

    assert spy.calls == []


def test_a_vm_that_is_no_longer_active_leaves_the_source_alone(monkeypatch):
    # e.g. a SECOND migration has fenced it back to `Migrating`. vali's own
    # record no longer says "this VM is settled on the destination", so the
    # KBS grant — however valid — is not a verdict about a stable placement.
    vm, job = _done_migration()
    _grant_evidence(monkeypatch, job, vm_id=vm.vm_id)
    Vm.objects.filter(id=vm.id).update(
        state=VmState.MIGRATING.value,
        migration_dest="node-src",
        new_generation=job.new_gen + 1,
    )
    spy = _Dispatches()
    monkeypatch.setattr(effects, "dispatch_source_reclaim", spy)

    service.reclaim_migrated_sources()

    assert spy.calls == []


def test_an_evidence_ticket_vali_never_issued_is_not_proof(monkeypatch):
    # The bundle names a ticket_id with no `OrderTicketIntake` row. vali
    # cannot say what generation or chip that grant was bound to, so it is
    # not a verdict about this destination.
    vm, job = _done_migration()
    _stub_evidence(
        monkeypatch,
        {
            "ticket_id": "tk-nobody-minted-this",
            "granted_at_unix": int(timezone.now().timestamp()) + 5,
        },
    )
    spy = _Dispatches()
    monkeypatch.setattr(effects, "dispatch_source_reclaim", spy)

    service.reclaim_migrated_sources()

    assert spy.calls == []


def test_an_evidence_ticket_for_a_different_vm_is_not_proof(monkeypatch):
    # Defence in depth against a ticket_id collision / a mis-keyed bundle:
    # the ticket must belong to THIS VM, not merely match the generation
    # and the destination chip.
    vm, job = _done_migration()
    OrderTicketIntake.objects.create(
        ticket_id="tk-other-vm",
        vm_id="some-other-vm",
        tenant_id="t",
        user_id="u",
        lease_id="l",
        vm_generation=job.new_gen,
        issue_time=0,
        expiry=0,
        node_id="node-dst",
        platform_id=_DEST_PLATFORM,
        resource_class="small",
        kid_hex="00",
        cose_blob=b"",
        received_from="system:migration-remint",
    )
    _stub_evidence(
        monkeypatch,
        {
            "ticket_id": "tk-other-vm",
            "granted_at_unix": int(timezone.now().timestamp()) + 5,
        },
    )
    spy = _Dispatches()
    monkeypatch.setattr(effects, "dispatch_source_reclaim", spy)

    service.reclaim_migrated_sources()

    assert spy.calls == []


def test_a_vm_that_left_the_destination_leaves_the_source_alone(monkeypatch):
    vm, job = _done_migration()
    _grant_evidence(monkeypatch, job, vm_id=vm.vm_id)
    Vm.objects.filter(id=vm.id).update(host="node-somewhere-else")
    spy = _Dispatches()
    monkeypatch.setattr(effects, "dispatch_source_reclaim", spy)

    service.reclaim_migrated_sources()

    assert spy.calls == []


def test_an_unresolvable_dest_chip_fails_closed(monkeypatch):
    # An unverifiable host bind is not a pass.
    from apps.miners.models import MinerIdentity

    vm, job = _done_migration()
    _grant_evidence(monkeypatch, job, vm_id=vm.vm_id)
    MinerIdentity.objects.filter(miner_id="node-dst").update(platform_id="")
    spy = _Dispatches()
    monkeypatch.setattr(effects, "dispatch_source_reclaim", spy)

    service.reclaim_migrated_sources()

    assert spy.calls == []


# ── a dispatch that did not happen is never reported as done ─────────


def test_a_failed_dispatch_stays_pending_and_retries(monkeypatch):
    # The miner refusing because the domain is still up (the reboot-watcher
    # resurrected it) surfaces here as an EffectError. Reporting success
    # having unlinked nothing is the #880 shape — refuse it.
    vm, job = _done_migration()
    _grant_evidence(monkeypatch, job, vm_id=vm.vm_id)
    spy = _Dispatches(
        fail=effects.EffectError("source-reclaim: source miner rejected (domain-still-up)")
    )
    monkeypatch.setattr(effects, "dispatch_source_reclaim", spy)

    service.reclaim_migrated_sources()

    job.refresh_from_db()
    assert job.source_reclaim_state == SourceReclaimState.PENDING.value
    assert len(spy.calls) == 1

    # …and the NEXT tick tries again (the domain has since gone down).
    spy.fail = None
    service.reclaim_migrated_sources()
    job.refresh_from_db()
    assert job.source_reclaim_state == SourceReclaimState.RECLAIMED.value
    assert len(spy.calls) == 2


def test_an_unreachable_source_never_fails_the_migration(monkeypatch):
    vm, job = _done_migration()
    _grant_evidence(monkeypatch, job, vm_id=vm.vm_id)
    monkeypatch.setattr(
        effects,
        "dispatch_source_reclaim",
        _Dispatches(fail=effects.EffectUnavailable("edge down")),
    )

    service.reclaim_migrated_sources()

    job.refresh_from_db()
    assert job.state == MigrationState.DONE.value, (
        "the reclaim is hygiene — it must never be able to un-complete a "
        "migration whose VM is live on the destination"
    )


# ── the proof window: give up LOUDLY, never silently ─────────────────


def test_an_unprovable_dest_is_abandoned_loudly_after_the_window(monkeypatch):
    # Asserts on the logger call, not via `caplog`: the project sets
    # `propagate: False` on the `apps` logger, so caplog's root handler
    # never sees these records.
    vm, job = _done_migration()
    _stub_evidence(monkeypatch, None)
    MigrationJob.objects.filter(id=job.id).update(
        finished_at=timezone.now() - timedelta(days=2)
    )
    spy = _Dispatches()
    monkeypatch.setattr(effects, "dispatch_source_reclaim", spy)
    errors: list[str] = []
    monkeypatch.setattr(
        service.log, "error", lambda msg, *a, **kw: errors.append(msg % a)
    )

    service.reclaim_migrated_sources()

    assert spy.calls == [], "an unprovable dest must never be reclaimed"
    job.refresh_from_db()
    assert job.source_reclaim_state == SourceReclaimState.SKIPPED.value
    assert job.source_reclaim_reason.startswith("dest-unproven:")
    assert any("REMAIN on that host" in e for e in errors), (
        "giving up must be operator-visible, never silent"
    )


# ── migrate-then-decommission ────────────────────────────────────────


def test_a_destroyed_vm_reclaims_the_source_without_needing_kbs_proof(
    monkeypatch,
):
    # §24 crypto-erases the per-VM Vault-Transit KEK, which is GLOBAL: the
    # source's leftover ciphertext becomes unopenable too. But §24's
    # `destroy` order goes to `_bound_miner_id` == the DESTINATION only, so
    # the source's files survive the teardown. There is no longer any copy
    # to lose, so reclaim them.
    vm, job = _done_migration()
    Vm.objects.filter(id=vm.id).update(state=VmState.DESTROYED.value, host="")
    _stub_evidence(monkeypatch, None)
    spy = _Dispatches()
    monkeypatch.setattr(effects, "dispatch_source_reclaim", spy)

    service.reclaim_migrated_sources()

    assert spy.calls == [(vm.vm_id, "node-src", job.job_id)]
    job.refresh_from_db()
    assert job.source_reclaim_state == SourceReclaimState.RECLAIMED.value


# ── the effect's own routing guards ──────────────────────────────────


def test_dispatch_refuses_to_reclaim_the_vms_current_host():
    # The catastrophic misroute: aiming the destroy at the machine the
    # tenant is live on. Refused BEFORE any order is built.
    vm = make_vm(host="node-dst")
    with pytest.raises(effects.EffectError, match="CURRENT host"):
        effects.dispatch_source_reclaim(
            vm, source_node_id="node-dst", job_id="j1"
        )


def test_dispatch_refuses_an_empty_source():
    vm = make_vm(host="node-dst")
    with pytest.raises(effects.EffectError, match="no source miner"):
        effects.dispatch_source_reclaim(vm, source_node_id="", job_id="j1")


def test_dispatch_targets_the_source_miner_identity(monkeypatch):
    from apps.orchestration import order_dispatch

    seen: dict[str, object] = {}

    class _Result:
        ok = True
        status = 200
        classifier = "destroyed"

    def _fake_dispatch(**kwargs):
        seen.update(kwargs)
        return _Result()

    monkeypatch.setattr(order_dispatch, "dispatch_order", _fake_dispatch)
    vm = make_vm(host="node-dst")

    effects.dispatch_source_reclaim(vm, source_node_id="node-src", job_id="j1")

    assert seen["miner_id"] == "node-src"
    assert seen["netbird_ip"] == "100.0.0.1"
    assert seen["kind"] == "destroy"
    # Keyed on the migration job so a re-migration can reclaim its own
    # source without colliding with the §24 `dec-destroy-<vm>-<gen>` key.
    assert seen["order_id"] == f"mig-reclaim-{vm.vm_id}-j1"


def test_dispatch_raises_when_the_source_miner_rejects(monkeypatch):
    from apps.orchestration import order_dispatch

    class _Rejected:
        ok = False
        status = 409
        classifier = "domain-still-up"

    monkeypatch.setattr(
        order_dispatch, "dispatch_order", lambda **kw: _Rejected()
    )
    vm = make_vm(host="node-dst")

    with pytest.raises(effects.EffectError, match="domain-still-up"):
        effects.dispatch_source_reclaim(
            vm, source_node_id="node-src", job_id="j1"
        )


# ── the kill switch ──────────────────────────────────────────────────


def test_the_sweep_is_a_no_op_when_disabled(monkeypatch, settings):
    settings.VALI_MIGRATION_SOURCE_RECLAIM_ENABLED = False
    vm, job = _done_migration()
    _grant_evidence(monkeypatch, job, vm_id=vm.vm_id)
    spy = _Dispatches()
    monkeypatch.setattr(effects, "dispatch_source_reclaim", spy)

    assert service.reclaim_migrated_sources() == 0
    assert spy.calls == []


# ── defense in depth: the destination GUEST must prove it runs ───────


@pytest.mark.parametrize(
    ("signal_after_s", "reclaimed"),
    [
        (None, False),  # key released, then silence: the live truncation case
        (60.0, False),  # alive, but not yet past the grace period
        (3600.0, True),
    ],
)
def test_the_source_waits_for_the_destination_guest_to_prove_it_runs(
    monkeypatch, signal_after_s, reclaimed
):
    """Live: a destination was released its key for a truncated volume and
    hung — the KBS grant alone let vali delete the only good copy."""
    vm, job = _done_migration()
    _grant_evidence(monkeypatch, job, vm_id=vm.vm_id)
    now = timezone.now()
    MigrationJob.objects.filter(id=job.id).update(finished_at=now - timedelta(hours=1))
    Vm.objects.filter(id=vm.id).update(
        guest_signal_at=None
        if signal_after_s is None
        else now - timedelta(hours=1) + timedelta(seconds=signal_after_s)
    )
    spy = _Dispatches()
    monkeypatch.setattr(effects, "dispatch_source_reclaim", spy)

    service.reclaim_migrated_sources()

    job.refresh_from_db()
    assert bool(spy.calls) is reclaimed
    assert (job.source_reclaim_state == SourceReclaimState.RECLAIMED.value) is reclaimed
    if not reclaimed:
        assert job.source_reclaim_state == SourceReclaimState.PENDING.value, "still waiting"


# ── the S3 snapshot follows the same proof ───────────────────────────


def _with_snapshot(job: MigrationJob) -> tuple[str, str]:
    from apps.storage import s3

    bucket = "snaps"
    key, state_key = f"migrations/{job.job_id}.luks", f"migrations/{job.job_id}.state"
    client = s3.get_s3_client()
    client.put_object(bucket=bucket, key=key, body=b"ciphertext", content_type="x")
    client.put_object(bucket=bucket, key=state_key, body=b"counter", content_type="x")
    MigrationJob.objects.filter(id=job.id).update(
        snapshot_bucket=bucket, snapshot_key=key, snapshot_state_key=state_key
    )
    job.refresh_from_db()
    return key, state_key


def _stored(key: str) -> bool:
    from apps.storage import s3

    return s3.get_s3_client().head_object(bucket="snaps", key=key) is not None


def test_the_snapshot_is_deleted_once_the_destination_is_proven_alive(monkeypatch):
    vm, job = _done_migration()
    key, state_key = _with_snapshot(job)
    _grant_evidence(monkeypatch, job, vm_id=vm.vm_id)
    monkeypatch.setattr(effects, "dispatch_source_reclaim", _Dispatches())

    service.reclaim_migrated_sources()

    job.refresh_from_db()
    assert not _stored(key) and not _stored(state_key)
    assert job.snapshot_deleted_at is not None


def test_the_snapshot_is_kept_while_the_destination_is_unproven(monkeypatch):
    vm, job = _done_migration()
    key, _ = _with_snapshot(job)
    _grant_evidence(monkeypatch, job, vm_id=vm.vm_id)
    Vm.objects.filter(id=vm.id).update(guest_signal_at=None)
    monkeypatch.setattr(effects, "dispatch_source_reclaim", _Dispatches())

    service.reclaim_migrated_sources()
    service.gc_migration_snapshots()

    assert _stored(key)


@pytest.mark.parametrize(
    ("job_state", "vm_state", "on_source", "age_h", "deleted"),
    [
        # a terminal job whose VM is gone
        (MigrationState.FAILED.value, VmState.DESTROYED.value, True, 0, True),
        # failed, VM restored to its source, past retention
        (MigrationState.FAILED.value, VmState.ACTIVE.value, True, 100, True),
        # ... within retention
        (MigrationState.FAILED.value, VmState.ACTIVE.value, True, 1, False),
        # failed, and the VM has since moved on elsewhere, past retention
        (MigrationState.FAILED.value, VmState.ACTIVE.value, False, 100, True),
        # failed and still fenced: a forward re-drive needs the snapshot
        (MigrationState.FAILED.value, VmState.MIGRATING.value, False, 100, False),
        # a job that is not terminal is never touched
        (MigrationState.UPLOADING.value, VmState.DESTROYED.value, True, 100, False),
    ],
)
def test_the_snapshot_janitor(job_state, vm_state, on_source, age_h, deleted):
    vm = make_vm(host="node-src", generation=1)
    job = make_migration_job(vm, state=job_state)
    MigrationJob.objects.filter(id=job.id).update(
        finished_at=timezone.now() - timedelta(hours=age_h)
    )
    patch = {"state": vm_state, "host": "node-src" if on_source else "node-dst"}
    if vm_state == VmState.MIGRATING.value:
        patch.update(migration_dest="node-dst", new_generation=job.new_gen)
    Vm.objects.filter(id=vm.id).update(**patch)
    job.refresh_from_db()
    key, _ = _with_snapshot(job)

    service.gc_migration_snapshots()

    assert _stored(key) is not deleted


def test_a_job_reclaimed_on_the_kbs_grant_alone_keeps_its_snapshot():
    """Rows reclaimed before the liveness gate existed — `reclaimed` does not
    prove the destination runs (the live data-loss case was one)."""
    vm, job = _done_migration()
    MigrationJob.objects.filter(id=job.id).update(
        source_reclaim_state=SourceReclaimState.RECLAIMED.value,
        finished_at=timezone.now() - timedelta(days=10),
    )
    job.refresh_from_db()
    key, _ = _with_snapshot(job)

    service.gc_migration_snapshots()
    assert _stored(key)

    _dest_alive(job)
    service.gc_migration_snapshots()
    assert not _stored(key)


def test_a_redriven_job_shares_the_snapshot_until_it_too_is_retired():
    """`vali_migration_recover --action redrive-dest` copies the failed job's
    snapshot keys: the old job being retired must not take the new job's
    only copy."""
    vm = make_vm(host="node-src", generation=1)
    old = make_migration_job(vm, state=MigrationState.FAILED.value)
    MigrationJob.objects.filter(id=old.id).update(
        finished_at=timezone.now() - timedelta(days=10)
    )
    old.refresh_from_db()
    key, state_key = _with_snapshot(old)
    new = make_migration_job(vm, state=MigrationState.DONE.value)
    MigrationJob.objects.filter(id=new.id).update(
        snapshot_bucket="snaps", snapshot_key=key, snapshot_state_key=state_key
    )
    Vm.objects.filter(id=vm.id).update(
        state=VmState.ACTIVE.value, host="node-dst", generation=new.new_gen
    )
    new.refresh_from_db()

    service.gc_migration_snapshots()
    assert _stored(key), "the re-driven destination has not proved it runs"

    _dest_alive(new)
    service.gc_migration_snapshots()
    assert not _stored(key)
    left = MigrationJob.objects.filter(snapshot_key=key, snapshot_deleted_at__isnull=True)
    assert not left.exists()


def test_jobs_that_never_retire_do_not_starve_the_janitor():
    for i in range(25):  # older, never retirable: Done, destination unproven
        v = make_vm(vm_id=f"vm-stuck-{i}", host="node-dst", generation=2)
        j = make_migration_job(v, state=MigrationState.DONE.value)
        MigrationJob.objects.filter(id=j.id).update(
            finished_at=timezone.now() - timedelta(days=30)
        )
        j.refresh_from_db()
        _with_snapshot(j)
    vm = make_vm(vm_id="vm-gone", host="node-src", generation=1)
    job = make_migration_job(vm, state=MigrationState.FAILED.value)
    Vm.objects.filter(id=vm.id).update(state=VmState.DESTROYED.value)
    job.refresh_from_db()
    key, _ = _with_snapshot(job)

    service.gc_migration_snapshots()

    assert not _stored(key)
