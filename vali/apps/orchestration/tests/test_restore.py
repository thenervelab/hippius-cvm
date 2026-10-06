"""Restore a VM from one of its backups (`apps.orchestration.restore`).

One test (or a small group) per claim the restore job makes — see the
module docstring there for the phases."""

from __future__ import annotations

import uuid
from datetime import timedelta
from typing import Any

import pytest
from django.conf import settings
from django.utils import timezone

from apps.backup.models import (
    BackupChain,
    BackupKind,
    BackupPolicy,
    BackupRun,
    ChainState,
    RunStatus,
)
from apps.lifecycle.models import Vm, VmBootPhase, VmPowerState, VmState
from apps.miners.models import MinerIdentity
from apps.orchestration import effects, restore, service
from apps.orchestration.models import (
    DestAuthorization,
    MigrationJob,
    MigrationKind,
    MigrationState,
    SourceReclaimState,
)
from apps.orchestration.services import power
from apps.orders.models import OrderTicketIntake
from apps.storage import s3

from .conftest import FakeEffects
from .factories import make_launch_record, make_service_client, make_vm

pytestmark = pytest.mark.django_db

GIB = 1024**3
MIB = 1024**2
SRC_CHIP = "11" * 64
DST_CHIP = "22" * 64


# ── fixtures ─────────────────────────────────────────────────────────


@pytest.fixture(autouse=True)
def _restore_env(monkeypatch: pytest.MonkeyPatch, fx: FakeEffects) -> s3.MockHippiusS3Client:
    from apps.backup import service as backup_service

    monkeypatch.setattr(settings, "VALI_RESTORE_ENABLED", True)
    monkeypatch.setattr(settings, "VALI_BACKUP_BUCKET", "vm-backups")
    monkeypatch.setattr(settings, "VALI_BACKUP_ENABLED", False)
    monkeypatch.setattr(settings, "VALI_PACKER_IMAGES_BUCKET", "images-public")
    monkeypatch.setattr(settings, "VALI_ORCHESTRATION_SNAPSHOT_BUCKET", "migrations")
    client = s3.MockHippiusS3Client()
    monkeypatch.setattr(backup_service, "backup_s3_client", lambda: client)
    monkeypatch.setattr(s3, "get_s3_client", lambda: client)
    # The destination ticket preflight reads Vault; covered by the §25 suite.
    monkeypatch.setattr(restore, "_preflight_dest_ticket", lambda vm: None)
    monkeypatch.setattr(effects, "poll_domain_running_on", fx.poll_domain_running_on)
    # The original's KBS checkpoint before the fence (A2 undo): a KBS without
    # the route here; the rollback suite serves one.
    from apps.orchestration.services import kbs_rollback

    def _no_checkpoint(vm_id: str, **_kw: object) -> None:
        raise effects.KbsRouteMissing("kbs-admin:rollback-checkpoint: 404 (test)")

    monkeypatch.setattr(kbs_rollback, "fetch_checkpoint", _no_checkpoint)
    MinerIdentity.objects.get_or_create(
        miner_id="node-src", defaults={"pubkey_hex": "aa" * 32, "platform_id": SRC_CHIP}
    )
    MinerIdentity.objects.get_or_create(
        miner_id="node-dst", defaults={"pubkey_hex": "bb" * 32, "platform_id": DST_CHIP}
    )
    return client


class _Power:
    """The power API, faked at its two entry points."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self.started: list[tuple[str, bool]] = []
        self.stopped: list[tuple[str, bool]] = []
        self.refuse: str | None = None
        monkeypatch.setattr(power, "start_vm", self._start)
        monkeypatch.setattr(power, "stop_vm", self._stop)

    def _start(self, vm: Vm, *, by_migration: bool = False) -> Vm:
        if self.refuse:
            raise power.PowerOpRefused(self.refuse, "refused")
        self.started.append((vm.vm_id, by_migration))
        Vm.objects.filter(pk=vm.pk).update(
            power_state=VmPowerState.RUNNING, power_state_at=timezone.now()
        )
        return vm

    def _stop(self, vm: Vm, *, by_migration: bool = False) -> Vm:
        if self.refuse:
            raise power.PowerOpRefused(self.refuse, "refused")
        self.stopped.append((vm.vm_id, by_migration))
        Vm.objects.filter(pk=vm.pk).update(
            power_state=VmPowerState.STOPPED, power_state_at=timezone.now()
        )
        return vm


@pytest.fixture
def pwr(monkeypatch: pytest.MonkeyPatch) -> _Power:
    return _Power(monkeypatch)


def _golden_vm(*, power_state: str = VmPowerState.RUNNING, counter: int = 3) -> Vm:
    vm = make_vm(generation=5, host="node-src")
    Vm.objects.filter(pk=vm.pk).update(
        power_state=power_state, power_state_at=timezone.now() - timedelta(days=1)
    )
    vm.refresh_from_db()
    make_launch_record(vm, disk_mode="golden_verity_overlay", flavor="small")
    BackupPolicy.objects.create(
        vm=vm, interval_s=3600, observed_boot_counter=counter, full_required=False
    )
    return vm


def _chain(vm: Vm, *, counter: int = 3, incrementals: int = 2) -> list[BackupRun]:
    chain = BackupChain.objects.create(
        vm=vm, state=ChainState.OPEN, boot_counter=counter, next_seq=incrementals + 1
    )
    runs: list[BackupRun] = []
    for seq in range(incrementals + 1):
        kind = BackupKind.FULL if seq == 0 else BackupKind.INCREMENTAL
        disk = 40 * GIB if seq == 0 else 100 * MIB
        base = f"backups/{vm.vm_id}/{chain.chain_id}/{seq:04d}"
        runs.append(
            BackupRun.objects.create(
                vm=vm,
                chain=chain,
                seq=seq,
                kind=kind,
                status=RunStatus.DONE,
                miner_id="node-src",
                disk_key=f"{base}.{'full.raw' if seq == 0 else 'inc.qcow2'}",
                state_key=f"{base}.state",
                manifest_key=f"{base}.manifest.json",
                parent_run_id=runs[-1].run_id if runs else "",
                part_size=512 * MIB,
                part_count=82,
                disk_bytes=disk,
                disk_sha256_hex="a" * 64,
                part_sha256_hex=["b" * 64] * -(-disk // (512 * MIB)),
                state_bytes=MIB,
                state_sha256_hex="c" * 64,
                boot_counter=counter,
                finished_at=timezone.now(),
            )
        )
    return runs


def _start(vm: Vm, run: BackupRun, **kw: Any) -> MigrationJob:
    job, created = restore.start_restore(
        vm=vm,
        run_id=run.run_id,
        request_id=kw.pop("request_id", f"req-{uuid.uuid4().hex[:8]}"),
        decided_by=kw.pop("decided_by", None) or make_service_client(),
        **kw,
    )
    assert created
    return job


def _advance(job: MigrationJob) -> MigrationJob:
    job = MigrationJob.objects.select_related("vm").get(pk=job.pk)
    service.advance_migration_job(job)
    job.refresh_from_db()
    return job


def _staged(fx: FakeEffects, job: MigrationJob, state: str = "staged", **kw: Any) -> None:
    fx.restore_status[job.dest_node_id] = {
        "vm_id": job.vm.vm_id,
        "restore_id": job.restore_id,
        "op": "stage",
        "state": state,
        "bytes_done": kw.pop("bytes_done", 100),
        "bytes_total": kw.pop("bytes_total", 100),
        "reason": kw.pop("reason", None),
        "swapped": False,
        "pre_restore_present": False,
        "domain_live": True,
    }


def _grant(fx: FakeEffects, job: MigrationJob, *, gen: int | None = None) -> None:
    """The KBS granted the restored guest's release at `new_gen` on the
    destination chip — the commit point."""
    job.refresh_from_db()
    ticket = f"tk-{uuid.uuid4().hex[:8]}"
    OrderTicketIntake.objects.create(
        ticket_id=ticket,
        vm_id=job.vm.vm_id,
        tenant_id="t",
        user_id="u",
        lease_id="l",
        vm_generation=job.new_gen if gen is None else gen,
        issue_time=0,
        expiry=0,
        node_id=job.dest_node_id,
        platform_id=MinerIdentity.objects.get(miner_id=job.dest_node_id).platform_id,
        resource_class="small",
        kid_hex="00",
        cose_blob=b"",
        received_from="system:migration-remint",
    )
    fx.kbs_evidence = {"ticket_id": ticket, "granted_at_unix": int(timezone.now().timestamp()) + 5}


def _original_grant(fx: FakeEffects, job: MigrationJob) -> None:
    """The KBS's latest grant is still the ORIGINAL's (at `source_gen`, on
    the source chip) — the positive evidence a revert needs."""
    job.refresh_from_db()
    ticket = f"tk-{uuid.uuid4().hex[:8]}"
    OrderTicketIntake.objects.create(
        ticket_id=ticket,
        vm_id=job.vm.vm_id,
        tenant_id="t",
        user_id="u",
        lease_id="l",
        vm_generation=job.source_gen,
        issue_time=0,
        expiry=0,
        node_id=job.source_node_id,
        platform_id=SRC_CHIP,
        resource_class="small",
        kid_hex="00",
        cose_blob=b"",
        received_from="launch",
    )
    fx.kbs_evidence = {"ticket_id": ticket, "granted_at_unix": 1}


def _to_verifying(fx: FakeEffects, pwr: _Power, job: MigrationJob) -> MigrationJob:
    _staged(fx, job)
    job = _advance(job)
    assert job.state == MigrationState.RESTORE_STOPPING.value
    fx.domain_running = False
    for _ in range(2):  # stop dispatched (a running vm), then seen down
        job = _advance(job)
        if job.state != MigrationState.RESTORE_STOPPING.value:
            break
    assert job.state == MigrationState.DEST_ACTIVATING.value
    fx.kbs_evidence = None  # nothing released yet
    job = _advance(job)
    assert job.state == MigrationState.RESTORE_VERIFYING.value, job.reason
    return job


def _age_phase(job: MigrationJob, seconds: float = 7200) -> None:
    MigrationJob.objects.filter(pk=job.pk).update(
        phase_started_at=timezone.now() - timedelta(seconds=seconds)
    )


# ── intake ───────────────────────────────────────────────────────────


def test_the_flag_off_refuses_a_restore(monkeypatch) -> None:
    monkeypatch.setattr(settings, "VALI_RESTORE_ENABLED", False)
    vm = _golden_vm()
    run = _chain(vm)[-1]
    with pytest.raises(restore.RestoreError) as exc:
        _start(vm, run)
    assert exc.value.code == "restore-disabled"
    assert not MigrationJob.objects.exists()


def test_a_restore_opens_staging_on_the_current_host_by_default() -> None:
    vm = _golden_vm()
    run = _chain(vm)[1]
    job = _start(vm, run)
    assert job.kind == MigrationKind.RESTORE.value
    assert job.state == MigrationState.RESTORE_STAGING.value
    assert (job.source_node_id, job.dest_node_id) == ("node-src", "node-src")
    assert (job.source_gen, job.new_gen) == (5, 6)
    assert job.restore_run_id == run.pk
    assert len(job.restore_id) == 32 and int(job.restore_id, 16) >= 0
    assert job.prior_power_state == "running" and not job.cold
    assert job.authorization.kind == MigrationKind.RESTORE.value
    assert job.authorization.request_id == job.request_id
    assert job.restore_eta_s and job.restore_eta_s > 0


def test_the_same_request_id_is_the_same_job() -> None:
    vm = _golden_vm()
    run = _chain(vm)[-1]
    actor = make_service_client()
    first, created = restore.start_restore(
        vm=vm, run_id=run.run_id, request_id="req-1", decided_by=actor
    )
    again, created_again = restore.start_restore(
        vm=vm, run_id=run.run_id, request_id="req-1", decided_by=actor
    )
    assert created and not created_again and again.pk == first.pk
    assert MigrationJob.objects.count() == 1


def test_a_request_id_reused_for_another_vm_is_refused() -> None:
    vm = _golden_vm()
    run = _chain(vm)[-1]
    _start(vm, run, request_id="req-x")
    other = make_vm("vm-2", generation=1, host="node-src")
    with pytest.raises(restore.RestoreError) as exc:
        restore.start_restore(
            vm=other, run_id=run.run_id, request_id="req-x", decided_by=make_service_client()
        )
    assert exc.value.code == "request-id-conflict"


def test_a_point_of_an_earlier_boot_is_rollback_unsupported() -> None:
    vm = _golden_vm(counter=4)  # the guest rebooted since this chain
    run = _chain(vm, counter=3)[-1]
    with pytest.raises(restore.RestoreError) as exc:
        _start(vm, run)
    assert exc.value.code == "rollback-unsupported"


def test_an_unfinished_run_is_not_a_point() -> None:
    vm = _golden_vm()
    runs = _chain(vm)
    BackupRun.objects.filter(pk=runs[-1].pk).update(status=RunStatus.FAILED)
    with pytest.raises(restore.RestoreError) as exc:
        _start(vm, runs[-1])
    assert exc.value.code == "point-not-restorable"


def test_a_vm_with_a_job_in_flight_is_refused() -> None:
    vm = _golden_vm()
    runs = _chain(vm)
    _start(vm, runs[-1])
    with pytest.raises(restore.RestoreError) as exc:
        _start(vm, runs[0])
    assert exc.value.code == "job-in-flight"


@pytest.mark.parametrize("state", [VmState.MIGRATING, VmState.DECOMMISSIONING])
def test_a_vm_that_is_not_active_is_refused(state) -> None:
    vm = _golden_vm()
    run = _chain(vm)[-1]
    Vm.objects.filter(pk=vm.pk).update(state=state, migration_dest="node-dst", new_generation=6)
    vm.refresh_from_db()
    with pytest.raises(restore.RestoreError) as exc:
        _start(vm, run)
    assert exc.value.code in ("vm-not-restorable", "point-not-restorable")


def test_a_stopped_vm_is_restored_cold() -> None:
    vm = _golden_vm(power_state=VmPowerState.STOPPED)
    job = _start(vm, _chain(vm)[-1])
    assert job.prior_power_state == "stopped" and job.cold


def test_another_destination_must_be_the_same_snp_generation(monkeypatch) -> None:
    from apps.scheduler import service as sched

    vm = _golden_vm()
    run = _chain(vm)[-1]
    MinerIdentity.objects.filter(miner_id="node-dst").update(platform_id="22" * 8)  # Turin
    monkeypatch.setattr(
        sched, "dispatchability", lambda m, **kw: sched.Dispatchability(True, None)
    )
    with pytest.raises(restore.RestoreError) as exc:
        _start(vm, run, dest_node_id="node-dst")
    assert exc.value.code == "no-eligible-miner" and "generation" in exc.value.detail


def test_another_destination_needs_room_for_the_flavor(monkeypatch) -> None:
    from apps.scheduler import service as sched

    vm = _golden_vm()
    run = _chain(vm)[-1]
    MinerIdentity.objects.filter(miner_id="node-dst").update(chain_node_id="d" * 64)
    monkeypatch.setattr(
        sched, "dispatchability", lambda m, **kw: sched.Dispatchability(True, None)
    )
    monkeypatch.setattr(
        sched,
        "host_resources_by_node",
        lambda: {"d" * 64: sched.HostResources(1024, 8, 10**6, 64)},
    )
    with pytest.raises(restore.RestoreError) as exc:
        _start(vm, run, dest_node_id="node-dst")
    assert exc.value.code == "no-eligible-miner" and "room" in exc.value.detail

    monkeypatch.setattr(
        sched,
        "host_resources_by_node",
        lambda: {"d" * 64: sched.HostResources(64 * 1024, 8, 10**6, 64)},
    )
    job = _start(vm, run, dest_node_id="node-dst")
    assert (job.source_node_id, job.dest_node_id) == ("node-src", "node-dst")


def test_an_undispatchable_destination_is_refused() -> None:
    vm = _golden_vm()
    run = _chain(vm)[-1]
    with pytest.raises(restore.RestoreError) as exc:
        _start(vm, run, dest_node_id="node-dst")  # no heartbeat, no chain id
    assert exc.value.code == "no-eligible-miner"


# ── staging: the original keeps running ──────────────────────────────


def test_staging_sends_the_chain_to_the_destination_and_leaves_the_vm_alone(
    fx: FakeEffects, pwr: _Power
) -> None:
    vm = _golden_vm()
    runs = _chain(vm, incrementals=2)
    job = _start(vm, runs[1])
    fx.restore_status = {}  # the destination knows nothing yet
    job = _advance(job)
    assert job.state == MigrationState.RESTORE_STAGING.value
    [(miner, order_id, payload)] = fx.restore_orders
    assert miner == "node-src" and order_id == f"restore-stage-{job.restore_id}-0"
    assert payload["op"] == "stage" and payload["restore_id"] == job.restore_id
    assert payload["disk_bytes"] == 40 * GIB and payload["streams"] == 8
    chain = payload["chain"]
    assert chain["restore_id"] == job.restore_id
    # Truncated at the chosen run: the later incremental is not applied.
    assert len(chain["incrementals"]) == 1
    assert chain["full"]["part_size"] == 512 * MIB
    vm.refresh_from_db()
    assert vm.state == VmState.ACTIVE and vm.power_state == VmPowerState.RUNNING
    assert pwr.stopped == [] and not fx.did("kbs_activate_dest")

    # Paced: not re-sent on the next tick.
    job = _advance(job)
    assert len(fx.restore_orders) == 1

    _staged(fx, job, "staging", bytes_done=25, bytes_total=100)
    job = _advance(job)
    assert (job.restore_bytes_done, job.restore_bytes_total) == (25, 100)
    assert restore.serialize(job)["pct"] == 25
    assert restore.serialize(job)["phase"] == "staging"

    _staged(fx, job)
    job = _advance(job)
    assert job.state == MigrationState.RESTORE_STOPPING.value


def test_a_staging_failure_fails_the_job_and_never_touches_the_vm(
    fx: FakeEffects, pwr: _Power
) -> None:
    vm = _golden_vm()
    job = _start(vm, _chain(vm)[-1])
    _staged(fx, job, "failed", reason="sha-mismatch")
    job = _advance(job)
    assert job.state == MigrationState.FAILED.value
    assert job.reason == "stage-sha-mismatch" and not job.reverted
    assert job.restore_cleanup_pending
    assert restore.serialize(job)["phase"] == "failed"
    vm.refresh_from_db()
    assert (vm.state, vm.power_state, vm.generation) == (VmState.ACTIVE, "running", 5)
    assert pwr.stopped == [] and not fx.did("kbs_activate_dest")


def test_a_lost_staging_is_resent_a_bounded_number_of_times(
    fx: FakeEffects, pwr: _Power, monkeypatch
) -> None:
    monkeypatch.setattr(settings, "VALI_RESTORE_STAGE_REDISPATCH_S", 0.0, raising=False)
    vm = _golden_vm()
    job = _start(vm, _chain(vm)[-1])
    for _ in range(3):
        job = _advance(job)
    assert [o[1][-2:] for o in fx.restore_orders] == ["-0", "-1", "-2"]
    job = _advance(job)
    assert job.state == MigrationState.FAILED.value and job.reason == "stage-lost"


def test_a_staging_timeout_fails_with_a_stage_reason(fx: FakeEffects, pwr: _Power) -> None:
    vm = _golden_vm()
    job = _start(vm, _chain(vm)[-1])
    _staged(fx, job, "staging")
    _age_phase(job, 13 * 3600)
    job = _advance(job)
    assert job.state == MigrationState.FAILED.value and job.reason == "stage-timeout"


# ── stopping ─────────────────────────────────────────────────────────


def test_stopping_uses_the_power_api_and_waits_for_the_host_to_report_down(
    fx: FakeEffects, pwr: _Power
) -> None:
    vm = _golden_vm()
    job = _start(vm, _chain(vm)[-1])
    _staged(fx, job)
    job = _advance(job)
    job = _advance(job)
    assert pwr.stopped == [(vm.vm_id, True)]
    for answer in (True, None):
        fx.domain_running = answer
        job = _advance(job)
        assert job.state == MigrationState.RESTORE_STOPPING.value
        assert not job.authorization.evidence.get("source_domain_down")
    fx.domain_running = False
    job = _advance(job)
    assert job.state == MigrationState.DEST_ACTIVATING.value
    assert job.authorization.evidence["source_domain_down"] is True
    assert pwr.stopped == [(vm.vm_id, True)], "stopped once"
    vm.refresh_from_db()
    assert vm.state == VmState.ACTIVE, "the fence is DestActivating's first step"


def test_an_already_stopped_vm_is_not_stopped_again(fx: FakeEffects, pwr: _Power) -> None:
    vm = _golden_vm(power_state=VmPowerState.STOPPED)
    job = _start(vm, _chain(vm)[-1])
    _staged(fx, job)
    job = _advance(job)
    fx.domain_running = False
    job = _advance(job)
    assert job.state == MigrationState.DEST_ACTIVATING.value and pwr.stopped == []


# ── activation, the commit point, done ───────────────────────────────


def test_a_restore_activates_the_destination_only_on_the_kbs_grant(
    fx: FakeEffects, pwr: _Power
) -> None:
    vm = _golden_vm()
    job = _start(vm, _chain(vm)[-1])
    job = _to_verifying(fx, pwr, job)

    vm.refresh_from_db()
    assert vm.state == VmState.MIGRATING
    assert (vm.migration_dest, vm.new_generation) == ("node-src", 6)
    # The KBS was activated at new_gen on the destination — here the same host.
    assert ("kbs_activate_dest", vm.vm_id, "node-src", 6) in fx.calls
    assert fx.activate_restore == {
        "staged_restore_id": job.restore_id,
        "get_url": "",
        "backup_chain": None,
    }
    assert restore.serialize(job)["phase"] == "verifying"

    # The destination's "done" alone never activates the VM.
    job = _advance(job)
    assert job.state == MigrationState.RESTORE_VERIFYING.value

    _grant(fx, job)
    job = _advance(job)
    assert job.state == MigrationState.DONE.value
    vm.refresh_from_db()
    assert (vm.state, vm.host, vm.generation) == (VmState.ACTIVE, "node-src", 6)
    assert vm.power_state == VmPowerState.RUNNING
    assert BackupPolicy.objects.get(vm=vm).full_required
    # Done on the KBS proof; the caller sees `verifying` until the restored
    # guest also proved it runs.
    assert restore.serialize(job)["phase"] == "verifying"
    assert restore.serialize(job)["finished_at"] is None
    now = timezone.now()
    MigrationJob.objects.filter(pk=job.pk).update(finished_at=now - timedelta(hours=1))
    Vm.objects.filter(pk=vm.pk).update(guest_signal_at=now)
    job.refresh_from_db()
    assert restore.serialize(job)["phase"] == "done"
    assert restore.serialize(job)["finished_at"] is not None


def test_a_grant_at_another_generation_is_not_the_commit(fx: FakeEffects, pwr: _Power) -> None:
    vm = _golden_vm()
    job = _to_verifying(fx, pwr, _start(vm, _chain(vm)[-1]))
    _grant(fx, job, gen=5)  # the original's own release
    job = _advance(job)
    assert job.state == MigrationState.RESTORE_VERIFYING.value


def test_a_restore_onto_another_miner_moves_the_vm(
    fx: FakeEffects, pwr: _Power, monkeypatch
) -> None:
    monkeypatch.setattr(restore, "_validate_other_dest", lambda vm, dest: None)
    vm = _golden_vm()
    job = _start(vm, _chain(vm)[-1], dest_node_id="node-dst")
    job = _to_verifying(fx, pwr, job)
    assert ("kbs_activate_dest", vm.vm_id, "node-dst", 6) in fx.calls
    _grant(fx, job)
    job = _advance(job)
    vm.refresh_from_db()
    assert (job.state, vm.host, vm.generation) == (MigrationState.DONE.value, "node-dst", 6)


def test_the_billing_cutover_is_when_the_source_went_down(fx: FakeEffects, pwr: _Power) -> None:
    vm = _golden_vm()
    job = _to_verifying(fx, pwr, _start(vm, _chain(vm)[-1]))
    down = restore.activation_started_at(job)
    assert down is not None
    _age_phase(job)  # the verifying phase began later than the source went down
    job.refresh_from_db()
    assert service._billing_cutover_unix(job) == int(down.timestamp())
    assert service._billing_cutover_unix(job) != int(job.phase_started_at.timestamp())


# ── the guard: each kind its own justification ───────────────────────


def _restore_at_dest_activating(vm: Vm, **auth_kw: Any) -> MigrationJob:
    actor = make_service_client()
    auth = None
    if auth_kw.get("kind") is not None:
        auth = DestAuthorization.objects.create(
            kind=auth_kw["kind"],
            requested_by=actor,
            request_id=auth_kw.get("request_id", "req-g"),
            evidence=auth_kw.get("evidence", {"source_domain_down": True}),
        )
    return MigrationJob.objects.create(
        job_id=uuid.uuid4().hex,
        kind=auth_kw.get("job_kind", MigrationKind.RESTORE.value),
        vm=vm,
        source_node_id="node-src",
        dest_node_id="node-src",
        source_gen=5,
        new_gen=6,
        state=MigrationState.DEST_ACTIVATING.value,
        phase_started_at=timezone.now(),
        decided_by=actor,
        request_id="req-g",
        restore_id="ab" * 16,
        authorization=auth,
        source_ack_verified=auth_kw.get("ack", False),
    )


@pytest.mark.parametrize(
    ("auth_kw", "reason"),
    [
        ({}, "dest-activating-without-restore-authorization"),
        ({"ack": True}, "dest-activating-without-restore-authorization"),
        ({"kind": "failover", "evidence": {"dead": True}}, "authorization-kind-mismatch"),
        ({"kind": "restore", "request_id": "other"}, "authorization-request-mismatch"),
        ({"kind": "restore", "evidence": {}}, "restore-without-source-down"),
    ],
)
def test_a_restore_never_activates_without_its_own_justification(
    fx: FakeEffects, auth_kw, reason
) -> None:
    vm = _golden_vm()
    job = _restore_at_dest_activating(vm, **auth_kw)
    assert service._migration_guard(job).startswith(reason)
    _advance(job)
    assert not fx.did("kbs_activate_dest") and not fx.did("dispatch_migrate_activate")


def test_a_migration_is_not_activated_on_a_restore_authorization(fx: FakeEffects) -> None:
    vm = _golden_vm()
    job = _restore_at_dest_activating(vm, kind="restore", job_kind=MigrationKind.MIGRATE.value)
    assert service._migration_guard(job) == "dest-activating-without-verified-source-ack"
    _advance(job)
    assert not fx.did("kbs_activate_dest")


def test_a_restore_with_its_justification_passes_the_guard() -> None:
    vm = _golden_vm()
    job = _restore_at_dest_activating(vm, kind="restore")
    assert service._migration_guard(job) is None


def test_a_job_in_another_kinds_state_fails_closed() -> None:
    vm = _golden_vm()
    job = _restore_at_dest_activating(vm, kind="restore")
    MigrationJob.objects.filter(pk=job.pk).update(state=MigrationState.QUIESCING.value)
    job.refresh_from_db()
    assert service._migration_guard(job) == "state-not-for-kind:quiescing:restore"
    MigrationJob.objects.filter(pk=job.pk).update(
        kind=MigrationKind.MIGRATE.value, state=MigrationState.RESTORE_STAGING.value
    )
    job.refresh_from_db()
    assert service._migration_guard(job).startswith("state-not-for-kind")


# ── failure before the commit point: revert ──────────────────────────


def test_a_failure_before_the_commit_point_reverts_to_the_original(
    fx: FakeEffects, pwr: _Power
) -> None:
    vm = _golden_vm()
    job = _to_verifying(fx, pwr, _start(vm, _chain(vm)[-1]))
    _original_grant(fx, job)
    _age_phase(job)
    job = _advance(job)
    assert job.state == MigrationState.RESTORE_REVERTING.value
    assert job.reason == "verify-timeout"

    job = _advance(job)  # fence forward, abort, unfence, relaunch
    # KBS: forward-only, one generation up, back on the SOURCE chip.
    assert ("kbs_activate_dest", vm.vm_id, "node-src", 7) in fx.calls
    assert [(m, p["op"]) for m, _o, p in fx.restore_orders if p["op"] == "abort"] == [
        ("node-src", "abort")
    ]
    vm.refresh_from_db()
    assert (vm.state, vm.host, vm.generation) == (VmState.ACTIVE, "node-src", 7)
    assert pwr.started == [(vm.vm_id, True)], "relaunched: it was running"
    job = _advance(job)
    assert job.state == MigrationState.FAILED.value and job.reverted
    assert restore.serialize(job)["phase"] == "reverted"
    assert job.source_reclaim_state == SourceReclaimState.PENDING.value


def test_a_revert_leaves_a_stopped_vm_stopped(fx: FakeEffects, pwr: _Power) -> None:
    vm = _golden_vm(power_state=VmPowerState.STOPPED)
    job = _to_verifying(fx, pwr, _start(vm, _chain(vm)[-1]))
    _original_grant(fx, job)
    _age_phase(job)
    job = _advance(job)
    job = _advance(job)
    assert job.state == MigrationState.FAILED.value and job.reverted
    assert pwr.started == []
    vm.refresh_from_db()
    assert vm.power_state == VmPowerState.STOPPED and vm.generation == 7


def test_a_destination_that_fails_to_boot_reverts(
    fx: FakeEffects, pwr: _Power, monkeypatch
) -> None:
    monkeypatch.setattr(settings, "VALI_MIGRATION_DEST_ACTIVATE_MAX_ATTEMPTS", 1)
    vm = _golden_vm()
    job = _start(vm, _chain(vm)[-1])
    _staged(fx, job)
    job = _advance(job)
    job = _advance(job)
    job = _advance(job)
    assert job.state == MigrationState.DEST_ACTIVATING.value
    _original_grant(fx, job)
    fx.dest_activation_status = "failed"
    fx.dest_activation_class = "migration/launch-failed"
    job = _advance(job)  # attempt 0 dispatched and reported failed
    job = _advance(job)
    assert job.state == MigrationState.RESTORE_REVERTING.value
    assert job.reason.startswith("activate-failed")


@pytest.mark.parametrize(
    "failure_class",
    [
        "migration/restore-staged-missing",
        "migration/restore-not-staged",
        "migration/staged-restore-conflict",
        "migration/restore-size-mismatch",
        "migration/restore-swap-conflict",
    ],
)
def test_a_deterministic_staged_restore_refusal_reverts_after_one_attempt(
    fx: FakeEffects, pwr: _Power, failure_class: str
) -> None:
    """Live: a same-host restore's `migrate-activate` refused with
    `restore-staged-missing` (the staged overlay was gone), and vali
    re-dispatched the SAME doomed order twice more — `-a1`, `-a2`, ~2
    minutes apart — before its pre-commit revert, holding the VM down for
    ~4 extra minutes on a class that a retry cannot change (the on-disk
    staging state is what it is). Unlike `test_a_destination_that_fails_
    to_boot_reverts`, `VALI_MIGRATION_DEST_ACTIVATE_MAX_ATTEMPTS` is left
    at its default (3): the assertion is that this class skips the retry
    budget entirely, not merely that a 1-attempt budget reverts."""
    vm = _golden_vm()
    job = _start(vm, _chain(vm)[-1])
    _staged(fx, job)
    job = _advance(job)
    job = _advance(job)
    job = _advance(job)
    assert job.state == MigrationState.DEST_ACTIVATING.value
    _original_grant(fx, job)
    fx.dest_activation_status = "failed"
    fx.dest_activation_class = failure_class
    job = _advance(job)  # attempt 0 dispatched and reported failed — terminal
    job = _advance(job)
    assert job.state == MigrationState.RESTORE_REVERTING.value
    assert job.reason == f"activate-failed:{failure_class}"
    dispatches = [c[6] for c in fx.calls if c[0] == "dispatch_migrate_activate"]
    assert dispatches == [0], "a deterministic refusal is never retried"


def test_a_transient_restore_swap_failure_still_retries(
    fx: FakeEffects, pwr: _Power
) -> None:
    """`restore-swap-io` is an ordinary write/rename/fsync failure — unlike
    the deterministic staged-restore refusals above, a retry can succeed,
    so it stays in the bounded retry loop rather than reverting at once."""
    vm = _golden_vm()
    job = _start(vm, _chain(vm)[-1])
    _staged(fx, job)
    job = _advance(job)
    job = _advance(job)
    job = _advance(job)
    assert job.state == MigrationState.DEST_ACTIVATING.value
    _original_grant(fx, job)
    fx.dest_activation_status = "failed"
    fx.dest_activation_class = "migration/restore-swap-io"
    job = _advance(job)  # attempt 0 dispatched and reported failed — retryable
    assert job.state == MigrationState.DEST_ACTIVATING.value, "retried, not reverted"

    _age_phase(job, 130)  # past the backoff floor
    fx.dest_activation_status = "done"
    job = _advance(job)  # attempt 1 — a new order, this time it succeeds
    assert job.state == MigrationState.RESTORE_VERIFYING.value
    dispatches = [c[6] for c in fx.calls if c[0] == "dispatch_migrate_activate"]
    assert dispatches == [0, 1]


def test_a_restored_guest_that_released_during_the_revert_blocks_it(
    fx: FakeEffects, pwr: _Power
) -> None:
    vm = _golden_vm()
    job = _to_verifying(fx, pwr, _start(vm, _chain(vm)[-1]))
    _original_grant(fx, job)
    _age_phase(job)
    job = _advance(job)
    assert job.state == MigrationState.RESTORE_REVERTING.value

    real = effects.kbs_activate_dest

    def _activate_then_grant(vm_, **kw):
        real_fake(vm_, **kw)
        _grant(fx, job)

    real_fake = fx.kbs_activate_dest
    effects.kbs_activate_dest = _activate_then_grant
    try:
        job = _advance(job)
    finally:
        effects.kbs_activate_dest = real
    assert job.state == MigrationState.FAILED.value
    assert job.reason == "revert-failed:blocked:revert-raced-commit:kbs-grant-at-new-gen"
    assert not job.reverted and pwr.started == []
    vm.refresh_from_db()
    assert vm.state == VmState.MIGRATING, "never relaunched into a 403"


# ── failure after the commit point: keep the original ────────────────


def test_a_failure_after_the_commit_point_keeps_the_original(
    fx: FakeEffects, pwr: _Power
) -> None:
    vm = _golden_vm()
    job = _to_verifying(fx, pwr, _start(vm, _chain(vm)[-1]))
    # The restored guest spoke (it unlocked), but the KBS bundle never came.
    Vm.objects.filter(pk=vm.pk).update(guest_signal_at=timezone.now() + timedelta(seconds=5))
    _age_phase(job)
    job = _advance(job)
    assert job.state == MigrationState.FAILED.value
    assert job.reason == "failed-after-commit:verify-timeout"
    assert not job.reverted and job.restore_keep_original_until is not None
    assert job.restore_keep_original_until > timezone.now() + timedelta(hours=23)
    assert [p["op"] for _m, _o, p in fx.restore_orders if p["op"] != "stage"] == []
    assert ("kbs_activate_dest", vm.vm_id, "node-src", 7) not in fx.calls
    vm.refresh_from_db()
    assert vm.state == VmState.MIGRATING


def test_a_kek_released_milestone_counts_as_committed(fx: FakeEffects, pwr: _Power) -> None:
    vm = _golden_vm()
    job = _to_verifying(fx, pwr, _start(vm, _chain(vm)[-1]))
    Vm.objects.filter(pk=vm.pk).update(boot_phase=VmBootPhase.KEK_RELEASED.value)
    _age_phase(job)
    job = _advance(job)
    assert job.state == MigrationState.FAILED.value and job.reason.startswith(
        "failed-after-commit"
    )


def test_an_unreadable_kbs_decides_nothing_until_twice_the_deadline(
    fx: FakeEffects, pwr: _Power
) -> None:
    vm = _golden_vm()
    job = _to_verifying(fx, pwr, _start(vm, _chain(vm)[-1]))
    fx.kbs_evidence = effects.EffectUnavailable("kbs down")
    _age_phase(job, 1000)  # past the 900 s deadline
    job = _advance(job)
    assert job.state == MigrationState.RESTORE_VERIFYING.value
    _age_phase(job, 1900)  # past twice the deadline
    job = _advance(job)
    assert job.state == MigrationState.FAILED.value
    assert job.reason == "blocked:commit-undecidable:verify-timeout"
    assert not job.reverted and job.restore_keep_original_until is not None


# ── reclaim after done ───────────────────────────────────────────────


def _done(fx: FakeEffects, pwr: _Power, vm: Vm, **kw: Any) -> MigrationJob:
    job = _to_verifying(fx, pwr, _start(vm, _chain(vm)[-1], **kw))
    _grant(fx, job)
    job = _advance(job)
    assert job.state == MigrationState.DONE.value
    return job


def _alive(job: MigrationJob) -> None:
    """The restored guest proved it runs, an hour after the job finished
    (everything the job stamped is moved back with it)."""
    now = timezone.now()
    finished = now - timedelta(hours=1)
    MigrationJob.objects.filter(pk=job.pk).update(finished_at=finished)
    Vm.objects.filter(pk=job.vm_id).update(
        guest_signal_at=now, power_state_at=finished - timedelta(seconds=1)
    )


def test_the_original_is_reclaimed_only_after_the_restored_vm_is_alive(
    fx: FakeEffects, pwr: _Power
) -> None:
    vm = _golden_vm()
    job = _done(fx, pwr, vm)
    service.reclaim_migrated_sources()
    assert [p["op"] for _m, _o, p in fx.restore_orders if p["op"] == "reclaim"] == []
    _alive(job)
    service.reclaim_migrated_sources()
    [(miner, order_id, payload)] = [o for o in fx.restore_orders if o[2]["op"] == "reclaim"]
    assert miner == "node-src" and payload["restore_id"] == job.restore_id
    assert not fx.did("dispatch_destroy")
    job.refresh_from_db()
    assert job.source_reclaim_state == SourceReclaimState.RECLAIMED.value


def test_a_restore_onto_another_miner_also_reclaims_the_source(
    fx: FakeEffects, pwr: _Power, monkeypatch
) -> None:
    calls: list[tuple[str, str]] = []
    monkeypatch.setattr(restore, "_validate_other_dest", lambda vm, dest: None)
    monkeypatch.setattr(
        effects,
        "dispatch_source_reclaim",
        lambda vm, *, source_node_id, job_id: calls.append((source_node_id, job_id)),
    )
    vm = _golden_vm()
    job = _done(fx, pwr, vm, dest_node_id="node-dst")
    _alive(job)
    service.reclaim_migrated_sources()
    assert [o[0] for o in fx.restore_orders if o[2]["op"] == "reclaim"] == ["node-dst"]
    assert calls == [("node-src", job.job_id)]


def test_a_stopped_vm_is_stopped_again_once_the_restore_proved_it_runs(
    fx: FakeEffects, pwr: _Power
) -> None:
    vm = _golden_vm(power_state=VmPowerState.STOPPED)
    job = _done(fx, pwr, vm)
    assert restore.serialize(job)["phase"] == "verifying"
    service.settle_cold_migrations()
    assert pwr.stopped == [], "not before the restored VM is proven"
    _alive(job)
    service.reclaim_migrated_sources()
    job.refresh_from_db()
    assert restore.serialize(job)["phase"] == "settling"
    service.settle_cold_migrations()
    assert pwr.stopped == [(vm.vm_id, False)]
    job.refresh_from_db()
    assert restore.serialize(job)["phase"] == "done"


def test_the_original_of_a_failed_after_commit_restore_waits_out_the_keep_window(
    fx: FakeEffects, pwr: _Power
) -> None:
    vm = _golden_vm()
    job = _to_verifying(fx, pwr, _start(vm, _chain(vm)[-1]))
    Vm.objects.filter(pk=vm.pk).update(guest_signal_at=timezone.now() + timedelta(seconds=5))
    _age_phase(job)
    job = _advance(job)
    assert job.restore_keep_original_until is not None
    service.reclaim_migrated_sources()
    assert not [o for o in fx.restore_orders if o[2]["op"] == "reclaim"]


# ── cancel + cleanup ─────────────────────────────────────────────────


def test_cancel_is_only_allowed_before_the_fence(fx: FakeEffects, pwr: _Power) -> None:
    vm = _golden_vm()
    job = _start(vm, _chain(vm)[-1])
    job = restore.cancel_restore(job=job, decided_by=make_service_client("op"))
    assert job.state == MigrationState.FAILED.value and job.reason == "cancelled by op"
    assert job.failed_from_state == MigrationState.RESTORE_STAGING.value
    assert job.restore_cleanup_pending

    job2 = _start(vm, _chain(vm)[-1])
    job2 = _to_verifying(fx, pwr, job2)
    with pytest.raises(restore.RestoreError) as exc:
        restore.cancel_restore(job=job2, decided_by=make_service_client())
    assert exc.value.code == "not-cancellable"


def test_a_cancel_after_the_stop_starts_the_vm_again(fx: FakeEffects, pwr: _Power) -> None:
    vm = _golden_vm()
    job = _start(vm, _chain(vm)[-1])
    _staged(fx, job)
    job = _advance(job)
    job = _advance(job)  # stopped
    assert job.state == MigrationState.RESTORE_STOPPING.value
    restore.cancel_restore(job=job, decided_by=make_service_client())
    fx.domain_running = False
    assert restore.sweep_restore_cleanups() == 1
    assert [p["op"] for _m, _o, p in fx.restore_orders if p["op"] == "abort"] == ["abort"]
    assert pwr.started == [(vm.vm_id, False)]
    job.refresh_from_db()
    assert not job.restore_cleanup_pending


def test_cleanup_never_restarts_a_vm_the_job_did_not_stop(fx: FakeEffects, pwr: _Power) -> None:
    vm = _golden_vm(power_state=VmPowerState.STOPPED)
    job = _start(vm, _chain(vm)[-1])
    restore.cancel_restore(job=job, decided_by=make_service_client())
    assert restore.sweep_restore_cleanups() == 1
    assert pwr.started == []


def test_cleanup_leaves_a_vm_the_tenant_touched_since(fx: FakeEffects, pwr: _Power) -> None:
    vm = _golden_vm()
    job = _start(vm, _chain(vm)[-1])
    _staged(fx, job)
    job = _advance(job)
    job = _advance(job)
    job = restore.cancel_restore(job=job, decided_by=make_service_client())
    Vm.objects.filter(pk=vm.pk).update(power_state_at=job.finished_at + timedelta(seconds=30))
    fx.domain_running = False
    restore.sweep_restore_cleanups()
    assert pwr.started == []


def test_a_refused_abort_keeps_the_cleanup_pending(fx: FakeEffects, pwr: _Power) -> None:
    vm = _golden_vm()
    job = _start(vm, _chain(vm)[-1])
    restore.cancel_restore(job=job, decided_by=make_service_client())
    fx.restore_reject = ("restore-vm-live", 409)
    assert restore.sweep_restore_cleanups() == 0
    job.refresh_from_db()
    assert job.restore_cleanup_pending


# ── strands, pruning pin, payloads ───────────────────────────────────


def test_a_vm_stranded_by_a_restore_job_is_never_restored_or_redriven(
    fx: FakeEffects, pwr: _Power
) -> None:
    vm = _golden_vm()
    job = _to_verifying(fx, pwr, _start(vm, _chain(vm)[-1]))
    Vm.objects.filter(pk=vm.pk).update(guest_signal_at=timezone.now() + timedelta(seconds=5))
    _age_phase(job)
    job = _advance(job)
    vm.refresh_from_db()
    verdict = service.stranded_recovery_verdict(vm, job)
    assert verdict.action == service.STRAND_BLOCKED and verdict.reason.startswith("restore-job")

    from apps.orchestration.management.commands.vali_migration_recover import Command

    assert "not re-driven" in Command()._redrive_blocker(vm, job)


def test_a_chain_is_pinned_while_a_restore_uses_it(fx: FakeEffects) -> None:
    from apps.backup import service as backup_service

    vm = _golden_vm()
    runs = _chain(vm)
    chain = runs[0].chain
    BackupChain.objects.filter(pk=chain.pk).update(
        state=ChainState.CLOSED, closed_at=timezone.now() - timedelta(days=30)
    )
    chain.refresh_from_db()
    job = _start(vm, runs[-1])
    policy = BackupPolicy.objects.get(vm=vm)
    assert not backup_service._prunable(chain, policy, timezone.now())
    restore.cancel_restore(job=job, decided_by=make_service_client())
    assert backup_service._prunable(chain, policy, timezone.now())


def test_backups_pause_while_a_restore_is_in_flight(fx: FakeEffects) -> None:
    from apps.backup import service as backup_service

    vm = _golden_vm()
    _start(vm, _chain(vm)[-1])
    assert backup_service._orchestration_job_in_flight(vm)


def test_the_staged_activation_payload_carries_no_download() -> None:
    from apps.orchestration import order_dispatch

    common = dict(
        vm_id="vm-1",
        new_gen=6,
        ovmf_path="o",
        kernel_path="k",
        initrd_path="i",
        cmdline="c",
        luks_disk_path="l",
        luks_disk_size_gb=40,
        rootfs_data_path="",
        rootfs_hash_path="",
        cpu_count=1,
        memory_mb=4096,
        cose_ticket=b"t",
    )
    payload = order_dispatch.build_migrate_activate_payload(
        get_url="", staged_restore_id="ab" * 16, **common
    )
    assert payload["staged_restore_id"] == "ab" * 16
    assert not {"get_url", "state_get_url", "backup_chain", "snapshot_size"} & set(payload)
    plain = order_dispatch.build_migrate_activate_payload(get_url="https://g", **common)
    assert plain["get_url"] == "https://g" and "staged_restore_id" not in plain
    for conflict in (
        {"get_url": "https://g"},
        {"get_url": "", "state_get_url": "https://s"},
        {"get_url": "", "backup_chain": {"restore_id": "x"}},
    ):
        with pytest.raises(ValueError):
            order_dispatch.build_migrate_activate_payload(
                staged_restore_id="ab" * 16, **{**common, **conflict}
            )


def test_the_kbs_activate_omits_an_empty_snapshot_url(fx: FakeEffects, monkeypatch) -> None:
    sent: list[dict[str, Any]] = []
    monkeypatch.setattr(effects, "_kbs_post", lambda vm, cmd, body: sent.append(body))
    vm = _golden_vm()
    fx.real["kbs_activate_dest"](vm, dest_node_id="node-src", new_gen=7, get_url="")
    fx.real["kbs_activate_dest"](vm, dest_node_id="node-dst", new_gen=8, get_url="https://g")
    assert sent == [
        {"dest_node_id": SRC_CHIP, "new_gen": 7},
        {"dest_node_id": DST_CHIP, "new_gen": 8, "snapshot_get_url": "https://g"},
    ]


def test_the_restore_status_is_type_checked() -> None:
    good = {
        "vm_id": "vm-1",
        "restore_id": "ab" * 16,
        "op": "stage",
        "state": "staging",
        "bytes_done": 1,
        "bytes_total": 2,
        "reason": None,
        "swapped": False,
        "pre_restore_present": False,
        "domain_live": True,
    }
    assert restore.parse_restore_status(good, vm_id="vm-1").bytes_total == 2
    for bad in (
        {**good, "vm_id": "vm-2"},
        {**good, "state": "weird"},
        {**good, "bytes_done": -1},
        {**good, "swapped": "no"},
    ):
        with pytest.raises(ValueError):
            restore.parse_restore_status(bad, vm_id="vm-1")
    assert restore.parse_restore_status({**good, "reason": "BAD REASON"}, vm_id="vm-1").reason == ""


def test_an_exhausted_activation_decided_late_still_reverts(
    fx: FakeEffects, pwr: _Power, monkeypatch
) -> None:
    """The failure is recorded while the KBS cannot be read (nothing is
    decided); once it can, the job reverts at once rather than waiting out
    the activation deadline."""
    monkeypatch.setattr(settings, "VALI_MIGRATION_DEST_ACTIVATE_MAX_ATTEMPTS", 1)
    vm = _golden_vm()
    job = _start(vm, _chain(vm)[-1])
    _staged(fx, job)
    job = _advance(job)
    job = _advance(job)
    job = _advance(job)
    assert job.state == MigrationState.DEST_ACTIVATING.value
    fx.kbs_evidence = effects.EffectUnavailable("kbs down")
    fx.dest_activation_status = "failed"
    job = _advance(job)
    job = _advance(job)
    assert job.state == MigrationState.DEST_ACTIVATING.value, "undecided"
    _original_grant(fx, job)
    job = _advance(job)
    assert job.state == MigrationState.RESTORE_REVERTING.value


def test_a_recovered_restore_keeps_its_original_until_the_window_ends(
    fx: FakeEffects, pwr: _Power
) -> None:
    vm = _golden_vm()
    job = _to_verifying(fx, pwr, _start(vm, _chain(vm)[-1]))
    Vm.objects.filter(pk=vm.pk).update(guest_signal_at=timezone.now() + timedelta(seconds=5))
    _age_phase(job)
    job = _advance(job)
    assert job.reason.startswith("failed-after-commit")
    # An operator recovers the VM on the destination; it is proven and alive.
    service._activate_dest_vm(job)
    _grant(fx, job)
    now = timezone.now()
    MigrationJob.objects.filter(pk=job.pk).update(finished_at=now - timedelta(hours=1))
    Vm.objects.filter(pk=vm.pk).update(guest_signal_at=now)
    service.reclaim_migrated_sources()
    assert not [o for o in fx.restore_orders if o[2]["op"] == "reclaim"], "window not over"
    MigrationJob.objects.filter(pk=job.pk).update(
        restore_keep_original_until=now - timedelta(seconds=1)
    )
    service.reclaim_migrated_sources()
    assert [o[0] for o in fx.restore_orders if o[2]["op"] == "reclaim"] == ["node-src"]


def test_the_backup_tick_starts_no_run_while_a_restore_is_in_flight(
    fx: FakeEffects, monkeypatch
) -> None:
    from apps.backup import service as backup_service

    monkeypatch.setattr(settings, "VALI_BACKUP_ENABLED", True)
    started: list[str] = []
    monkeypatch.setattr(
        backup_service, "_start_run", lambda policy, kind, now: started.append(kind) or True
    )
    monkeypatch.setattr(backup_service, "_probe_if_due", lambda policy, now: False)
    vm = _golden_vm()
    BackupPolicy.objects.filter(vm=vm).update(full_required=True)
    job = _start(vm, _chain(vm)[-1])
    report = backup_service.BackupTickReport()
    backup_service._maybe_start(BackupPolicy.objects.get(vm=vm), timezone.now(), report)
    assert started == []
    restore.cancel_restore(job=job, decided_by=make_service_client())
    backup_service._maybe_start(BackupPolicy.objects.get(vm=vm), timezone.now(), report)
    assert started == ["full"]


def test_a_vm_that_leaves_active_during_staging_fails_with_a_stage_reason(
    fx: FakeEffects,
) -> None:
    vm = _golden_vm()
    job = _start(vm, _chain(vm)[-1])
    Vm.objects.filter(pk=vm.pk).update(
        state=VmState.DECOMMISSIONING, migration_dest="", new_generation=None
    )
    job = _advance(job)
    assert job.state == MigrationState.FAILED.value
    assert job.reason.startswith("stage-vm-no-longer-active")


def test_a_failure_before_the_fence_landed_reverts_without_touching_the_kbs(
    fx: FakeEffects, pwr: _Power
) -> None:
    vm = _golden_vm()
    job = _restore_at_dest_activating(vm, kind="restore", evidence={})
    MigrationJob.objects.filter(pk=job.pk).update(prior_power_state="running")
    fx.kbs_evidence = None
    job = _advance(job)  # the guard trips: no source-down evidence
    assert job.state == MigrationState.RESTORE_REVERTING.value
    job = _advance(job)
    assert job.state == MigrationState.FAILED.value and job.reverted
    assert not fx.did("kbs_activate_dest")
    assert [p["op"] for _m, _o, p in fx.restore_orders] == ["abort"]
    vm.refresh_from_db()
    assert (vm.state, vm.generation) == (VmState.ACTIVE, 5)
    assert pwr.started == [], "the original never stopped in this case"


def test_no_kbs_evidence_at_all_never_reverts(fx: FakeEffects, pwr: _Power) -> None:
    """A KBS restart erases the bundles: absence cannot prove the restored
    guest did NOT release, so the original is kept and an operator looks."""
    vm = _golden_vm()
    job = _to_verifying(fx, pwr, _start(vm, _chain(vm)[-1]))
    fx.kbs_evidence = None
    _age_phase(job)
    job = _advance(job)
    assert job.state == MigrationState.FAILED.value
    assert job.reason == "blocked:commit-undecidable:verify-timeout"
    assert job.restore_keep_original_until is not None and not job.reverted
    assert not [p for _m, _o, p in fx.restore_orders if p["op"] == "abort"]


def test_a_revert_waits_for_the_destination_to_finish_its_abort(
    fx: FakeEffects, pwr: _Power, monkeypatch
) -> None:
    vm = _golden_vm()
    job = _to_verifying(fx, pwr, _start(vm, _chain(vm)[-1]))
    _original_grant(fx, job)
    _age_phase(job)
    job = _advance(job)
    assert job.state == MigrationState.RESTORE_REVERTING.value
    # The abort is accepted but the destination still reports the restore
    # swapped and its domain live.
    monkeypatch.setattr(fx, "restore_status", {})
    stuck = {
        "vm_id": vm.vm_id,
        "restore_id": job.restore_id,
        "op": "abort",
        "state": "staged",
        "bytes_done": 1,
        "bytes_total": 1,
        "reason": None,
        "swapped": True,
        "pre_restore_present": True,
        "domain_live": True,
    }
    monkeypatch.setattr(effects, "poll_restore_status", lambda **kw: dict(stuck))
    job = _advance(job)
    vm.refresh_from_db()
    assert vm.state == VmState.MIGRATING and pwr.started == [], "not relaunched yet"
    stuck.update(state="aborted", domain_live=False, swapped=False, pre_restore_present=False)
    job = _advance(job)
    vm.refresh_from_db()
    assert (vm.state, vm.generation) == (VmState.ACTIVE, 7)
    assert pwr.started == [(vm.vm_id, True)]


def test_an_abort_still_in_flight_is_not_done(fx: FakeEffects, monkeypatch) -> None:
    from apps.orchestration import order_dispatch

    MinerIdentity.objects.filter(miner_id="node-src").update(netbird_ip="100.64.0.9")
    answers = iter(
        [
            order_dispatch.DispatchResult(ok=False, status=409, classifier="order-in-flight"),
            order_dispatch.DispatchResult(ok=False, status=409, classifier="order-in-flight"),
            order_dispatch.DispatchResult(ok=False, status=507, classifier="insufficient-space"),
        ]
    )
    monkeypatch.setattr(order_dispatch, "dispatch_order", lambda **kw: next(answers))
    dispatch = fx.real["dispatch_restore"]
    dispatch(miner_id="node-src", order_id="o", payload={"op": "stage"})
    with pytest.raises(effects.EffectUnavailable):
        dispatch(miner_id="node-src", order_id="o", payload={"op": "abort"}, in_flight_ok=False)
    with pytest.raises(effects.RestoreRejected) as exc:
        dispatch(miner_id="node-src", order_id="o", payload={"op": "stage"})
    assert exc.value.classifier == "insufficient-space"


def test_a_replay_answers_the_same_job_even_with_the_flag_off(monkeypatch) -> None:
    vm = _golden_vm()
    run = _chain(vm)[-1]
    first = _start(vm, run, request_id="req-flag")
    monkeypatch.setattr(settings, "VALI_RESTORE_ENABLED", False)
    again, created = restore.start_restore(
        vm=vm, run_id=run.run_id, request_id="req-flag", decided_by=make_service_client()
    )
    assert not created and again.pk == first.pk


def test_a_disabled_policy_offers_no_current_boot_point() -> None:
    vm = _golden_vm()
    run = _chain(vm)[-1]
    BackupPolicy.objects.filter(vm=vm).update(enabled=False)
    with pytest.raises(restore.RestoreError) as exc:
        _start(vm, run)
    assert exc.value.code == "rollback-unsupported"


def test_a_chain_being_pruned_is_never_restored_from() -> None:
    vm = _golden_vm()
    run = _chain(vm)[-1]
    BackupChain.objects.filter(pk=run.chain_id).update(pruned_at=timezone.now())
    with pytest.raises(restore.RestoreError) as exc:
        _start(vm, run)
    assert exc.value.code == "point-not-restorable"
    assert not MigrationJob.objects.exists()


def test_prune_never_deletes_a_chain_a_restore_pinned(fx: FakeEffects, monkeypatch) -> None:
    """The pin is re-checked under the chain lock right before deleting."""
    from apps.backup import service as backup_service

    vm = _golden_vm()
    runs = _chain(vm)
    chain = runs[0].chain
    _start(vm, runs[-1])
    deleted: list[str] = []
    monkeypatch.setattr(
        backup_service.backup_s3_client(),
        "delete_object",
        lambda **kw: deleted.append(kw["key"]),
    )
    assert backup_service._prune_chain(chain, timezone.now()) is False
    assert deleted == []
    chain.refresh_from_db()
    assert chain.pruned_at is None and chain.state == ChainState.OPEN


def test_a_cancel_that_races_the_stop_still_restarts_the_vm(
    fx: FakeEffects, pwr: _Power, monkeypatch
) -> None:
    vm = _golden_vm()
    job = _start(vm, _chain(vm)[-1])
    _staged(fx, job)
    job = _advance(job)
    assert job.state == MigrationState.RESTORE_STOPPING.value
    real_stop = pwr._stop

    def _stop_after_a_cancel(vm_: Vm, *, by_migration: bool = False) -> Vm:
        restore.cancel_restore(job=job, decided_by=make_service_client())
        return real_stop(vm_, by_migration=by_migration)

    monkeypatch.setattr(power, "stop_vm", _stop_after_a_cancel)
    _advance(job)
    job.refresh_from_db()
    assert job.state == MigrationState.FAILED.value
    vm.refresh_from_db()
    assert vm.power_state == VmPowerState.STOPPED and vm.power_state_at > job.finished_at
    fx.domain_running = False
    restore.sweep_restore_cleanups()
    assert pwr.started == [(vm.vm_id, False)]


def test_a_verifying_tick_that_lost_to_a_revert_activates_nothing(
    fx: FakeEffects, pwr: _Power
) -> None:
    vm = _golden_vm()
    job = _to_verifying(fx, pwr, _start(vm, _chain(vm)[-1]))
    stale = MigrationJob.objects.select_related("vm").get(pk=job.pk)
    # Another tick decided to revert first.
    MigrationJob.objects.filter(pk=job.pk).update(
        state=MigrationState.RESTORE_REVERTING.value, version=job.version + 1
    )
    _grant(fx, job)
    assert restore.h_verifying(stale) is None
    vm.refresh_from_db()
    assert vm.state == VmState.MIGRATING


def test_a_revert_whose_evidence_vanished_after_the_fence_is_blocked(
    fx: FakeEffects, pwr: _Power
) -> None:
    vm = _golden_vm()
    job = _to_verifying(fx, pwr, _start(vm, _chain(vm)[-1]))
    _original_grant(fx, job)
    _age_phase(job)
    job = _advance(job)
    assert job.state == MigrationState.RESTORE_REVERTING.value
    fx.kbs_evidence = None  # a KBS restart erased the bundles meanwhile
    job = _advance(job)
    assert job.state == MigrationState.FAILED.value
    assert job.reason.startswith("revert-failed:blocked:commit-undecidable")
    assert pwr.started == [] and not [p for _m, _o, p in fx.restore_orders if p["op"] == "abort"]


def test_a_new_gen_grant_somewhere_else_is_undecidable(fx: FakeEffects, pwr: _Power) -> None:
    vm = _golden_vm()
    job = _to_verifying(fx, pwr, _start(vm, _chain(vm)[-1]))
    ticket = "tk-elsewhere"
    OrderTicketIntake.objects.create(
        ticket_id=ticket,
        vm_id=vm.vm_id,
        tenant_id="t",
        user_id="u",
        lease_id="l",
        vm_generation=job.new_gen,
        issue_time=0,
        expiry=0,
        node_id="node-dst",
        platform_id=DST_CHIP,
        resource_class="small",
        kid_hex="00",
        cose_blob=b"",
        received_from="x",
    )
    fx.kbs_evidence = {"ticket_id": ticket, "granted_at_unix": int(timezone.now().timestamp())}
    assert restore.commit_state(job)[0] == restore.UNDECIDABLE


def test_the_intake_rechecks_the_chain_under_its_lock(monkeypatch) -> None:
    from apps.backup import service as backup_service

    vm = _golden_vm()
    run = _chain(vm)[-1]
    point = backup_service.classify_run(vm, run)
    assert point.restorable
    BackupChain.objects.filter(pk=run.chain_id).update(pruned_at=timezone.now())
    # Classified before the prune marked the chain (the race): the lock
    # re-check still refuses it.
    monkeypatch.setattr(backup_service, "classify_run", lambda vm_, run_: point)
    with pytest.raises(restore.RestoreError) as exc:
        _start(vm, run)
    assert exc.value.code == "point-not-restorable"


def test_a_chain_being_pruned_holds_no_point() -> None:
    from apps.backup import service as backup_service

    vm = _golden_vm()
    run = _chain(vm)[-1]
    BackupChain.objects.filter(pk=run.chain_id).update(pruned_at=timezone.now())
    run.refresh_from_db()
    assert backup_service.classify_run(vm, run).klass == backup_service.PointClass.UNAVAILABLE


def test_a_restored_vm_that_never_proves_it_runs_reads_failed(
    fx: FakeEffects, pwr: _Power, monkeypatch
) -> None:
    vm = _golden_vm()
    job = _done(fx, pwr, vm)
    MigrationJob.objects.filter(pk=job.pk).update(
        finished_at=timezone.now() - timedelta(hours=7)
    )
    service.reclaim_migrated_sources()  # the proof window is over: skipped
    job.refresh_from_db()
    assert job.source_reclaim_state == SourceReclaimState.SKIPPED.value
    view = restore.serialize(job)
    assert view["phase"] == "failed" and view["reason"].startswith("failed-after-commit:")
    assert not [o for o in fx.restore_orders if o[2]["op"] == "reclaim"], "original kept"


def test_a_backup_run_in_flight_at_the_cutover_is_abandoned(
    fx: FakeEffects, pwr: _Power
) -> None:
    vm = _golden_vm()
    job = _to_verifying(fx, pwr, _start(vm, _chain(vm)[-1]))
    chain = BackupChain.objects.filter(vm=vm).first()
    run = BackupRun.objects.create(
        vm=vm,
        chain=chain,
        seq=99,
        kind=BackupKind.INCREMENTAL,
        status=RunStatus.RUNNING,
        miner_id="node-src",
        disk_key="k",
        state_key="s",
        manifest_key="m",
        part_size=512 * MIB,
        part_count=1,
    )
    _grant(fx, job)
    job = _advance(job)
    assert job.state == MigrationState.DONE.value
    run.refresh_from_db()
    assert run.status == RunStatus.FAILED and run.reason == "vm-restored"
    assert BackupPolicy.objects.get(vm=vm).full_required


def test_a_stop_that_lands_after_the_cleanup_reopens_it(
    fx: FakeEffects, pwr: _Power, monkeypatch
) -> None:
    vm = _golden_vm()
    job = _start(vm, _chain(vm)[-1])
    _staged(fx, job)
    job = _advance(job)
    stale = MigrationJob.objects.select_related("vm").get(pk=job.pk)
    real_stop = pwr._stop

    def _cancel_and_clean_then_stop(vm_: Vm, *, by_migration: bool = False) -> Vm:
        restore.cancel_restore(job=job, decided_by=make_service_client())
        restore.sweep_restore_cleanups()  # the VM is still running: nothing to do
        assert not MigrationJob.objects.get(pk=job.pk).restore_cleanup_pending
        return real_stop(vm_, by_migration=by_migration)

    monkeypatch.setattr(power, "stop_vm", _cancel_and_clean_then_stop)
    restore.h_stopping(stale)
    job.refresh_from_db()
    assert job.restore_cleanup_pending, "reopened by the stop that landed late"
    fx.domain_running = False
    restore.sweep_restore_cleanups()
    assert pwr.started == [(vm.vm_id, False)]


def test_a_stopping_tick_that_lost_to_a_cancel_stops_nothing(
    fx: FakeEffects, pwr: _Power
) -> None:
    vm = _golden_vm()
    job = _start(vm, _chain(vm)[-1])
    _staged(fx, job)
    job = _advance(job)
    stale = MigrationJob.objects.select_related("vm").get(pk=job.pk)
    restore.cancel_restore(job=job, decided_by=make_service_client())
    assert restore.h_stopping(stale) is None
    assert pwr.stopped == []
