"""Operator-only manual failover off a dead miner (`restore.start_failover`)."""

from __future__ import annotations

from datetime import timedelta
from typing import Any

import pytest
from django.conf import settings
from django.core.management import call_command
from django.utils import timezone

from apps.lifecycle.models import Vm, VmState
from apps.miners.models import MinerIdentity
from apps.orchestration import effects, restore, service
from apps.orchestration.models import (
    DestAuthorization,
    FailoverQuarantine,
    MigrationJob,
    MigrationKind,
    MigrationState,
    SourceReclaimState,
)
from apps.scheduler import service as sched

from .conftest import FakeEffects
from .factories import make_service_client, make_vm
from .test_restore import (  # noqa: F401 — autouse fixture
    _age_phase,
    _chain,
    _golden_vm,
    _grant,
    _original_grant,
    _Power,
    _restore_env,
)

pytestmark = pytest.mark.django_db

_REAL_VALIDATE = restore._validate_other_dest


class _World:
    """The dead-miner signals, as the test sets them."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self.peers: list[dict[str, Any]] | Exception = []
        self.edge: dict[str, str] = {}
        self.stops: list[tuple[str, str]] = []
        self.reclaims: list[tuple[str, str]] = []
        monkeypatch.setattr(effects, "list_netbird_peers", self._peers)
        monkeypatch.setattr(
            effects, "probe_edge_session", lambda vm, node: self.edge.get(node, "reachable")
        )
        monkeypatch.setattr(
            effects,
            "dispatch_force_stop_on",
            lambda vm, *, node_id, order_id: self.stops.append((vm.vm_id, node_id)),
        )
        monkeypatch.setattr(
            effects,
            "dispatch_source_reclaim",
            lambda vm, *, source_node_id, job_id: self.reclaims.append((vm.vm_id, source_node_id)),
        )

    def _peers(self) -> list[dict[str, Any]]:
        if isinstance(self.peers, Exception):
            raise self.peers
        return self.peers

    def kill(self, miner_id: str = "node-src") -> None:
        MinerIdentity.objects.filter(miner_id=miner_id).update(
            last_seen_at=timezone.now() - timedelta(hours=1), netbird_ip="100.64.0.1"
        )
        self.peers = [
            {
                "id": "p1",
                "ip": "100.64.0.1",
                "connected": False,
                "last_seen": (timezone.now() - timedelta(hours=1)).isoformat(),
            }
        ]
        self.edge[miner_id] = "unreachable"


@pytest.fixture
def pwr(monkeypatch: pytest.MonkeyPatch) -> _Power:
    return _Power(monkeypatch)


@pytest.fixture
def world(monkeypatch: pytest.MonkeyPatch) -> _World:
    return _World(monkeypatch)


@pytest.fixture(autouse=True)
def _failover_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "VALI_FAILOVER_MANUAL_ENABLED", True)
    # Every other miner is a fine destination unless a test says otherwise.
    monkeypatch.setattr(restore, "_validate_other_dest", lambda vm, dest, source=None: None)


def _failover(vm: Vm, **kw: Any) -> MigrationJob:
    job, created = restore.start_failover(
        vm=vm,
        request_id=kw.pop("request_id", "fo-1"),
        decided_by=make_service_client(),
        dest_node_id=kw.pop("dest_node_id", "node-dst"),
        **kw,
    )
    assert created
    return job


def _advance(job: MigrationJob) -> MigrationJob:
    job = MigrationJob.objects.select_related("vm").get(pk=job.pk)
    service.advance_migration_job(job)
    job.refresh_from_db()
    return job


def _verifying(fx: FakeEffects, world: _World, job: MigrationJob) -> MigrationJob:
    fx.kbs_evidence = None
    job = _advance(job)
    assert job.state == MigrationState.RESTORE_VERIFYING.value, job.reason
    return job


# ── the evidence ─────────────────────────────────────────────────────


def test_a_dead_miner_needs_all_three_signals(world: _World) -> None:
    vm = _golden_vm()
    world.kill()
    assert restore.dead_evidence(vm, "node-src")["dead"] is True

    MinerIdentity.objects.filter(miner_id="node-src").update(last_seen_at=timezone.now())
    ev = restore.dead_evidence(vm, "node-src")
    assert ev["dead"] is False and ev["heartbeat_stale"] is False

    world.kill()
    world.peers[0]["connected"] = True
    assert restore.dead_evidence(vm, "node-src")["dead"] is False

    world.kill()
    world.peers[0]["last_seen"] = timezone.now().isoformat()  # just dropped
    assert restore.dead_evidence(vm, "node-src")["dead"] is False

    world.kill()
    world.peers[0]["last_seen"] = None  # disconnected, last seen unreadable
    assert restore.dead_evidence(vm, "node-src")["dead"] is False

    world.kill()
    for edge in ("reachable", "unknown"):
        world.edge["node-src"] = edge
        assert restore.dead_evidence(vm, "node-src")["dead"] is False

    world.kill()
    world.peers = effects.EffectUnavailable("netbird down")
    ev = restore.dead_evidence(vm, "node-src")
    assert ev["dead"] is False and ev["netbird"] == "unknown"

    world.kill()
    world.peers = []  # the peer record is gone
    assert restore.dead_evidence(vm, "node-src")["dead"] is True


# ── intake ───────────────────────────────────────────────────────────


def test_the_flag_off_refuses_a_failover(monkeypatch, world: _World) -> None:
    monkeypatch.setattr(settings, "VALI_FAILOVER_MANUAL_ENABLED", False)
    vm = _golden_vm()
    _chain(vm)
    world.kill()
    with pytest.raises(restore.RestoreError) as exc:
        _failover(vm)
    assert exc.value.code == "failover-disabled"


def test_a_live_miner_is_refused_with_the_evidence(world: _World) -> None:
    vm = _golden_vm()
    _chain(vm)
    with pytest.raises(restore.MinerNotDead) as exc:
        _failover(vm)
    assert exc.value.code == "miner-not-dead"
    assert exc.value.evidence["dead"] is False and "heartbeat_stale" in exc.value.evidence
    assert not MigrationJob.objects.exists()


def test_a_failover_enters_dest_activating_with_the_dead_evidence(world: _World) -> None:
    vm = _golden_vm()
    runs = _chain(vm)
    world.kill()
    job = _failover(vm)
    assert job.kind == MigrationKind.FAILOVER.value
    assert job.state == MigrationState.DEST_ACTIVATING.value
    assert (job.source_node_id, job.dest_node_id) == ("node-src", "node-dst")
    assert job.restore_run_id == runs[-1].pk, "the newest current-boot point"
    auth = job.authorization
    assert auth.kind == MigrationKind.FAILOVER.value and auth.evidence["dead"] is True
    assert service._migration_guard(job) is None


def test_a_failover_refuses_the_dead_miner_as_its_destination(world: _World) -> None:
    vm = _golden_vm()
    _chain(vm)
    world.kill()
    with pytest.raises(restore.RestoreError) as exc:
        _failover(vm, dest_node_id="node-src")
    assert exc.value.code == "no-eligible-miner"


def test_a_failover_without_a_current_boot_point_is_refused(world: _World) -> None:
    vm = _golden_vm(counter=4)
    _chain(vm, counter=3)
    world.kill()
    with pytest.raises(restore.RestoreError) as exc:
        _failover(vm)
    assert exc.value.code == "point-not-restorable"


def test_a_failover_to_a_named_earlier_boot_point_is_rollback_unsupported(
    world: _World,
) -> None:
    vm = _golden_vm(counter=4)  # the guest rebooted since this chain closed
    run = _chain(vm, counter=3)[-1]
    world.kill()
    with pytest.raises(restore.RestoreError) as exc:
        _failover(vm, run_id=run.run_id)
    assert exc.value.code == "rollback-unsupported"


def test_a_restore_request_id_reused_at_failover_is_a_conflict(world: _World) -> None:
    vm = _golden_vm()
    run = _chain(vm)[-1]
    restore.start_restore(
        vm=vm,
        run_id=run.run_id,
        request_id="shared-id",
        decided_by=make_service_client(),
    )
    world.kill()
    with pytest.raises(restore.RestoreError) as exc:
        _failover(vm, request_id="shared-id")
    assert exc.value.code == "request-id-conflict"


def test_a_failover_request_id_is_idempotent(world: _World) -> None:
    vm = _golden_vm()
    _chain(vm)
    world.kill()
    first = _failover(vm, request_id="fo-idem")
    job, created = restore.start_failover(
        vm=vm,
        request_id="fo-idem",
        decided_by=make_service_client(),
        dest_node_id="node-dst",
    )
    assert not created and job.pk == first.pk
    assert MigrationJob.objects.count() == 1


def test_the_destination_is_picked_by_generation_region_and_room(
    world: _World, monkeypatch
) -> None:
    monkeypatch.setattr(restore, "_validate_other_dest", _REAL_VALIDATE)
    vm = _golden_vm()
    MinerIdentity.objects.create(miner_id="node-far", pubkey_hex="cc" * 32, platform_id="33" * 64)
    MinerIdentity.objects.create(miner_id="node-turin", pubkey_hex="dd" * 32, platform_id="44" * 8)
    for m, cid in (("node-dst", "d" * 64), ("node-far", "f" * 64), ("node-turin", "e" * 64)):
        MinerIdentity.objects.filter(miner_id=m).update(chain_node_id=cid)
    monkeypatch.setattr(sched, "dispatchability", lambda m, **kw: sched.Dispatchability(True, None))
    monkeypatch.setattr(sched, "launch_region_for_vm", lambda vm_id: "FR")
    monkeypatch.setattr(
        sched, "region_by_node", lambda **kw: {"d" * 64: "FR", "f" * 64: "AU", "e" * 64: "FR"}
    )
    monkeypatch.setattr(
        sched,
        "host_resources_by_node",
        lambda: {
            c: sched.HostResources(64 * 1024, 8, 10**6, 64) for c in ("d" * 64, "f" * 64, "e" * 64)
        },
    )
    assert restore._pick_failover_dest(vm, "node-src") == "node-dst"
    monkeypatch.setattr(sched, "region_by_node", lambda **kw: {"f" * 64: "AU", "e" * 64: "FR"})
    with pytest.raises(restore.RestoreError) as exc:
        restore._pick_failover_dest(vm, "node-src")
    assert exc.value.code == "no-eligible-miner"


def test_a_destination_without_disk_room_is_refused(world: _World, monkeypatch) -> None:
    """The restore / failover destination runs the scheduler's disk gate:
    under `enforce` a refusal reason there makes the host ineligible."""
    monkeypatch.setattr(restore, "_validate_other_dest", _REAL_VALIDATE)
    vm = _golden_vm()
    MinerIdentity.objects.filter(miner_id="node-dst").update(chain_node_id="d" * 64)
    monkeypatch.setattr(sched, "dispatchability", lambda m, **kw: sched.Dispatchability(True, None))
    monkeypatch.setattr(
        sched,
        "host_resources_by_node",
        lambda: {"d" * 64: sched.HostResources(64 * 1024, 8, 10**6, 64)},
    )
    asked: list[tuple[str, str]] = []

    def _gate(nid: str, rc: str, *, context: str, data_disk_gb: int | None = None) -> str:
        asked.append((nid, context))
        return "disk free 10 < 50 GiB"

    monkeypatch.setattr(sched, "disk_gate_refusal", _gate)
    with pytest.raises(restore.RestoreError, match="data disk"):
        restore._validate_other_dest(vm, "node-dst", source="node-src")
    assert asked == [("d" * 64, "restore-dest")]
    monkeypatch.setattr(sched, "disk_gate_refusal", lambda *a, **k: "")
    restore._validate_other_dest(vm, "node-dst", source="node-src")


# ── the fence and the activation ─────────────────────────────────────


def test_a_miner_that_came_back_before_the_fence_is_left_alone(
    fx: FakeEffects, world: _World, pwr: _Power
) -> None:
    vm = _golden_vm()
    _chain(vm)
    world.kill()
    job = _failover(vm)
    world.edge["node-src"] = "reachable"  # it came back
    fx.kbs_evidence = None
    job = _advance(job)
    assert job.state == MigrationState.RESTORE_REVERTING.value
    assert job.reason == "miner-not-dead-at-fence"
    job = _advance(job)
    assert job.state == MigrationState.FAILED.value and job.reverted
    assert not fx.did("kbs_activate_dest") and not FailoverQuarantine.objects.exists()
    vm.refresh_from_db()
    assert (vm.state, vm.host, vm.generation) == (VmState.ACTIVE, "node-src", 5)


def test_a_racing_decommission_blocks_the_fence_instead_of_being_bypassed(
    fx: FakeEffects, world: _World
) -> None:
    # A `DecommissionJob` won `Active -> Decommissioning` for this VM in
    # between `start_failover`'s intake and this job's first tick (both
    # `_has_active_job` checks can race — see `service.py`'s own docstring
    # on that). The failover must fail closed, never quarantine the source
    # or touch the KBS on the strength of a state it never re-verified.
    vm = _golden_vm()
    _chain(vm)
    world.kill()
    job = _failover(vm)
    Vm.objects.filter(pk=vm.pk).update(state=VmState.DECOMMISSIONING.value)
    job = _advance(job)
    assert job.state == MigrationState.DEST_ACTIVATING.value, job.reason
    assert not fx.did("kbs_activate_dest")
    assert not FailoverQuarantine.objects.exists()
    vm.refresh_from_db()
    assert vm.state == VmState.DECOMMISSIONING


def test_the_fence_quarantines_the_source_and_the_destination_restores_the_chain(
    fx: FakeEffects, world: _World
) -> None:
    vm = _golden_vm()
    runs = _chain(vm)
    world.kill()
    job = _verifying(fx, world, _failover(vm))
    vm.refresh_from_db()
    assert vm.state == VmState.MIGRATING and vm.migration_dest == "node-dst"
    assert ("kbs_activate_dest", vm.vm_id, "node-dst", 6) in fx.calls
    chain = fx.activate_restore["backup_chain"]
    assert chain["restore_id"] == job.restore_id and len(chain["incrementals"]) == len(runs) - 1
    assert fx.activate_restore["get_url"] == chain["full"]["url"]
    assert fx.activate_restore["staged_restore_id"] == ""
    [q] = FailoverQuarantine.objects.all()
    assert q.miner_id == "node-src" and q.cleared_at is None
    node = MinerIdentity.objects.get(miner_id="node-src")
    assert sched.dispatchability(node).reason == sched.REASON_FAILOVER_QUARANTINED
    assert "node-src" in sched.failover_quarantined_miner_ids()

    _grant(fx, job)
    job = _advance(job)
    vm.refresh_from_db()
    assert (job.state, vm.host, vm.generation) == (MigrationState.DONE.value, "node-dst", 6)


def test_a_failover_activation_gets_time_for_the_download(world: _World) -> None:
    vm = _golden_vm()
    _chain(vm)
    world.kill()
    job = _failover(vm)
    MigrationJob.objects.filter(pk=job.pk).update(restore_eta_s=3 * 3600)
    job.refresh_from_db()
    assert restore.job_timeout_s(job) == 9 * 3600 + 600
    assert service._activate_settle_by_unix(job) > job.phase_started_at.timestamp() + 9 * 3600


def test_a_failover_revert_does_not_relaunch_on_the_dead_miner(
    fx: FakeEffects, world: _World, pwr: _Power
) -> None:
    vm = _golden_vm()
    _chain(vm)
    world.kill()
    job = _verifying(fx, world, _failover(vm))
    _original_grant(fx, job)
    _age_phase(job)
    job = _advance(job)
    assert job.state == MigrationState.RESTORE_REVERTING.value
    job = _advance(job)
    assert job.state == MigrationState.FAILED.value and job.reverted
    assert pwr.started == []
    vm.refresh_from_db()
    assert (vm.state, vm.host, vm.generation) == (VmState.ACTIVE, "node-src", 7)


def test_a_failover_job_needs_dead_evidence_of_its_own(world: _World) -> None:
    vm = _golden_vm()
    _chain(vm)
    world.kill()
    job = _failover(vm)
    DestAuthorization.objects.filter(pk=job.authorization_id).update(evidence={"dead": False})
    job.refresh_from_db()
    assert service._migration_guard(job) == "failover-without-dead-evidence"
    DestAuthorization.objects.filter(pk=job.authorization_id).update(
        kind=MigrationKind.RESTORE.value, evidence={"source_domain_down": True}
    )
    job.refresh_from_db()
    assert service._migration_guard(job).startswith("authorization-kind-mismatch")


# ── after: reclaim and reappearance ──────────────────────────────────


def _done(fx: FakeEffects, world: _World) -> tuple[Vm, MigrationJob]:
    vm = _golden_vm()
    _chain(vm)
    world.kill()
    job = _verifying(fx, world, _failover(vm))
    _grant(fx, job)
    job = _advance(job)
    assert job.state == MigrationState.DONE.value
    now = timezone.now()
    MigrationJob.objects.filter(pk=job.pk).update(finished_at=now - timedelta(days=2))
    Vm.objects.filter(pk=vm.pk).update(guest_signal_at=now)
    return vm, job


def test_the_dead_source_is_reclaimed_only_once_it_reappears(
    fx: FakeEffects, world: _World
) -> None:
    vm, job = _done(fx, world)
    service.reclaim_migrated_sources()
    job.refresh_from_db()
    assert world.reclaims == []
    assert job.source_reclaim_state == SourceReclaimState.PENDING.value, "never given up"
    MinerIdentity.objects.filter(miner_id="node-src").update(last_seen_at=timezone.now())
    service.reclaim_migrated_sources()
    assert world.reclaims == [(vm.vm_id, "node-src")]


def test_a_reappearing_miner_has_its_stale_domain_stopped(
    fx: FakeEffects, world: _World, monkeypatch
) -> None:
    vm, job = _done(fx, world)
    running: dict[str, bool | None] = {"node-src": True}
    monkeypatch.setattr(effects, "poll_domain_running_on", lambda vm_, node: running.get(node))
    assert restore.reconcile_failover_quarantines() == 0, "not back yet"
    MinerIdentity.objects.filter(miner_id="node-src").update(last_seen_at=timezone.now())
    assert restore.reconcile_failover_quarantines() == 1
    assert world.stops == [(vm.vm_id, "node-src")]
    running["node-src"] = False
    assert restore.reconcile_failover_quarantines() == 0


def test_a_vm_back_on_its_miner_is_never_stopped_there(
    fx: FakeEffects, world: _World, pwr: _Power, monkeypatch
) -> None:
    vm = _golden_vm()
    _chain(vm)
    world.kill()
    job = _verifying(fx, world, _failover(vm))
    _original_grant(fx, job)
    _age_phase(job)
    _advance(job)
    _advance(job)  # reverted: the vm is back on node-src
    monkeypatch.setattr(effects, "poll_domain_running_on", lambda vm_, node: True)
    MinerIdentity.objects.filter(miner_id="node-src").update(last_seen_at=timezone.now())
    assert restore.reconcile_failover_quarantines() == 0 and world.stops == []


def test_a_failed_after_commit_failover_still_gets_its_stale_domain_stopped(
    fx: FakeEffects, world: _World, monkeypatch
) -> None:
    # A post-commit failure never reverts (the restored guest already
    # unlocked at new_gen): `vm.host` stays whatever it was — the source —
    # because only a REVERT (`h_reverting`) or a successful commit
    # (`h_verifying`'s `_activate_dest_vm`) ever moves it. The old
    # `vm.host == q.miner_id` skip in the reconciliation treated this
    # exactly like a legitimate revert; it must not.
    vm = _golden_vm()
    _chain(vm)
    world.kill()
    job = _verifying(fx, world, _failover(vm))
    Vm.objects.filter(pk=vm.pk).update(guest_signal_at=timezone.now() + timedelta(seconds=5))
    _age_phase(job)
    job = _advance(job)
    assert job.state == MigrationState.FAILED.value
    assert job.reason.startswith("failed-after-commit") and not job.reverted
    vm.refresh_from_db()
    assert vm.host == "node-src"

    monkeypatch.setattr(effects, "poll_domain_running_on", lambda vm_, node: True)
    MinerIdentity.objects.filter(miner_id="node-src").update(last_seen_at=timezone.now())
    assert restore.reconcile_failover_quarantines() == 1
    assert world.stops == [(vm.vm_id, "node-src")]


def test_reconciliation_is_not_starved_by_older_still_dead_quarantines(
    world: _World, monkeypatch
) -> None:
    from apps.orchestration.tests.factories import make_migration_job

    now = timezone.now()

    old_vm = make_vm(vm_id="vm-old", host="node-old")
    MinerIdentity.objects.get_or_create(
        miner_id="node-old", defaults={"pubkey_hex": "55" * 32, "platform_id": "55" * 64}
    )
    old_job = make_migration_job(old_vm, dest_node_id="node-dst")
    MigrationJob.objects.filter(pk=old_job.pk).update(
        kind=MigrationKind.FAILOVER.value, source_node_id="node-old"
    )
    old_q = FailoverQuarantine.objects.create(job=old_job, miner_id="node-old")
    FailoverQuarantine.objects.filter(pk=old_q.pk).update(created_at=now - timedelta(hours=2))
    # node-old never reappears (`last_seen_at` stays NULL) — this quarantine
    # is open forever, exactly the case that used to occupy every sweep.

    new_vm = make_vm(vm_id="vm-new", host="node-new")
    MinerIdentity.objects.get_or_create(
        miner_id="node-new",
        defaults={"pubkey_hex": "66" * 32, "platform_id": "66" * 64, "last_seen_at": now},
    )
    new_job = make_migration_job(new_vm, dest_node_id="node-dst")
    MigrationJob.objects.filter(pk=new_job.pk).update(
        kind=MigrationKind.FAILOVER.value, source_node_id="node-new"
    )
    new_q = FailoverQuarantine.objects.create(job=new_job, miner_id="node-new")
    FailoverQuarantine.objects.filter(pk=new_q.pk).update(created_at=now - timedelta(minutes=30))

    monkeypatch.setattr(effects, "poll_domain_running_on", lambda vm_, node: node == "node-new")

    # `old_q` is strictly older, so an unfiltered `order_by("created_at")`
    # limited to 1 row would return ONLY it, forever — `new_q`, which has
    # actually reappeared, would never be reached.
    assert restore.reconcile_failover_quarantines(limit=1) == 1
    assert world.stops == [("vm-new", "node-new")]


def test_an_operator_clears_the_quarantine(fx: FakeEffects, world: _World, capsys) -> None:
    _done(fx, world)
    call_command("vali_failover_quarantine")
    assert "node-src" in capsys.readouterr().out
    call_command("vali_failover_quarantine", "--clear", "node-src", "--by", "op")
    assert FailoverQuarantine.objects.get().cleared_by == "op"
    assert "node-src" not in sched.failover_quarantined_miner_ids()


# ── the route ────────────────────────────────────────────────────────


def test_the_failover_route(root_client, authed_client, world: _World) -> None:
    vm = _golden_vm()
    _chain(vm)
    body = {"request_id": "fo-r", "dest_node_id": "node-dst"}
    denied = authed_client.post(f"/v1/vm/{vm.vm_id}/failover", body, format="json")
    assert denied.status_code == 403
    resp = root_client.post(f"/v1/vm/{vm.vm_id}/failover", body, format="json")
    assert resp.status_code == 409 and resp.json()["error"] == "miner-not-dead"
    assert resp.json()["evidence"]["dead"] is False
    world.kill()
    resp = root_client.post(f"/v1/vm/{vm.vm_id}/failover", body, format="json")
    assert resp.status_code == 202 and resp.json()["kind"] == "failover"
    assert resp.json()["phase"] == "activating"
    latest = root_client.get(f"/v1/vm/{vm.vm_id}/restore").json()
    assert latest["job_id"] == resp.json()["job_id"]
    bad = root_client.post(f"/v1/vm/{vm.vm_id}/failover", {"x": 1}, format="json")
    assert bad.status_code == 400


# ── the effect's own guards (the `world` fixture fakes these away above,
#    so their real bodies are exercised only here) ─────────────────────


def test_dispatch_force_stop_on_refuses_the_vms_current_host() -> None:
    vm = make_vm(host="node-src")
    with pytest.raises(effects.EffectError, match="current host"):
        effects.dispatch_force_stop_on(vm, node_id="node-src", order_id="o1")


def test_dispatch_force_stop_on_refuses_an_empty_node() -> None:
    vm = make_vm(host="node-src")
    with pytest.raises(effects.EffectError, match="current host"):
        effects.dispatch_force_stop_on(vm, node_id="", order_id="o1")


def test_dispatch_force_stop_on_targets_the_named_miner(monkeypatch) -> None:
    from apps.orchestration import order_dispatch

    seen: dict[str, object] = {}

    class _Result:
        ok = True
        status = 200
        classifier = "stopped"

    def _fake(**kwargs: Any) -> _Result:
        seen.update(kwargs)
        return _Result()

    monkeypatch.setattr(order_dispatch, "dispatch_order_settled", _fake)
    MinerIdentity.objects.filter(miner_id="node-src").update(netbird_ip="100.0.0.1")
    vm = make_vm(host="node-dst")

    effects.dispatch_force_stop_on(vm, node_id="node-src", order_id="fo-stop-1")

    assert seen["miner_id"] == "node-src"
    assert seen["netbird_ip"] == "100.0.0.1"
    assert seen["kind"] == "stop"
    assert seen["order_id"] == "fo-stop-1"


def test_dispatch_force_stop_on_raises_when_the_miner_rejects(monkeypatch) -> None:
    from apps.orchestration import order_dispatch

    class _Rejected:
        ok = False
        status = 409
        classifier = "domain-gone"

    monkeypatch.setattr(order_dispatch, "dispatch_order_settled", lambda **kw: _Rejected())
    MinerIdentity.objects.filter(miner_id="node-src").update(netbird_ip="100.0.0.1")
    vm = make_vm(host="node-dst")

    with pytest.raises(effects.EffectError, match="domain-gone"):
        effects.dispatch_force_stop_on(vm, node_id="node-src", order_id="fo-stop-1")


def test_probe_edge_session_reads_edge_no_session_statuses(monkeypatch) -> None:
    monkeypatch.setattr(settings, "VALI_EDGE_GATEWAY_URL", "https://edge.example")
    MinerIdentity.objects.filter(miner_id="node-src").update(netbird_ip="100.0.0.1")
    vm = make_vm(host="node-dst")

    for status_code in (502, 504):
        monkeypatch.setattr(
            effects, "_http", lambda *a, _s=status_code, **kw: (_s, b"")
        )
        assert effects.probe_edge_session(vm, "node-src") == "unreachable"

    for status_code in (200, 404, 503):
        monkeypatch.setattr(
            effects, "_http", lambda *a, _s=status_code, **kw: (_s, b"")
        )
        assert effects.probe_edge_session(vm, "node-src") == "reachable"


def test_probe_edge_session_is_unknown_when_it_cannot_tell(monkeypatch) -> None:
    vm = make_vm(host="node-dst")
    # No MinerIdentity for "node-ghost": `_miner_identity` raises `EffectError`.
    assert effects.probe_edge_session(vm, "node-ghost") == "unknown"
