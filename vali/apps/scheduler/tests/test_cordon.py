"""Gate (h) — the operator cordon — and gate (g)'s per-miner boot cap.

A cordon closes a miner to NEW work (launch, feasibility, resize, migration
and failover destinations) and does nothing else: unlike `QUARANTINED` it
leaves the miner's status, telemetry source, dispatchability and the VMs
already there alone, and enrols no drain. Both controls are written only
through `capacity_admin` (audited) by `vali_set_miner_capacity`.
"""

from __future__ import annotations

from io import StringIO

import pytest
from django.core.management import CommandError, call_command
from django.urls import reverse
from django.utils import timezone
from rest_framework import status
from rest_framework.test import APIClient

from apps.miners.models import MinerStatus
from apps.orchestration import service as orchestration_service
from apps.orchestration.models import MigrationJob
from apps.scheduler import chain, service
from apps.scheduler.models import MinerCapacity, MinerCapacityAudit, Placement, PlacementStatus
from apps.scheduler.placement import MINERS_BOOTING, PlacementError, decide_placement
from apps.telemetry.models import SourceType, TelemetrySource

from .factories import (
    make_dispatchable_identity,
    make_miner,
    make_placement,
    make_snapshot,
    make_vm,
    node_id,
)


def _decide(snapshot, **kw):
    return decide_placement(
        snapshot=snapshot,
        capacity_by_node={m.node_id: 8 for m in snapshot.miners},
        load_by_node={},
        family_load_by_node={},
        max_epoch_lag=2,
        **kw,
    )


# ─── the pure gates ──────────────────────────────────────────────────


def test_a_cordoned_miner_is_never_chosen() -> None:
    snap = make_snapshot(10, [make_miner(1), make_miner(2)])
    assert _decide(snap) == node_id(1)
    assert _decide(snap, cordoned={node_id(1): "maintenance"}) == node_id(2)


def test_an_all_cordoned_fleet_is_no_eligible_miner_and_says_why() -> None:
    """Not `miners-booting`: a cordon is an operator decision, nothing to
    wait out."""
    snap = make_snapshot(10, [make_miner(1)])
    with pytest.raises(PlacementError) as exc:
        _decide(snap, cordoned={node_id(1): ""})
    assert exc.value.category == "no-eligible-miner"
    assert "1 candidate(s) cordoned by the operator" in exc.value.message


def test_the_cordon_matches_any_spelling_of_the_node_id() -> None:
    snap = make_snapshot(10, [make_miner(1), make_miner(2)])
    assert _decide(snap, cordoned={node_id(1).lower(): "x"}) == node_id(2)


def test_a_per_miner_boot_cap_overrides_the_fleet_value() -> None:
    snap = make_snapshot(10, [make_miner(1), make_miner(2)])
    booting = {node_id(1): 1}
    # Fleet cap 3: node 1 (one boot) still wins the tie-break...
    assert _decide(snap, booting_by_node=booting, max_booting_per_node=3) == node_id(1)
    # ...its own cap of 1 skips it.
    assert _decide(
        snap,
        booting_by_node=booting,
        max_booting_per_node=3,
        max_booting_by_node={node_id(1): 1},
    ) == node_id(2)
    # An override applies even with the fleet gate off.
    assert _decide(
        snap,
        booting_by_node=booting,
        max_booting_per_node=0,
        max_booting_by_node={node_id(1): 1},
    ) == node_id(2)
    # And a higher override lifts the fleet cap for that miner.
    with pytest.raises(PlacementError) as exc:
        _decide(snap, booting_by_node={node_id(1): 3, node_id(2): 3}, max_booting_per_node=3)
    assert exc.value.category == MINERS_BOOTING
    assert _decide(
        snap,
        booting_by_node={node_id(1): 3, node_id(2): 3},
        max_booting_per_node=3,
        max_booting_by_node={node_id(2): 5},
    ) == node_id(2)


# ─── the service inputs ──────────────────────────────────────────────


def _row(seed: int, **over: object) -> MinerCapacity:
    fields: dict[str, object] = dict(
        miner_node_id=node_id(seed),
        status="active",
        capacity_slots=8,
        observed_epoch=10,
        data_epoch=10,
        refreshed_at=timezone.now(),
    )
    fields.update(over)
    return MinerCapacity.objects.create(**fields)


@pytest.mark.django_db()
def test_service_reads_the_cordon_and_the_overrides() -> None:
    _row(1, cordoned_at=timezone.now(), cordon_reason="disk")
    _row(2, max_booting=2)
    _row(3)
    assert service.cordoned_node_ids() == {node_id(1): "disk"}
    assert service.max_booting_overrides() == {node_id(2): 2}
    assert node_id(1) in service.hard_gated_node_ids()
    assert node_id(3) not in service.hard_gated_node_ids()


@pytest.mark.django_db()
def test_every_new_work_caller_gets_the_cordon_and_the_launch_the_overrides() -> None:
    _row(1, cordoned_at=timezone.now(), cordon_reason="disk")
    _row(2, max_booting=2)
    snap = make_snapshot(10, [make_miner(1), make_miner(2)])
    args = dict(snapshot=snap, tenant_id="t", user_id="u", flavor="small")
    # Feasibility and resize (no boot gate) still see the cordon.
    plain = service.placement_arguments(**args)
    assert plain["cordoned"] == {node_id(1): "disk"}
    assert "max_booting_by_node" not in plain
    launch = service.placement_arguments(**args, boot_gate=True)
    assert launch["max_booting_by_node"] == {node_id(2): 2}


@pytest.mark.django_db()
def test_an_override_alone_turns_the_boot_gate_on(settings) -> None:
    settings.VALI_SCHEDULER_MAX_BOOTING_PER_MINER = 0
    assert service.boot_gate_arguments() == {}
    _row(2, max_booting=1)
    gated = service.boot_gate_arguments()
    assert gated["max_booting_per_node"] == 0
    assert gated["max_booting_by_node"] == {node_id(2): 1}
    assert gated["booting_by_node"] == {}


# ─── the operator command ────────────────────────────────────────────


def _run(*args: str, reason: str | None = "maintenance") -> str:
    out = StringIO()
    extra = ["--by", "ops"] + (["--reason", reason] if reason is not None else [])
    call_command("vali_set_miner_capacity", "--node-id", node_id(4), *args, *extra, stdout=out)
    return out.getvalue()


def _audits(field: str) -> list[MinerCapacityAudit]:
    return list(MinerCapacityAudit.objects.filter(field=field))


@pytest.mark.django_db()
def test_cordon_and_uncordon_are_audited() -> None:
    row = _row(4)

    _run("--cordon", reason="load ~350")
    row.refresh_from_db()
    first = row.cordoned_at
    assert first is not None and row.cordon_reason == "load ~350"
    assert [a.actor for a in _audits("cordoned_at")] == ["op:ops"]
    assert _audits("cordon_reason")[0].after == "load ~350"

    # Re-cordoning restates the reason, keeps the instant it began.
    _run("--cordon", reason="still loaded")
    row.refresh_from_db()
    assert (row.cordoned_at, row.cordon_reason) == (first, "still loaded")
    assert len(_audits("cordoned_at")) == 1

    _run("--uncordon", reason="load back to 20")
    row.refresh_from_db()
    assert (row.cordoned_at, row.cordon_reason) == (None, "")
    assert len(_audits("cordoned_at")) == 2
    assert any(a.after is None for a in _audits("cordoned_at"))


@pytest.mark.django_db()
def test_a_cordon_needs_a_reason() -> None:
    _row(4)
    with pytest.raises(CommandError, match="--reason"):
        call_command(
            "vali_set_miner_capacity",
            "--node-id",
            node_id(4),
            "--cordon",
            "--dry-run",
            stdout=StringIO(),
        )


@pytest.mark.django_db()
def test_max_booting_is_set_bounded_and_dropped() -> None:
    row = _row(4)
    _run("--max-booting", "2")
    row.refresh_from_db()
    assert row.max_booting == 2
    assert _audits("max_booting")[0].after == 2
    for bad in ("0", "65"):
        with pytest.raises(CommandError, match="out of range"):
            _run("--max-booting", bad)
    _run("--max-booting-default")
    row.refresh_from_db()
    assert row.max_booting is None


@pytest.mark.django_db()
def test_show_prints_both_controls() -> None:
    _row(4, max_booting=2, cordoned_at=timezone.now(), cordon_reason="disk")
    out = StringIO()
    call_command("vali_set_miner_capacity", "--node-id", node_id(4), "--show", stdout=out)
    text = out.getvalue()
    assert "max_booting" in text and "cordoned_at" in text and "disk" in text


# ─── no QUARANTINED side effects ─────────────────────────────────────


@pytest.mark.django_db()
def test_a_cordon_has_none_of_the_quarantine_side_effects(monkeypatch) -> None:
    """The cordoned miner stays Active, its telemetry source stays active,
    it stays dispatchable, its running VM's placement is untouched, and the
    departing-miner auto-migration does not enrol it."""
    identity = make_dispatchable_identity(4)
    TelemetrySource.objects.create(
        source=SourceType.MINER.value,
        source_id=identity.miner_id,
        verifying_key=bytes(32),
        is_active=True,
    )
    _row(4)
    running = make_placement(make_vm("vm-on-m4"), node_id(4), status=PlacementStatus.BOUND.value)
    monkeypatch.setattr(chain, "read_miner_status", lambda: make_snapshot(10, [make_miner(4)]))

    _run("--cordon", reason="maintenance")

    identity.refresh_from_db()
    assert identity.status == MinerStatus.ACTIVE
    assert TelemetrySource.objects.get(source_id=identity.miner_id).is_active is True
    assert node_id(4) in service.dispatchable_node_ids()
    assert Placement.objects.get(pk=running.pk).status == PlacementStatus.BOUND.value
    assert orchestration_service.enroll_departing_miner_migrations() == 0
    assert not MigrationJob.objects.exists()


# ─── the capacity readout ────────────────────────────────────────────


@pytest.mark.django_db()
def test_the_capacity_readout_shows_the_cordon_and_offers_nothing_there(
    authed_client: APIClient, monkeypatch, settings
) -> None:
    settings.VALI_SCHEDULER_MAX_BOOTING_PER_MINER = 3
    make_dispatchable_identity(1)
    make_dispatchable_identity(2)
    monkeypatch.setattr(
        chain, "read_miner_status", lambda: make_snapshot(10, [make_miner(1), make_miner(2)])
    )
    MinerCapacity.objects.update_or_create(
        miner_node_id=node_id(1),
        defaults=dict(
            status="active",
            capacity_slots=4,
            observed_epoch=10,
            data_epoch=10,
            refreshed_at=timezone.now(),
            cordoned_at=timezone.now(),
            cordon_reason="disk",
        ),
    )
    MinerCapacity.objects.update_or_create(
        miner_node_id=node_id(2),
        defaults=dict(
            status="active",
            capacity_slots=4,
            observed_epoch=10,
            data_epoch=10,
            refreshed_at=timezone.now(),
            max_booting=1,
        ),
    )

    resp = authed_client.get(reverse("scheduler_capacity"))

    assert resp.status_code == status.HTTP_200_OK, resp.content
    by_node = {m["node_id"]: m for m in resp.json()["miners"]}
    cordoned, open_ = by_node[node_id(1)], by_node[node_id(2)]
    assert (cordoned["cordoned"], cordoned["cordon_reason"]) == (True, "disk")
    assert cordoned["free_slots"] == 0
    assert not any(cordoned["free_by_flavor"].values())
    assert (open_["cordoned"], open_["cordon_reason"]) == (False, None)
    assert open_["free_slots"] > 0
    assert (cordoned["max_booting"], open_["max_booting"]) == (3, 1)


def test_the_cordon_matches_an_upper_case_chain_spelling() -> None:
    upper = node_id(171).upper()  # "...AB": a spelling with letters in it
    snap = make_snapshot(10, [make_miner(upper), make_miner(2)])
    assert _decide(snap, cordoned={upper.lower(): "x"}) == node_id(2)


@pytest.mark.django_db()
def test_a_long_reason_is_truncated_to_the_column() -> None:
    row = _row(4)
    _run("--cordon", reason="r" * 300)
    row.refresh_from_db()
    assert row.cordon_reason == "r" * 256


# ─── explicitly named destinations ───────────────────────────────────


@pytest.mark.django_db()
def test_named_destinations_are_refused_too(monkeypatch) -> None:
    """A cordon refuses new work whoever chose the host: the operator-named
    launch (`vali_create_vm`), an explicit §25 destination, and an explicit
    restore/failover destination."""
    from apps.orchestration import restore
    from apps.orchestration.services import launch
    from apps.orchestration.tests.test_launch_service import _spec

    identity = make_dispatchable_identity(4)
    _row(4, cordoned_at=timezone.now(), cordon_reason="disk")
    assert service.miner_cordon_reason(identity.miner_id) == "disk"
    assert service.miner_cordon_reason("miner-unknown") is None

    with pytest.raises(launch.LaunchConfigError, match="cordoned"):
        launch.launch_on_named_miner(_spec(), identity, decided_by=None)
    assert not Placement.objects.exists()

    with pytest.raises(orchestration_service.StartError) as exc:
        orchestration_service._reject_cordoned_dest(identity.miner_id)
    assert exc.value.category == "dest-cordoned"

    monkeypatch.setattr(
        service, "dispatchability", lambda miner, **kw: service.Dispatchability(True, None)
    )
    monkeypatch.setattr(orchestration_service, "_snp_generation", lambda node: "genoa")
    with pytest.raises(restore.RestoreError, match="cordoned"):
        restore._validate_other_dest(make_vm("vm-r"), identity.miner_id, source="miner-a")

    # Lifted, the same miner is a destination again.
    MinerCapacity.objects.filter(miner_node_id=node_id(4)).update(cordoned_at=None)
    orchestration_service._reject_cordoned_dest(identity.miner_id)


def test_the_fleet_view_reports_a_cordoned_miner_unschedulable_with_an_existing_reason() -> None:
    from apps.operator.fleet import _placement_verdict

    common = dict(
        dispatchable=True,
        dispatch_reason=None,
        zombie_quarantined=False,
        chain_row={"status": "active", "data_epoch": 10},
        on_chain=True,
        current_epoch=10,
        cvm_verdict="proven",
        cap={"model": "v1", "free_slots": 4},
    )
    assert _placement_verdict(**common) == (True, None)
    assert _placement_verdict(**common, cordoned=True) == (False, "full")
