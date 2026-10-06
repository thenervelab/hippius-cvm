"""Gate (g) — concurrent boots per miner.

2026-10-05: a burst of ~20 runner launches landed 13 on one host within a
few minutes. Admission prices the RESERVED vCPU only, so every one of them
fit; all 13 then formatted their dm-integrity disks at once, load ~396, and
no guest got past its KEK release. The gate counts what each host is
booting right now and skips a host at the cap.
"""

from __future__ import annotations

from datetime import timedelta

import pytest
from django.test import override_settings
from django.utils import timezone

from apps.lifecycle.models import VmBootPhase, VmPowerState
from apps.orchestration.models import LaunchJob, LaunchJobState
from apps.scheduler import service
from apps.scheduler.models import Placement, PlacementStatus
from apps.scheduler.placement import MINERS_BOOTING, PlacementError, decide_placement

from .factories import (
    make_miner,
    make_placement,
    make_service_client,
    make_snapshot,
    make_vm,
    node_id,
)


def _decide(snapshot, *, booting, cap=3, region="", region_by_node=None):
    return decide_placement(
        snapshot=snapshot,
        capacity_by_node={m.node_id: 8 for m in snapshot.miners},
        load_by_node={},
        family_load_by_node={},
        max_epoch_lag=2,
        booting_by_node=booting,
        max_booting_per_node=cap,
        region=region,
        region_by_node=region_by_node,
    )


# ─── the pure gate ───────────────────────────────────────────────────


def test_a_miner_at_the_cap_is_skipped_for_the_next_one() -> None:
    snap = make_snapshot(10, [make_miner(1), make_miner(2)])
    # node 1 wins the tie-break when nothing is booting...
    assert _decide(snap, booting={}) == node_id(1)
    # ...and is skipped once it boots `cap` guests.
    assert _decide(snap, booting={node_id(1): 3}) == node_id(2)
    # Below the cap it still competes normally.
    assert _decide(snap, booting={node_id(1): 2}) == node_id(1)


def test_every_miner_at_the_cap_is_its_own_transient_category() -> None:
    snap = make_snapshot(10, [make_miner(1), make_miner(2)])
    with pytest.raises(PlacementError) as exc:
        _decide(snap, booting={node_id(1): 3, node_id(2): 5})
    assert exc.value.category == MINERS_BOOTING
    assert f"{node_id(1)}=3" in exc.value.message
    assert f"{node_id(2)}=5" in exc.value.message


def test_cap_zero_disables_the_gate() -> None:
    snap = make_snapshot(10, [make_miner(1)])
    assert _decide(snap, booting={node_id(1): 50}, cap=0) == node_id(1)


def test_a_miner_failing_another_gate_does_not_make_the_fleet_look_busy() -> None:
    """The gate runs last: `miners-booting` is claimed only when a node
    that passed every other gate was removed by it. A region miss stays a
    region miss, never "wait for a boot slot"."""
    snap = make_snapshot(10, [make_miner(1)])
    with pytest.raises(PlacementError) as exc:
        _decide(snap, booting={node_id(1): 9}, region="FR", region_by_node={node_id(1): "DE"})
    assert exc.value.category == "no-miner-in-region"


# ─── what counts as booting ──────────────────────────────────────────


def _bound(vm_id: str, seed: int, **vm_fields):
    vm = make_vm(vm_id, lease_id=f"lease-{vm_id}")
    for k, v in vm_fields.items():
        setattr(vm, k, v)
    vm.save()
    return make_placement(
        vm, node_id(seed), status=PlacementStatus.BOUND.value, resource_class="small"
    )


def _pending(vm_id: str, seed: int, *, job_state: str | None):
    make_placement(make_vm(vm_id, lease_id=f"lease-{vm_id}"), node_id(seed))
    if job_state is not None:
        LaunchJob.objects.create(
            job_id=f"job-{vm_id}",
            vm_id=vm_id,
            tenant_id="t",
            flavor="small",
            spec_json={},
            userdata_vault_path="p",
            userdata_vault_version=1,
            kek_vault_path="k",
            state=job_state,
            phase_started_at=timezone.now(),
            finished_at=None if job_state == LaunchJobState.RUNNING.value else timezone.now(),
            decided_by=make_service_client(),
        )


@pytest.mark.django_db()
def test_booting_by_node_counts_only_boots_still_in_progress() -> None:
    now = timezone.now()
    ago = lambda s: now - timedelta(seconds=s)  # noqa: E731
    # Counted on node 1: a launch dispatching, and four guests with no
    # in-guest signal since their current boot began.
    _pending("pending", 1, job_state=LaunchJobState.RUNNING.value)
    _bound("fresh", 1, boot_started_at=ago(60))
    _bound("unlocked", 1, boot_started_at=ago(300), boot_phase=VmBootPhase.KEK_RELEASED)
    # A relaunch: `running` is the PREVIOUS boot's milestone (monotonic).
    _bound(
        "relaunch",
        1,
        boot_started_at=ago(60),
        boot_phase=VmBootPhase.RUNNING,
        boot_phase_at=ago(3600),
        guest_signal_at=ago(120),
    )
    # `running` with no timestamp is not evidence about this boot.
    _bound("untimed", 1, boot_started_at=ago(60), boot_phase=VmBootPhase.RUNNING)
    # Not counted (node 2): up, by either signal; stalled past the small
    # flavor's deadline (900 + 15 × 40 s); powered off; a Pending whose
    # launch job is over (it died before failing its row) or has none.
    _bound("signalled", 2, boot_started_at=ago(600), guest_signal_at=ago(30))
    _bound(
        "milestone",
        2,
        boot_started_at=ago(600),
        boot_phase=VmBootPhase.RUNNING,
        boot_phase_at=ago(30),
    )
    _bound("stalled", 2, boot_started_at=ago(1501))
    _bound("stopped", 2, boot_started_at=ago(60), power_state=VmPowerState.STOPPED)
    _pending("abandoned", 2, job_state=LaunchJobState.FAILED.value)
    _pending("operator", 2, job_state=None)
    # A job left `running` by a killed worker: bounded by the row's age.
    _pending("killed", 2, job_state=LaunchJobState.RUNNING.value)
    Placement.objects.filter(vm__vm_id="killed").update(
        decided_at=ago(service.stale_pending_after_s() + 1)
    )

    assert service.booting_by_node(now=now) == {node_id(1): 5}


@pytest.mark.django_db()
def test_a_legacy_row_falls_back_to_created_at() -> None:
    """No `boot_started_at` (pre-column row): the clock is `created_at`, so
    an old never-signalled VM is past its deadline and does not count."""
    _bound("legacy", 1)
    assert service.booting_by_node() == {node_id(1): 1}
    assert service.booting_by_node(now=timezone.now() + timedelta(hours=1)) == {}


@pytest.mark.django_db()
def test_only_the_launch_path_asks_for_the_gate() -> None:
    snap = make_snapshot(10, [make_miner(1)])
    args = dict(snapshot=snap, tenant_id="t", user_id="u", flavor="small")
    assert "booting_by_node" not in service.placement_arguments(**args)
    gated = service.placement_arguments(**args, boot_gate=True)
    assert gated["max_booting_per_node"] == 3
    assert gated["booting_by_node"] == {}
    with override_settings(VALI_SCHEDULER_MAX_BOOTING_PER_MINER=0):
        assert "booting_by_node" not in service.placement_arguments(**args, boot_gate=True)
