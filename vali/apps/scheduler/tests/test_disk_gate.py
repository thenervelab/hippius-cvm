"""Storage-aware placement: the DATA-disk dimension of admission.

vali's own ledger (Σ flavor `disk_gb` + rootfs per counted placement) is
the authority; every miner-supplied figure (heartbeat v4) is only a term
of a `min`; the gate is `off | record | enforce` and runs under both
admission models; unknown data is governed by `allow | deny`.
"""

from __future__ import annotations

import json
import logging
from datetime import timedelta

import pytest
from django.core.exceptions import ImproperlyConfigured
from django.test import override_settings
from django.utils import timezone

from apps.orchestration.services import flavors
from apps.scheduler import capacity, capacity_config, capacity_earn, feasibility, service
from apps.scheduler.capacity import DiskInputs, disk_budget
from apps.scheduler.models import (
    CapacityTrustClass,
    MinerCapacity,
    MinerCapacityAudit,
    MinerStatusMirror,
    PlacementStatus,
)
from apps.scheduler.placement import PlacementError, decide_placement

from .factories import (
    make_dispatchable_identity,
    make_miner,
    make_placement,
    make_snapshot,
    make_vm,
    node_id,
    observe_chain_epoch,
)

pytestmark = pytest.mark.django_db

ENFORCE = override_settings(VALI_SCHEDULER_DISK_GATE="enforce")
RECORD = override_settings(VALI_SCHEDULER_DISK_GATE="record")
OFF = override_settings(VALI_SCHEDULER_DISK_GATE="off")
V2 = override_settings(VALI_SCHEDULER_RESOURCE_ADMISSION="true")

#: What one VM of each flavor commits: data disk + the 10 GiB rootfs.
SMALL = 40 + flavors.ROOTFS_DISK_GB
LARGE = 160 + flavors.ROOTFS_DISK_GB
XLARGE = 320 + flavors.ROOTFS_DISK_GB


@pytest.fixture(autouse=True)
def _propagate_apps_logs(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(logging.getLogger("apps"), "propagate", True)


def _inputs(**over: object) -> DiskInputs:
    base: dict[str, object] = dict(
        anchor_total_gb=None,
        declared_budget_gb=None,
        reported_total_gb=None,
        reported_available_gb=None,
        earned_disk_gb=None,
        reserve_gb=100,
        committed_gb=0,
        overclaim_slack_gb=50,
    )
    base.update(over)
    return DiskInputs(**base)  # type: ignore[arg-type]


def _mirror(seed: int, **fields: object) -> MinerCapacity:
    base: dict[str, object] = dict(
        miner_node_id=node_id(seed),
        status=MinerStatusMirror.ACTIVE,
        capacity_slots=64,
        observed_epoch=10,
        data_epoch=10,
        refreshed_at=timezone.now(),
        trust_class=CapacityTrustClass.OPERATOR,
        total_cpus=64,
        total_memory_mb=512_000,
    )
    base.update(fields)
    return MinerCapacity.objects.create(**base)


def _disk(seed: int, *, declared: int | None = None, total: int | None = None,
          available: int | None = None, staging: int | None = None,
          at: object = None) -> None:
    MinerCapacity.objects.filter(miner_node_id=node_id(seed)).update(
        declared_disk_gb_budget=declared,
        reported_data_disk_total_gb=total,
        reported_data_disk_available_gb=available,
        reported_staging_disk_available_gb=staging,
        disk_reported_at=timezone.now() if at is None else at,
    )


def _place(seed: int, n: int, resource_class: str, *, status: str = "bound") -> None:
    for i in range(n):
        make_placement(
            make_vm(f"vm-{seed}-{resource_class}-{status}-{i}", f"l-{seed}-{status}-{i}"),
            node_id(seed),
            status=status,
            resource_class=resource_class,
        )


def _decide(flavor: str, *seeds: int) -> str:
    snapshot = make_snapshot(10, [make_miner(s) for s in seeds])
    cap, load, fam = service.decision_inputs("tenant-x")
    return decide_placement(
        snapshot=snapshot,
        capacity_by_node=cap,
        load_by_node=load,
        family_load_by_node=fam,
        max_epoch_lag=5,
        resource_fit=service.resource_fit(flavor),
    )


def _would_reject_lines(caplog: pytest.LogCaptureFixture) -> list[dict[str, object]]:
    out = []
    for r in caplog.records:
        msg = r.getMessage()
        if msg.startswith("disk-gate: "):
            out.append(json.loads(msg.removeprefix("disk-gate: ")))
    return out


# ─── the pure budget: down-only min ─────────────────────────────────


def test_budget_is_the_min_of_every_known_term() -> None:
    d = disk_budget(
        _inputs(anchor_total_gb=5000, declared_budget_gb=3000, reported_total_gb=4000)
    )
    assert (d.known, d.budget_gb, d.binding) == (True, 3000, "disk:declared")
    # The reserve comes off the anchor and the reported total — not the
    # declared budget, which is already the operator's net commitment.
    d = disk_budget(_inputs(declared_budget_gb=3950, reported_total_gb=4000))
    assert (d.budget_gb, d.binding) == (3900, "disk:reported")
    d = disk_budget(_inputs(anchor_total_gb=2000, declared_budget_gb=1950))
    assert (d.budget_gb, d.binding) == (1900, "disk:anchor")


def test_a_huge_self_report_cannot_raise_the_budget_above_the_other_term() -> None:
    honest = disk_budget(_inputs(reported_total_gb=2100))
    lying = disk_budget(
        _inputs(reported_total_gb=2100, declared_budget_gb=4_000_000_000)
    )
    assert honest.budget_gb == lying.budget_gb == 2000
    lying = disk_budget(_inputs(declared_budget_gb=1000, reported_total_gb=4_000_000_000))
    assert lying.budget_gb == 1000
    anchored = disk_budget(
        _inputs(anchor_total_gb=1100, declared_budget_gb=9_999_999, reported_total_gb=9_999_999)
    )
    assert anchored.budget_gb == 1000


def test_no_term_at_all_is_unknown_never_a_fit() -> None:
    d = disk_budget(_inputs())
    assert (d.known, d.budget_gb, d.free_gb) == (False, 0, 0)


def test_the_earned_ceiling_is_a_down_only_term_and_zero_is_real() -> None:
    assert disk_budget(_inputs(declared_budget_gb=2000, earned_disk_gb=500)).budget_gb == 500
    assert disk_budget(_inputs(declared_budget_gb=2000, earned_disk_gb=0)).budget_gb == 0
    assert disk_budget(_inputs(declared_budget_gb=200, earned_disk_gb=5000)).budget_gb == 200


def test_free_is_budget_minus_committed_clamped_down_by_the_reported_available() -> None:
    d = disk_budget(_inputs(declared_budget_gb=1000, committed_gb=300))
    assert d.free_gb == 700
    d = disk_budget(
        _inputs(declared_budget_gb=1000, committed_gb=300, reported_available_gb=250)
    )
    # The reserve (100) stays off the measured-free figure too.
    assert d.free_gb == 150
    # An over-report of available never raises free above the ledger's.
    d = disk_budget(
        _inputs(declared_budget_gb=1000, committed_gb=300, reported_available_gb=900_000)
    )
    assert d.free_gb == 700
    # Committed above the budget clamps free at 0, never negative.
    assert disk_budget(_inputs(declared_budget_gb=100, committed_gb=300)).free_gb == 0


def test_over_claim_fires_only_below_committed_minus_slack() -> None:
    base = dict(declared_budget_gb=2000, committed_gb=1000, overclaim_slack_gb=50)
    assert disk_budget(_inputs(**base, reported_available_gb=949)).over_claim is True
    assert disk_budget(_inputs(**base, reported_available_gb=950)).over_claim is False
    assert disk_budget(_inputs(**base)).over_claim is False  # no report, no alarm


def test_over_claim_never_changes_the_budget() -> None:
    flagged = disk_budget(
        _inputs(declared_budget_gb=2000, committed_gb=1000, reported_available_gb=10)
    )
    assert flagged.over_claim and flagged.budget_gb == 2000


# ─── committed arithmetic from vali's own ledger ────────────────────


def test_each_vm_commits_its_flavor_disk_plus_the_rootfs() -> None:
    for name in flavors.FLAVOR_NAMES:
        size = flavors.resolve_flavor(name)
        assert service.flavor_disk_gb(name) == size.data_disk_size_gb + flavors.ROOTFS_DISK_GB


def test_an_unknown_class_commits_the_reference_disk() -> None:
    assert service.flavor_disk_gb("std") == 160 + flavors.ROOTFS_DISK_GB
    with override_settings(VALI_SCHEDULER_SLOT_REF_DISK_GB=500):
        assert service.flavor_disk_gb("std") == 500 + flavors.ROOTFS_DISK_GB


def test_committed_disk_sums_only_the_placements_admission_counts() -> None:
    _mirror(1)
    _place(1, 2, "large")
    _place(1, 1, "small", status=PlacementStatus.PENDING.value)
    _place(1, 3, "xlarge", status=PlacementStatus.FAILED.value)
    assert service._committed_by_node()[node_id(1)].disk_gb == 2 * LARGE + SMALL
    assert service.disk_budgets_by_node()[node_id(1)].committed_gb == 2 * LARGE + SMALL


def test_stale_heartbeat_disk_terms_are_dropped() -> None:
    _mirror(1)
    _disk(1, declared=300, total=5000)
    assert service.disk_budgets_by_node()[node_id(1)].budget_gb == 300
    _disk(1, declared=300, total=5000, at=timezone.now() - timedelta(days=1))
    assert service.disk_budgets_by_node()[node_id(1)].known is False
    MinerCapacity.objects.filter(miner_node_id=node_id(1)).update(total_disk_gb=900)
    # The operator anchor needs no heartbeat.
    assert service.disk_budgets_by_node()[node_id(1)].budget_gb == 800


def test_a_zero_heartbeat_figure_is_no_term() -> None:
    _mirror(1)
    _disk(1, declared=0, total=1000)
    d = service.disk_budgets_by_node()[node_id(1)]
    assert (d.budget_gb, d.binding) == (900, "disk:reported")


# ─── settings fail loudly ───────────────────────────────────────────


@pytest.mark.parametrize(
    "setting",
    [
        {"VALI_SCHEDULER_DISK_GATE": "enforced"},
        {"VALI_SCHEDULER_DISK_GATE": ""},
        {"VALI_SCHEDULER_DISK_UNKNOWN": "maybe"},
        {"VALI_DISK_RESERVE_GB": "lots"},
        {"VALI_DISK_RESERVE_GB": -1},
        {"VALI_DISK_OVERCLAIM_SLACK_GB": "x"},
        {"VALI_SCHEDULER_SLOT_REF_DISK_GB": 0},
    ],
)
def test_a_malformed_disk_setting_raises(setting: dict[str, object]) -> None:
    with override_settings(**setting), pytest.raises(ImproperlyConfigured):
        capacity_config.validate_all()


def test_defaults() -> None:
    assert capacity_config.disk_gate_mode() == "record"
    assert capacity_config.disk_unknown_policy() == "allow"
    assert capacity_config.disk_reserve_gb() == 100
    assert capacity_config.disk_overclaim_slack_gb() == 50
    assert capacity_config.slot_ref_disk_gb() == 160


def test_the_disk_knobs_are_read_from_the_environment() -> None:
    from vali import settings as vali_settings

    env = {
        "VALI_SCHEDULER_DISK_GATE": "enforce",
        "VALI_SCHEDULER_DISK_UNKNOWN": "deny",
        "VALI_DISK_RESERVE_GB": "200",
        "VALI_DISK_OVERCLAIM_SLACK_GB": "10",
        "VALI_SCHEDULER_SLOT_REF_DISK_GB": "320",
    }
    assert vali_settings._capacity_v2_env(env) == env


# ─── the gate in decide_placement (v1 and v2) ───────────────────────


def _full_disk_host_and_roomy_host() -> None:
    """Node 1 wins every other tie (lower id) but has disk for ONE small
    VM only; node 2 has plenty."""
    _mirror(1)
    _mirror(2)
    _disk(1, declared=SMALL + 5)
    _disk(2, declared=5000)


@pytest.mark.parametrize("model", ["v1", "v2"])
def test_off_ignores_disk_entirely(model: str, caplog: pytest.LogCaptureFixture) -> None:
    _full_disk_host_and_roomy_host()
    with OFF, override_settings(VALI_SCHEDULER_RESOURCE_ADMISSION=model == "v2"):
        assert service.resource_fit("large").disk_refusal_by_node == {}
        assert _decide("large", 1, 2) == node_id(1)
    assert _would_reject_lines(caplog) == []


@pytest.mark.parametrize("model", ["v1", "v2"])
def test_record_admits_but_logs_the_decision_enforce_would_refuse(
    model: str, caplog: pytest.LogCaptureFixture
) -> None:
    _full_disk_host_and_roomy_host()
    with RECORD, override_settings(VALI_SCHEDULER_RESOURCE_ADMISSION=model == "v2"):
        assert _decide("large", 1, 2) == node_id(1)
    lines = _would_reject_lines(caplog)
    assert lines == [
        {
            "context": "placement",
            "disk_gb": LARGE,
            "event": "disk_gate_would_reject",
            "mode": "record",
            "node_id": node_id(1),
            "reason": f"disk free {SMALL + 5} < {LARGE} GiB",
            "resource_class": "large",
        }
    ]


def test_record_is_silent_when_the_chosen_node_fits(caplog: pytest.LogCaptureFixture) -> None:
    _full_disk_host_and_roomy_host()
    with RECORD:
        assert _decide("small", 1, 2) == node_id(1)
    assert _would_reject_lines(caplog) == []


@pytest.mark.parametrize("model", ["v1", "v2"])
def test_enforce_refuses_the_host_without_room(model: str) -> None:
    _full_disk_host_and_roomy_host()
    with ENFORCE, override_settings(VALI_SCHEDULER_RESOURCE_ADMISSION=model == "v2"):
        assert _decide("large", 1, 2) == node_id(2)
        assert _decide("small", 1, 2) == node_id(1)
        with pytest.raises(PlacementError) as exc:
            _decide("large", 1)
    assert "data-disk gate" in exc.value.message


def test_enforce_counts_the_disk_already_committed() -> None:
    _mirror(1)
    _disk(1, declared=2 * LARGE)
    _place(1, 1, "large")
    with ENFORCE:
        assert _decide("large", 1) == node_id(1)  # 170 of 340 used: one more fits
        _place(1, 1, "large", status=PlacementStatus.PENDING.value)
        with pytest.raises(PlacementError):
            _decide("large", 1)


def test_enforce_unknown_allow_admits_and_deny_refuses() -> None:
    _mirror(1)  # no disk data at all
    _mirror(2)
    _disk(2, declared=5000)
    with ENFORCE:
        assert _decide("large", 1, 2) == node_id(1)
    with ENFORCE, override_settings(VALI_SCHEDULER_DISK_UNKNOWN="deny"):
        assert _decide("large", 1, 2) == node_id(2)
        with pytest.raises(PlacementError):
            _decide("large", 1)


def test_record_admits_unknown_even_under_deny(caplog: pytest.LogCaptureFixture) -> None:
    _mirror(1)
    with RECORD, override_settings(VALI_SCHEDULER_DISK_UNKNOWN="deny"):
        assert _decide("large", 1) == node_id(1)
    assert [line["reason"] for line in _would_reject_lines(caplog)] == ["disk-unknown"]


def test_a_lying_huge_declared_budget_cannot_buy_a_placement() -> None:
    _mirror(1)
    _disk(1, declared=4_000_000_000, total=SMALL + 100 + 5)  # fs holds one small
    with ENFORCE:
        with pytest.raises(PlacementError):
            _decide("large", 1)
        assert _decide("small", 1) == node_id(1)


# ─── v2 budgets, units, headroom and the readouts ───────────────────


def test_the_v2_budget_carries_disk_but_applies_it_only_under_enforce() -> None:
    _mirror(1)
    _disk(1, declared=LARGE)
    with RECORD:
        b = service.host_budgets_by_node()[node_id(1)]
        assert b.disk.budget_gb == LARGE and b.disk_gate == capacity.DISK_GATE_OFF
        assert capacity.fits(b, cpu_count=8, memory_mb=32768, disk_gb=XLARGE)
    with ENFORCE:
        b = service.host_budgets_by_node()[node_id(1)]
        assert b.disk_gate == capacity.DISK_GATE_APPLY
        assert not capacity.fits(b, cpu_count=8, memory_mb=32768, disk_gb=XLARGE)
        assert not capacity.big_enough(b, cpu_count=8, memory_mb=32768, disk_gb=XLARGE)
        assert capacity.headroom(b, cpu_count=1, memory_mb=4096, disk_gb=SMALL) == LARGE // SMALL
        u = capacity.units(b, unit_cpus=4, unit_memory_mb=16384, unit_disk_gb=LARGE)
        assert (u.total, u.free) == (1, 1)
    with ENFORCE, override_settings(VALI_SCHEDULER_DISK_UNKNOWN="deny"):
        MinerCapacity.objects.update(disk_reported_at=None)
        b = service.host_budgets_by_node()[node_id(1)]
        assert b.disk_gate == capacity.DISK_GATE_DENY
        assert capacity.headroom(b, cpu_count=1, memory_mb=4096, disk_gb=SMALL) == 0
        assert capacity.units(b, unit_cpus=4, unit_memory_mb=16384, unit_disk_gb=LARGE).total == 0


@V2
def test_capacity_views_follow_the_enforced_disk() -> None:
    _mirror(1)
    _disk(1, declared=2 * LARGE)
    with RECORD:
        view = service.capacity_views()[node_id(1)]
        assert view.free_by_flavor["large"] > 2
    with ENFORCE:
        view = service.capacity_views()[node_id(1)]
        assert view.free_by_flavor["large"] == 2
        assert view.fits_hardware["xlarge"] is True
        assert view.fits_hardware["2xlarge"] is False
    with ENFORCE, override_settings(VALI_SCHEDULER_DISK_UNKNOWN="deny"):
        MinerCapacity.objects.update(disk_reported_at=None)
        view = service.capacity_views()[node_id(1)]
        assert view.fits_hardware["small"] is None  # cannot say, never "too small"
        assert view.free_by_flavor["small"] == 0


def test_capacity_views_v1_follow_the_enforced_disk() -> None:
    _mirror(1)
    _disk(1, declared=2 * LARGE)
    with ENFORCE:
        view = service.capacity_views()[node_id(1)]
    assert view.model == "v1"
    assert view.free_by_flavor["large"] == 2
    assert view.fits_hardware["xlarge"] is True
    assert view.fits_hardware["2xlarge"] is False


# ─── feasibility ────────────────────────────────────────────────────


def _feasible_host(seed: int, monkeypatch: pytest.MonkeyPatch, **disk: int | None) -> None:
    from apps.scheduler import chain

    observe_chain_epoch(10)
    make_dispatchable_identity(seed)
    _mirror(seed)
    if disk:
        _disk(seed, **disk)
    snapshot = make_snapshot(10, [make_miner(seed)])
    monkeypatch.setattr(chain, "read_miner_status", lambda: snapshot)


@pytest.mark.parametrize("model", ["v1", "v2"])
def test_feasibility_reports_disk_per_host_and_gates_it_only_when_enforced(
    model: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    _feasible_host(1, monkeypatch, declared=LARGE)
    with RECORD, override_settings(VALI_SCHEDULER_RESOURCE_ADMISSION=model == "v2"):
        f = feasibility.assess("xlarge")
        host = f.hosts[0]
        assert (host.disk_checked, host.budget_disk_gb, host.free_disk_gb) == (True, LARGE, LARGE)
        assert host.fits is True and f.verdict == "yes" and f.disk_checked is False
    with ENFORCE, override_settings(VALI_SCHEDULER_RESOURCE_ADMISSION=model == "v2"):
        f = feasibility.assess("xlarge")
        assert f.hosts[0].fits is False and f.hosts[0].big_enough is False
        assert f"host disk budget {LARGE} < {XLARGE} GiB" in f.hosts[0].shortfall
        assert f.verdict == "never"
        ok = feasibility.assess("large")
        assert ok.verdict == "yes" and ok.disk_checked is True and ok.headroom == 1


def test_feasibility_disk_checked_is_false_when_a_fitting_host_has_no_data(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _feasible_host(1, monkeypatch)
    with ENFORCE:
        f = feasibility.assess("small")
    assert f.verdict == "yes"
    assert f.hosts[0].disk_checked is False
    assert f.disk_checked is False


# ─── explicit destinations (§25 / restore / failover) ───────────────


def test_an_explicit_destination_is_gated_like_a_placement(
    caplog: pytest.LogCaptureFixture,
) -> None:
    _mirror(1)
    _disk(1, declared=SMALL)
    with OFF:
        assert service.disk_gate_refusal(node_id(1), "large", context="t") == ""
    with RECORD:
        assert service.disk_gate_refusal(node_id(1), "large", context="migration-dest") == ""
    assert [line["context"] for line in _would_reject_lines(caplog)] == ["migration-dest"]
    with ENFORCE:
        assert service.disk_gate_refusal(node_id(1), "large", context="t") == (
            f"disk free {SMALL} < {LARGE} GiB"
        )
        assert service.disk_gate_refusal(node_id(1), "small", context="t") == ""
        # No mirror row = unknown = the unknown policy.
        assert service.disk_gate_refusal(node_id(9), "large", context="t") == ""
    with ENFORCE, override_settings(VALI_SCHEDULER_DISK_UNKNOWN="deny"):
        assert service.disk_gate_refusal(node_id(9), "large", context="t") == "disk-unknown"


def test_start_migration_refuses_a_destination_without_disk_room() -> None:
    from apps.miners.models import MinerIdentity
    from apps.orchestration import service as orch

    _mirror(2)
    _disk(2, declared=SMALL)
    make_dispatchable_identity(2)
    dest = MinerIdentity.objects.get(chain_node_id=node_id(2)).miner_id
    vm = make_vm("vm-mig", "lease-mig")
    make_placement(vm, node_id(1), status="bound", resource_class="large")
    with ENFORCE, pytest.raises(orch.StartError) as exc:
        orch._reject_disk_full_dest(vm, dest)
    assert exc.value.category == "dest-insufficient-disk"
    with RECORD:
        orch._reject_disk_full_dest(vm, dest)  # logged, allowed


# ─── the earned disk ceiling ────────────────────────────────────────


def test_a_disk_refusal_halves_the_earned_disk_ceiling_from_the_current_budget() -> None:
    _mirror(1, trust_class=CapacityTrustClass.EARNED, total_cpus=None, total_memory_mb=None)
    _disk(1, declared=1000, total=5000)
    assert capacity_earn.record_event(node_id(1), capacity_earn.DISK_INSUFFICIENT, incident="a")
    row = MinerCapacity.objects.get(miner_node_id=node_id(1))
    assert row.earned_disk_gb == 500
    assert row.earned_last_reason == "disk-insufficient"
    # CPU/RAM ceilings untouched.
    assert (row.earned_vms, row.earned_vcpus, row.earned_memory_mb) == (None, None, None)
    assert service.disk_budgets_by_node()[node_id(1)].budget_gb == 500
    # Idempotent per incident; a new incident cuts again from the new budget.
    assert not capacity_earn.record_event(node_id(1), capacity_earn.DISK_INSUFFICIENT, incident="a")
    assert capacity_earn.record_event(node_id(1), capacity_earn.DISK_INSUFFICIENT, incident="b")
    assert MinerCapacity.objects.get(miner_node_id=node_id(1)).earned_disk_gb == 250
    audit = MinerCapacityAudit.objects.filter(field="earned_disk_gb").order_by("created_at")
    assert [a.after for a in audit] == [500, 250]
    assert {a.actor for a in audit} == {"event:disk-insufficient"}


def test_an_honest_disk_refusal_after_vali_over_booked_costs_nothing() -> None:
    """Under `record` vali can place past a host's disk budget; the 507 that
    follows is the host telling the truth and must not cut its ceiling."""
    _mirror(1, trust_class=CapacityTrustClass.EARNED, total_cpus=None, total_memory_mb=None)
    _disk(1, declared=LARGE)
    _place(1, 2, "large")  # 340 committed > 170 budget: vali over-booked
    assert not capacity_earn.record_event(node_id(1), capacity_earn.DISK_INSUFFICIENT)
    assert MinerCapacity.objects.get().earned_disk_gb is None


def test_a_disk_refusal_after_a_flagged_over_claim_costs_nothing() -> None:
    _mirror(1, trust_class=CapacityTrustClass.EARNED, total_cpus=None, total_memory_mb=None)
    _disk(1, declared=5000, available=10)
    _place(1, 1, "xlarge")  # 330 committed, 10 available: the host SAID it was short
    assert not capacity_earn.record_event(node_id(1), capacity_earn.DISK_INSUFFICIENT)
    assert MinerCapacity.objects.get().earned_disk_gb is None


def test_a_full_disk_reported_as_zero_available_is_real_next_to_a_total() -> None:
    _mirror(1)
    _disk(1, declared=5000, total=4000, available=0)
    d = service.disk_budgets_by_node()[node_id(1)]
    assert (d.known, d.free_gb) == (True, 0)
    with ENFORCE, pytest.raises(PlacementError):
        _decide("small", 1)


def test_a_disk_refusal_never_touches_an_operator_row_or_an_unsized_host() -> None:
    _mirror(1)  # operator
    _disk(1, declared=1000)
    assert not capacity_earn.record_event(node_id(1), capacity_earn.DISK_INSUFFICIENT)
    _mirror(2, trust_class=CapacityTrustClass.EARNED)
    assert not capacity_earn.record_event(node_id(2), capacity_earn.DISK_INSUFFICIENT)
    assert MinerCapacity.objects.filter(earned_disk_gb__isnull=False).count() == 0


def test_the_earned_reset_forgives_the_disk_cut() -> None:
    from io import StringIO

    from django.core.management import call_command

    _mirror(1, trust_class=CapacityTrustClass.EARNED, earned_disk_gb=10)
    call_command(
        "vali_set_miner_capacity",
        "--node-id",
        node_id(1),
        "--earned-reset",
        "--by",
        "ops",
        "--reason",
        "test",
        stdout=StringIO(),
    )
    assert MinerCapacity.objects.get().earned_disk_gb is None


# ─── the operator anchor command ────────────────────────────────────


def test_the_disk_anchor_is_set_audited_and_refused_below_the_committed_disk() -> None:
    from io import StringIO

    from django.core.management import CommandError, call_command

    _mirror(1)
    args = ["vali_set_miner_capacity", "--node-id", node_id(1), "--by", "ops", "--reason", "r"]
    call_command(*args, "--disk-gb", "3000", stdout=StringIO())
    assert MinerCapacity.objects.get().total_disk_gb == 3000
    assert MinerCapacityAudit.objects.filter(field="total_disk_gb").count() == 1
    _place(1, 2, "large")
    with pytest.raises(CommandError, match="below the"):
        call_command(*args, "--disk-gb", str(2 * LARGE - 1), stdout=StringIO())
    call_command(*args, "--disk-clear", stdout=StringIO())
    assert MinerCapacity.objects.get().total_disk_gb is None


# ─── the reeval survey: over-claim alarm + gauges ───────────────────


def test_the_survey_warns_on_disk_over_claim_and_pushes_gauges(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    from apps.scheduler.management.commands import vali_scheduler_reeval as reeval
    from apps.synthetic import metrics

    _mirror(1)
    _mirror(2)
    _disk(1, declared=5000, available=10)
    _disk(2, declared=5000, available=4000)
    _place(1, 2, "xlarge")  # 660 committed, 10 available ⇒ alarm
    pushed: list[str] = []
    monkeypatch.setattr(metrics, "push", lambda ms, **_k: pushed.append(ms.render()) or True)
    with override_settings(VALI_SYNTHETIC_PUSHGATEWAY_URL="http://pgw"):
        reeval.disk_survey()
    warnings = [r.getMessage() for r in caplog.records if "disk over-claim" in r.getMessage()]
    assert len(warnings) == 1 and node_id(1) in warnings[0]
    body = pushed[0]
    assert f'hippius_vali_disk_over_claim{{node_id="{node_id(1)}"}} 1' in body
    assert f'hippius_vali_disk_over_claim{{node_id="{node_id(2)}"}} 0' in body
    assert f'hippius_vali_disk_committed_gb{{node_id="{node_id(1)}"}} {2 * XLARGE}' in body
    # 10 GiB free on node 1 ⇒ enforce would refuse even a small there.
    assert (
        f'hippius_vali_disk_gate_would_refuse{{flavor="small",node_id="{node_id(1)}"}} 1' in body
    )
    assert (
        f'hippius_vali_disk_gate_would_refuse{{flavor="small",node_id="{node_id(2)}"}} 0' in body
    )
