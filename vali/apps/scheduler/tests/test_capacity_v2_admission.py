"""Capacity v2 wired into admission: `service.resource_fit`, gate (a) of
`decide_placement` (enforced and shadow), the ranking term, feasibility,
and the budget-input assembly (freshness, floors, overrides)."""

from __future__ import annotations

import json
import logging
from datetime import timedelta
from decimal import Decimal

import pytest
from django.test import override_settings
from django.utils import timezone

from apps.scheduler import chain, feasibility, service
from apps.scheduler.models import (
    CapacityTrustClass,
    MinerCapacity,
    MinerStatusMirror,
    PlacementStatus,
)
from apps.scheduler.placement import PlacementError, ResourceFit, decide_placement

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

ENFORCE = override_settings(VALI_SCHEDULER_RESOURCE_ADMISSION="true")


@pytest.fixture(autouse=True)
def _propagate_apps_logs(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(logging.getLogger("apps"), "propagate", True)


def _mirror(seed: int, **fields: object) -> MinerCapacity:
    base: dict[str, object] = dict(
        miner_node_id=node_id(seed),
        status=MinerStatusMirror.ACTIVE,
        capacity_slots=64,
        observed_epoch=10,
        data_epoch=10,
        refreshed_at=timezone.now(),
        trust_class=CapacityTrustClass.OPERATOR,
        total_cpus=24,
        total_memory_mb=384_395,
    )
    base.update(fields)
    return MinerCapacity.objects.create(**base)


def _place(seed: int, n: int, resource_class: str, *, start: int = 0) -> None:
    for i in range(start, start + n):
        make_placement(
            make_vm(f"vm-{seed}-{i}", f"lease-{seed}-{i}"),
            node_id(seed),
            status=PlacementStatus.BOUND.value,
            resource_class=resource_class,
        )


def _decide(flavor: str, *seeds: int, **extra: object) -> str:
    snapshot = make_snapshot(10, [make_miner(s) for s in seeds])
    cap, load, fam = service.decision_inputs("tenant-x")
    return decide_placement(
        snapshot=snapshot,
        capacity_by_node=cap,
        load_by_node=load,
        family_load_by_node=fam,
        max_epoch_lag=5,
        resource_fit=service.resource_fit(flavor),
        **extra,
    )


# ─── budget-input assembly ──────────────────────────────────────────


def test_fresh_declarations_clamp_and_stale_ones_are_ignored() -> None:
    now = timezone.now()
    row = _mirror(
        1,
        declared_cpu_budget=20,
        declared_memory_mb_budget=98304,
        declared_asid_capacity=99,
        declared_at=now,
    )
    b = service.host_budgets_by_node()[node_id(1)]
    assert (b.vcpu_budget, b.memory_budget_mb, b.vm_budget) == (20, 98304, 64)
    MinerCapacity.objects.filter(pk=row.pk).update(declared_at=now - timedelta(days=1))
    stale = service.host_budgets_by_node()[node_id(1)]
    # Stale ⇒ dropped ⇒ back UP to the trusted terms, never above them.
    assert stale.vcpu_budget == 44 and stale.memory_budget_mb == 384_395 - 8192


def test_the_host_reserve_default_is_8192(settings) -> None:
    del settings.VALI_SCHEDULER_HOST_RESERVE_MEMORY_MB
    assert service._host_reserve_memory_mb() == 8192


def test_earned_rows_resolve_the_floor_and_the_earned_hard_cap() -> None:
    _mirror(1, trust_class=CapacityTrustClass.EARNED, total_cpus=None, total_memory_mb=None)
    b = service.host_budgets_by_node()[node_id(1)]
    assert (b.vcpu_budget, b.memory_budget_mb, b.vm_budget) == (8, 32768, 4)
    _mirror(
        2,
        trust_class=CapacityTrustClass.EARNED,
        earned_vms=200,
        earned_vcpus=64,
        capacity_slots=1000,
    )
    b2 = service.host_budgets_by_node()[node_id(2)]
    assert b2.vm_budget == 64  # VALI_CAPACITY_EARN_HARD_CAP_VMS, not the operator's 96
    assert b2.binding[2] == "vms:hard-cap"


def test_a_per_miner_ratio_overrides_the_global_one() -> None:
    _mirror(1, cpu_ratio=Decimal("1.00"))
    _mirror(2)
    budgets = service.host_budgets_by_node()
    assert budgets[node_id(1)].vcpu_budget == 22
    assert budgets[node_id(2)].vcpu_budget == 44


@override_settings(VALI_SCHEDULER_CPU_OVERCOMMIT="1.0")
def test_the_global_ratio_is_read_from_settings() -> None:
    _mirror(1)
    assert service.host_budgets_by_node()[node_id(1)].vcpu_budget == 22


def test_committed_load_is_vali_ledger_times_the_flavor_table() -> None:
    _mirror(1)
    _place(1, 2, "xlarge")
    _place(1, 1, "std", start=5)  # unknown class counts as the reference slot
    b = service.host_budgets_by_node()[node_id(1)]
    ref_cpus, ref_mb = service._slot_ref_cpus(), service._slot_ref_memory_mb()
    assert b.free_vcpus == 44 - 2 * 8 - ref_cpus
    assert b.free_memory_mb == 384_395 - 8192 - 2 * (32768 + 256) - (ref_mb + 256)
    assert b.free_vms == 64 - 3


# ─── gate (a) enforced ──────────────────────────────────────────────


@ENFORCE
def test_enforced_refuses_a_host_the_flavor_does_not_fit() -> None:
    """miner 1 has v1 slots to spare but only 8 vCPU left; a 2xlarge
    (16 vCPU) must go to miner 2."""
    for s in (1, 2):
        make_dispatchable_identity(s)
    _mirror(1, total_cpus=6, capacity_slots=64)  # (6 − 2) × 2 = 8 vCPU
    _mirror(2)
    assert _decide("2xlarge", 1, 2) == node_id(2)
    assert _decide("small", 1) == node_id(1)


@ENFORCE
def test_enforced_admits_past_the_v1_slot_count() -> None:
    """v1 (slot ref 2 vCPU at 1:1) would call a 24-thread host full at 11;
    v2 at 2:1 still fits a small."""
    make_dispatchable_identity(1)
    _mirror(1)
    _place(1, 20, "small")
    cap, load, _ = service.decision_inputs("tenant-x")
    assert cap[node_id(1)] - load[node_id(1)] <= 0  # v1 says full
    assert _decide("small", 1) == node_id(1)


@ENFORCE
def test_enforced_refuses_when_nothing_fits() -> None:
    make_dispatchable_identity(1)
    _mirror(1, capacity_slots=2)
    _place(1, 2, "small")
    with pytest.raises(PlacementError):
        _decide("small", 1)


def test_a_node_absent_from_the_fit_map_is_refused_when_enforced() -> None:
    snapshot = make_snapshot(10, [make_miner(1)])
    fit = ResourceFit("small", fits_by_node={}, free_fraction_by_node={}, enforce=True)
    with pytest.raises(PlacementError):
        decide_placement(
            snapshot=snapshot,
            capacity_by_node={node_id(1): 8},
            load_by_node={},
            family_load_by_node={},
            max_epoch_lag=5,
            resource_fit=fit,
        )


def test_enforced_ranking_uses_the_free_fraction() -> None:
    """v1 slots say miner 1 is emptier; v2 says miner 2 is. v2 decides."""
    snapshot = make_snapshot(10, [make_miner(1), make_miner(2)])
    args = dict(
        snapshot=snapshot,
        capacity_by_node={node_id(1): 10, node_id(2): 10},
        load_by_node={node_id(1): 0, node_id(2): 9},
        family_load_by_node={},
        max_epoch_lag=5,
    )
    assert decide_placement(**args) == node_id(1)  # v1
    fit = ResourceFit(
        "small",
        fits_by_node={node_id(1): True, node_id(2): True},
        free_fraction_by_node={node_id(1): 0.1, node_id(2): 0.9},
        enforce=True,
    )
    assert decide_placement(**args, resource_fit=fit) == node_id(2)


# ─── shadow ─────────────────────────────────────────────────────────


def _shadow_lines(caplog: pytest.LogCaptureFixture) -> list[dict[str, object]]:
    return [
        json.loads(r.getMessage().split(": ", 1)[1])
        for r in caplog.records
        if r.name == "apps.scheduler.placement" and "capacity-v2 shadow" in r.getMessage()
    ]


def test_shadow_keeps_v1_deciding_and_logs_the_disagreement(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.INFO, logger="apps.scheduler.placement")
    for s in (1, 2):
        make_dispatchable_identity(s)
    _mirror(1, total_cpus=6)  # v2: 8 vCPU — a 2xlarge does not fit
    _mirror(2)
    # v1 picks the lowest node id among equals: miner 1, although v2 would not.
    assert _decide("2xlarge", 1, 2) == node_id(1)
    [line] = _shadow_lines(caplog)
    assert line["chosen"] == node_id(1)
    assert line["chosen_fits_v2"] is False
    assert line["disagree"] == [node_id(1)]
    assert line["resource_class"] == "2xlarge"


def test_shadow_logs_a_refusal_too(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.INFO, logger="apps.scheduler.placement")
    make_dispatchable_identity(1)
    _mirror(1, capacity_slots=1)
    _place(1, 1, "small")
    with pytest.raises(PlacementError):
        _decide("small", 1)
    [line] = _shadow_lines(caplog)
    assert line["chosen"] is None


@ENFORCE
def test_no_shadow_line_once_enforced(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.INFO, logger="apps.scheduler.placement")
    make_dispatchable_identity(1)
    _mirror(1)
    _decide("small", 1)
    assert _shadow_lines(caplog) == []


def test_placement_arguments_carry_the_flavor_fit() -> None:
    make_dispatchable_identity(1)
    _mirror(1, total_cpus=6)
    args = service.placement_arguments(
        snapshot=make_snapshot(10, []), tenant_id="t", user_id="u", flavor="2xlarge"
    )
    fit = args["resource_fit"]
    assert fit.resource_class == "2xlarge"
    assert fit.fits_by_node[node_id(1)] is False
    assert fit.enforce is False


# ─── feasibility on v2 ──────────────────────────────────────────────


@pytest.fixture
def v2_fleet(monkeypatch: pytest.MonkeyPatch) -> None:
    observe_chain_epoch(10)
    make_dispatchable_identity(1)
    _mirror(1, declared_memory_mb_budget=98304, declared_at=timezone.now())
    monkeypatch.setattr(chain, "read_miner_status", lambda: make_snapshot(10, [make_miner(1)]))


@ENFORCE
def test_feasibility_headroom_matches_what_admission_takes(v2_fleet: None) -> None:
    result = feasibility.assess("small")
    assert result.verdict == "yes"
    # RAM binds: 98304 // (4096 + 256) = 22 smalls (vCPU would allow 44).
    assert result.headroom == 22
    [host] = result.hosts
    assert (host.free_vms, host.headroom) == (64, 22)
    _place(1, 22, "small")
    after = feasibility.assess("small")
    assert (after.verdict, after.headroom) == ("not-now", 0)
    assert "memory" in after.hosts[0].shortfall


@ENFORCE
def test_feasibility_never_when_wider_than_the_hosts_threads(v2_fleet: None) -> None:
    MinerCapacity.objects.update(total_cpus=12)  # 10 usable threads, 20 vCPU at 2:1
    result = feasibility.assess("2xlarge")  # 16 vCPU > 10 threads
    assert result.verdict == "never"
    assert "threads" in result.hosts[0].shortfall


def test_feasibility_stays_on_v1_while_the_flag_is_off(v2_fleet: None) -> None:
    result = feasibility.assess("small")
    [host] = result.hosts
    assert host.free_vms is None and host.headroom is None


# ─── the report ─────────────────────────────────────────────────────


@override_settings(VALI_SCHEDULER_SLOT_REF_CPUS=2, VALI_SCHEDULER_SLOT_REF_MEMORY_MB=8192)
def test_report_shows_v1_and_v2_side_by_side() -> None:
    from io import StringIO

    from django.core.management import call_command

    make_dispatchable_identity(1)
    _mirror(1, declared_memory_mb_budget=98304, declared_at=timezone.now())
    _place(1, 2, "2xlarge")
    out = StringIO()
    call_command("vali_capacity_report", "--json", stdout=out)
    [row] = json.loads(out.getvalue())
    assert row["dispatchable"] is True
    assert row["v2_binding"] == ["vcpu:anchor", "memory:declared", "vms:ceiling"]
    # 2 × 2xlarge = 16 units committed out of an 11-unit RAM-bound budget:
    # free clamps to 0, committed = total.
    assert row["v2_units"] == {"total": 11, "committed": 11, "free": 0}
    assert row["headroom"]["small"][1] == 0
    text = StringIO()
    call_command("vali_capacity_report", stdout=text)
    assert "bound by vcpu:anchor, memory:declared, vms:ceiling" in text.getvalue()


@override_settings(VALI_SCHEDULER_SLOT_REF_CPUS=2, VALI_SCHEDULER_SLOT_REF_MEMORY_MB=8192)
def test_show_prints_the_v2_breakdown() -> None:
    from io import StringIO

    from django.core.management import call_command

    _mirror(1)
    out = StringIO()
    call_command("vali_set_miner_capacity", "--node-id", node_id(1), "--show", stdout=out)
    assert "v2  budget 44 vCPU" in out.getvalue()
    assert "units  total 22" in out.getvalue()


def test_0014_rebackfill_promotes_only_fully_anchored_earned_rows() -> None:
    import importlib

    from django.apps import apps as django_apps

    full = _mirror(1, trust_class=CapacityTrustClass.EARNED)
    half = _mirror(2, trust_class=CapacityTrustClass.EARNED, total_cpus=None)
    bare = _mirror(3, trust_class=CapacityTrustClass.EARNED, total_cpus=None, total_memory_mb=None)
    importlib.import_module(
        "apps.scheduler.migrations.0014_capacity_v2_rebackfill"
    )._forward(django_apps, None)
    for row, want in ((full, "operator"), (half, "earned"), (bare, "earned")):
        row.refresh_from_db()
        assert row.trust_class == want


# ─── review follow-ups ──────────────────────────────────────────────


def test_a_shadow_failure_never_blocks_a_v1_placement(monkeypatch: pytest.MonkeyPatch) -> None:
    make_dispatchable_identity(1)
    _mirror(1)

    def boom(**_kw: object) -> None:
        raise RuntimeError("budget assembly broke")

    monkeypatch.setattr(service, "host_budgets_by_node", boom)
    assert service.resource_fit("small") is None
    assert _decide("small", 1) == node_id(1)


@ENFORCE
def test_an_enforced_failure_refuses_instead_of_waving_through(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def boom(**_kw: object) -> None:
        raise RuntimeError("budget assembly broke")

    monkeypatch.setattr(service, "host_budgets_by_node", boom)
    with pytest.raises(RuntimeError):
        service.resource_fit("small")


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("VALI_SCHEDULER_CPU_OVERCOMMIT", "two"),
        ("VALI_SCHEDULER_RESOURCE_ADMISSION", "ture"),
        ("VALI_CAPACITY_EARN_FLOOR_VMS", "-3"),
    ],
)
def test_capacity_knobs_are_validated_when_the_app_loads(name: str, value: str) -> None:
    from django.apps import apps
    from django.core.exceptions import ImproperlyConfigured

    with override_settings(**{name: value}), pytest.raises(ImproperlyConfigured, match=name):
        apps.get_app_config("scheduler").ready()


def test_an_earned_ceiling_of_zero_is_zero_not_the_floor() -> None:
    _mirror(
        1,
        trust_class=CapacityTrustClass.EARNED,
        total_cpus=None,
        total_memory_mb=None,
        earned_vms=0,
        earned_vcpus=0,
        earned_memory_mb=0,
    )
    b = service.host_budgets_by_node()[node_id(1)]
    assert (b.vm_budget, b.vcpu_budget, b.memory_budget_mb) == (0, 0, 0)


@override_settings(VALI_SCHEDULER_SLOT_REF_CPUS=2, VALI_SCHEDULER_SLOT_REF_MEMORY_MB=8192)
def test_preflight_flags_hosts_the_flip_would_strand() -> None:
    from io import StringIO

    from django.core.management import CommandError, call_command

    for s in (1, 2, 3, 4):
        make_dispatchable_identity(s)
    _mirror(1)  # fine
    _mirror(2, total_cpus=None)  # operator, half anchor
    _mirror(3, trust_class=CapacityTrustClass.EARNED, total_cpus=None, total_memory_mb=None)
    _mirror(4, cpu_ratio=Decimal("1.00"))
    _place(4, 12, "medium")  # 24 vCPU on a 22-vCPU 1:1 budget
    from apps.scheduler.capacity_report import fleet_report, preflight_issues

    reports = {r.node_id: r for r in fleet_report()}

    assert preflight_issues(reports[node_id(1)]) == []
    assert preflight_issues(reports[node_id(2)]) == ["v2-unknown"]
    assert preflight_issues(reports[node_id(3)]) == ["v2-earned-floor"]
    assert "v2-over-committed" in preflight_issues(reports[node_id(4)])
    with pytest.raises(CommandError, match="preflight FAILED"):
        call_command("vali_capacity_report", "--preflight", stdout=StringIO())


def test_preflight_passes_on_a_healthy_fleet() -> None:
    from io import StringIO

    from django.core.management import call_command

    make_dispatchable_identity(1)
    _mirror(1)
    out = StringIO()
    call_command("vali_capacity_report", "--preflight", stdout=out)
    assert "preflight: OK" in out.getvalue()


def test_shadow_never_changes_the_v1_decision() -> None:
    """Randomized: the same inputs with an UNENFORCED ResourceFit (random
    fit map, random fractions) choose exactly what v1 alone chooses."""
    import random

    rng = random.Random(1263)
    for _ in range(400):
        n = rng.randint(1, 6)
        seeds = list(range(1, n + 1))
        snapshot = make_snapshot(10, [make_miner(s, quality=rng.randint(0, 5)) for s in seeds])
        args = dict(
            snapshot=snapshot,
            capacity_by_node={node_id(s): rng.randint(0, 8) for s in seeds},
            load_by_node={node_id(s): rng.randint(0, 8) for s in seeds},
            family_load_by_node={node_id(s): rng.randint(0, 2) for s in seeds},
            max_epoch_lag=5,
            max_host_share=rng.choice([1.0, 0.5]),
        )
        fit = ResourceFit(
            "small",
            fits_by_node={node_id(s): rng.random() < 0.5 for s in seeds},
            free_fraction_by_node={node_id(s): rng.random() for s in seeds},
            enforce=False,
            shadow_log=False,
        )
        try:
            v1 = decide_placement(**args)
        except PlacementError:
            v1 = None
        try:
            shadowed = decide_placement(**args, resource_fit=fit)
        except PlacementError:
            shadowed = None
        assert shadowed == v1
