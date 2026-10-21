"""Self-service sizing of an unanchored `earned` miner
(`VALI_CAPACITY_DECLARED_CEILING`): the declared hardware ceiling bounds
growth and never grants it, corroborated guest-attested shortfalls lower
the earned ceiling, at-floor faults land a strike, and feasibility says
what its answer rests on.

Each test names the claim it defends; breaking the claim must fail it."""

from __future__ import annotations

from datetime import timedelta

import pytest
from django.test import override_settings
from django.utils import timezone

from apps.lifecycle.models import Vm
from apps.scheduler import capacity, capacity_earn, chain, feasibility, service
from apps.scheduler.capacity_admin import STRIKE_FIELD
from apps.scheduler.capacity_earn import Sample
from apps.scheduler.models import (
    CapacityTrustClass,
    MinerCapacity,
    MinerCapacityAudit,
    MinerStatusMirror,
    PlacementStatus,
)
from apps.telemetry.models import GuestResourceShortfall

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

NODE = node_id(7)
CEILING_ON = override_settings(VALI_CAPACITY_DECLARED_CEILING=True)
FULL_FLOOR = Sample(vms=4, vcpus=8, memory_mb=32768)


def _row(**over: object) -> MinerCapacity:
    fields: dict[str, object] = dict(
        miner_node_id=NODE,
        status="active",
        capacity_slots=64,
        observed_epoch=10,
        data_epoch=10,
        refreshed_at=timezone.now(),
        trust_class=CapacityTrustClass.EARNED,
    )
    fields.update(over)
    return MinerCapacity.objects.create(**fields)


def _declared(vcpus: int | None, memory_mb: int | None, asid: int | None) -> dict[str, object]:
    return dict(
        declared_cpu_budget=vcpus,
        declared_memory_mb_budget=memory_mb,
        declared_asid_capacity=asid,
        declared_at=timezone.now(),
    )


def _ceiling() -> tuple[int | None, int | None, int | None]:
    r = MinerCapacity.objects.get(miner_node_id=NODE)
    return (r.earned_vms, r.earned_vcpus, r.earned_memory_mb)


def _hold(sample: Sample) -> capacity_earn.EarnReport:
    """Hold `sample` for a full proof window (two ticks 31 min apart)."""
    t0 = timezone.now()
    capacity_earn.tick(now=t0, sampler=lambda _n, _a: sample)
    return capacity_earn.tick(now=t0 + timedelta(minutes=31), sampler=lambda _n, _a: sample)


# ─── the ceiling bounds growth ──────────────────────────────────────


def test_flag_off_growth_ignores_the_declaration() -> None:
    """Claim: default off ⇒ byte-identical growth (inert flag)."""
    _row(**_declared(10, 40000, 9))
    _hold(FULL_FLOOR)
    assert _ceiling() == (6, 12, 49152)


@CEILING_ON
def test_growth_stops_at_the_declared_ceiling() -> None:
    """Claim: a held proof never lifts a ceiling past the declared hardware.
    Declared 10 vCPU / 40000 MiB / 9 ASIDs (− 3 reserve = 6 VMs)."""
    _row(**_declared(10, 40000, 9))
    _hold(FULL_FLOOR)
    # Unbounded growth would be 6 / 12 / 49152.
    assert _ceiling() == (6, 10, 40000)


@CEILING_ON
def test_a_dimension_with_no_ceiling_signal_does_not_grow() -> None:
    """Claim: no hardware figure ⇒ no growth (never the hard cap)."""
    _row(**_declared(None, 40000, None))
    _hold(FULL_FLOOR)
    floor_vms, floor_vcpus = 4, 8
    assert _ceiling() == (floor_vms, floor_vcpus, 40000)


@CEILING_ON
def test_a_low_declaration_never_lowers_the_earned_ceiling() -> None:
    """Claim: the ceiling only stops growth; it never cuts what was earned
    (the budget already takes a fresh declaration as a `min` term)."""
    _row(earned_vms=10, earned_vcpus=20, earned_memory_mb=81920, **_declared(4, 16384, 5))
    _hold(Sample(vms=10, vcpus=20, memory_mb=81920))
    assert _ceiling() == (10, 20, 81920)


@CEILING_ON
def test_the_declaration_alone_grants_nothing() -> None:
    """Claim: lying high gains nothing without held proof."""
    _row(**_declared(256, 1024 * 1024, 509))
    assert capacity_earn.tick().grown == 0  # VALI_CAPACITY_EARN_PROOF=off
    assert _ceiling() == (None, None, None)
    _hold(Sample(vms=1, vcpus=2, memory_mb=8192))  # proof below the fill trigger
    assert _ceiling() == (None, None, None)


@CEILING_ON
def test_the_anchor_is_one_more_ceiling_term() -> None:
    """Claim: the most conservative figure wins — an anchor below the
    declaration bounds growth. (24 − 2 reserved threads) × 1.0 = 22 vCPU is
    above the declaration; 30000 − 8192 = 21808 MiB is below it."""
    _row(
        total_cpus=24,
        total_memory_mb=30000,
        cpu_ratio="1.00",
        **_declared(10, 40000, 9),
    )
    ceiling = capacity_earn.hardware_ceiling(MinerCapacity.objects.get())
    assert ceiling == {"vms": 6, "vcpus": 10, "memory_mb": 21808}


def test_a_stale_declaration_still_bounds_growth() -> None:
    """Claim: the miner's last word is its ceiling, fresh or not (a stale
    figure must not lift the bound to the hard caps)."""
    row = _row(**_declared(10, 40000, 9))
    MinerCapacity.objects.filter(pk=row.pk).update(declared_at=timezone.now() - timedelta(days=3))
    assert capacity_earn.hardware_ceiling(MinerCapacity.objects.get())["vcpus"] == 10


@CEILING_ON
def test_operator_rows_are_never_grown_or_bounded() -> None:
    _row(trust_class=CapacityTrustClass.OPERATOR, total_cpus=24, total_memory_mb=125000)
    _hold(FULL_FLOOR)
    assert _ceiling() == (None, None, None)


# ─── guest-attested shortfalls ──────────────────────────────────────


def _short(
    vm_id: str,
    tenant: str,
    *,
    node: str = NODE,
    seen_ago_s: int = 60,
    reason: str = "mem-firmware",
) -> None:
    vm = make_vm(vm_id, f"lease-{vm_id}")
    Vm.objects.filter(pk=vm.pk).update(tenant_id=tenant)
    seen = timezone.now() - timedelta(seconds=seen_ago_s)
    GuestResourceShortfall.objects.create(
        vm_id=vm_id,
        node_id_hex=node,
        flavor="medium",
        want_vcpus=2,
        want_memory_mb=8192,
        vcpus_online=2,
        mem_firmware_kib=4 * 1024 * 1024,
        reason=reason,
        first_seen_at=seen,
        last_seen_at=seen,
        last_body_digest="ab" * 32,
    )


BIG = dict(earned_vms=20, earned_vcpus=40, earned_memory_mb=163840)


@CEILING_ON
def test_one_tenant_alone_cannot_shrink_a_miner() -> None:
    """Claim: root inside one tenant's guests can forge figures, so one
    tenant (however many VMs) is never enough."""
    _row(**BIG)
    _short("vm-a1", "tenant-a")
    _short("vm-a2", "tenant-a")
    assert capacity_earn.tick().shortfall_penalties == 0
    assert _ceiling() == (20, 40, 163840)


@CEILING_ON
def test_two_tenants_short_halve_the_ceiling_once_per_tenant_set() -> None:
    """Claim: corroborated evidence costs the START_FAILED decrease, once
    per distinct tenant SET, audited as `event:guest-resource-short`."""
    _row(**BIG)
    _short("vm-a", "tenant-a", seen_ago_s=120)
    _short("vm-b", "tenant-b")
    assert capacity_earn.tick().shortfall_penalties == 1
    assert _ceiling() == (10, 20, 81920)
    audit = MinerCapacityAudit.objects.get(actor="event:guest-resource-short", field="earned_vms")
    assert "tenant-a" not in audit.reason  # tenant ids stay out of the audit
    assert capacity_earn.tick().shortfall_penalties == 0  # same evidence
    assert _ceiling() == (10, 20, 81920)
    _short("vm-c", "tenant-c", seen_ago_s=0)
    assert capacity_earn.tick().shortfall_penalties == 1
    assert _ceiling() == (5, 10, 40960)


@CEILING_ON
def test_once_corroborated_more_vms_of_the_same_tenants_cost_nothing() -> None:
    """Claim: a framing tenant cannot turn one corroboration into a halving
    per forged VM."""
    _row(**BIG)
    _short("vm-a", "tenant-a")
    _short("vm-b", "tenant-b")
    capacity_earn.tick()
    for i in range(3):
        _short(f"vm-a{i}", "tenant-a", seen_ago_s=0)
        assert capacity_earn.tick().shortfall_penalties == 0
    assert _ceiling() == (10, 20, 81920)


@CEILING_ON
def test_a_superseded_launch_is_not_a_shortfall() -> None:
    """Claim: only RESOURCE findings count — a stale launch says nothing
    about the hardware."""
    _row(**BIG)
    _short("vm-a", "tenant-a", reason="superseded-launch")
    _short("vm-b", "tenant-b", reason="superseded-launch")
    assert capacity_earn.tick().shortfall_penalties == 0


@CEILING_ON
def test_a_vm_without_a_tenant_corroborates_nothing() -> None:
    """Claim: a finding vali cannot attribute to a tenant (blank, or no Vm
    row) is not a second owner."""
    _row(**BIG)
    _short("vm-a", "tenant-a")
    _short("vm-b", "")
    GuestResourceShortfall.objects.create(
        vm_id="vm-gone",
        node_id_hex=NODE,
        flavor="medium",
        want_vcpus=2,
        want_memory_mb=8192,
        reason="vcpus",
        first_seen_at=timezone.now(),
        last_seen_at=timezone.now(),
        last_body_digest="cd" * 32,
    )
    assert capacity_earn.tick().shortfall_penalties == 0


def test_flag_off_shortfalls_cost_nothing() -> None:
    _row(**BIG)
    _short("vm-a", "tenant-a")
    _short("vm-b", "tenant-b")
    assert capacity_earn.tick().shortfall_penalties == 0
    assert _ceiling() == (20, 40, 163840)


@CEILING_ON
def test_only_this_hosts_fresh_findings_count() -> None:
    """Claim: evidence is keyed on vali's own node attribution and must be
    inside the flag window."""
    _row(**BIG)
    _short("vm-a", "tenant-a")
    _short("vm-b", "tenant-b", node=node_id(8))  # another host
    _short("vm-c", "tenant-c", seen_ago_s=7 * 86400)  # long gone
    assert capacity_earn.shortfall_incident(NODE, now=timezone.now()) == ""
    assert capacity_earn.tick().shortfall_penalties == 0


@CEILING_ON
@override_settings(VALI_CAPACITY_SHORTFALL_MIN_OWNERS=3)
def test_the_corroboration_threshold_is_configurable() -> None:
    _row(**BIG)
    _short("vm-a", "tenant-a")
    _short("vm-b", "tenant-b")
    assert capacity_earn.tick().shortfall_penalties == 0
    _short("vm-c", "tenant-c")
    assert capacity_earn.tick().shortfall_penalties == 1


@override_settings(VALI_CAPACITY_SHORTFALL_MIN_OWNERS=1)
def test_a_single_tenant_threshold_is_refused_loudly() -> None:
    from django.core.exceptions import ImproperlyConfigured

    from apps.scheduler import capacity_config

    with pytest.raises(ImproperlyConfigured):
        capacity_config.shortfall_min_owners()


@CEILING_ON
def test_shortfalls_never_take_a_miner_below_the_floor() -> None:
    _row()
    _short("vm-a", "tenant-a")
    _short("vm-b", "tenant-b")
    capacity_earn.tick()
    assert _ceiling() == (4, 8, 32768)  # resolved to the floor, never below


# ─── strikes ────────────────────────────────────────────────────────


def _strikes() -> list[tuple[str, str]]:
    return list(
        MinerCapacityAudit.objects.filter(field=STRIKE_FIELD).values_list("actor", "reason")
    )


@CEILING_ON
def test_an_at_floor_fault_lands_one_strike_per_incident() -> None:
    _row(earned_vms=4, earned_vcpus=8, earned_memory_mb=32768)
    for _ in range(3):
        assert not capacity_earn.record_event(NODE, capacity_earn.START_FAILED, incident="vm=vm-1")
    assert _strikes() == [("event:start-failed", "start-failed vm=vm-1")]


def test_flag_off_no_strike() -> None:
    _row(earned_vms=4, earned_vcpus=8, earned_memory_mb=32768)
    capacity_earn.record_event(NODE, capacity_earn.START_FAILED, incident="vm=vm-1")
    assert _strikes() == []


@CEILING_ON
def test_an_incident_less_event_never_strikes() -> None:
    """Claim: strikes are idempotent — the tick's incapable reset (no
    incident) must not strike an at-floor miner every pass."""
    _row(earned_vms=4, earned_vcpus=8, earned_memory_mb=32768)
    for _ in range(3):
        capacity_earn.record_event(NODE, capacity_earn.CVM_INCAPABLE)
    assert _strikes() == []


@CEILING_ON
def test_an_honest_preflight_refusal_is_never_a_strike() -> None:
    _row(earned_vms=0, earned_vcpus=0, earned_memory_mb=0)
    capacity_earn.record_event(NODE, capacity_earn.PREFLIGHT_INSUFFICIENT, incident="vm=vm-1")
    assert _strikes() == []


# ─── budget source + feasibility ────────────────────────────────────


def test_the_budget_names_its_source() -> None:
    _row(**_declared(10, 40000, 9))
    operator = node_id(8)
    MinerCapacity.objects.create(
        miner_node_id=operator,
        status="active",
        capacity_slots=64,
        observed_epoch=10,
        data_epoch=10,
        refreshed_at=timezone.now(),
        trust_class=CapacityTrustClass.OPERATOR,
        total_cpus=24,
        total_memory_mb=125000,
    )
    unanchored_operator = node_id(9)
    MinerCapacity.objects.create(
        miner_node_id=unanchored_operator,
        status="active",
        capacity_slots=64,
        observed_epoch=10,
        data_epoch=10,
        refreshed_at=timezone.now(),
        trust_class=CapacityTrustClass.OPERATOR,
    )
    undeclared = node_id(10)
    MinerCapacity.objects.create(
        miner_node_id=undeclared,
        status="active",
        capacity_slots=64,
        observed_epoch=10,
        data_epoch=10,
        refreshed_at=timezone.now(),
        trust_class=CapacityTrustClass.EARNED,
    )
    budgets = service.host_budgets_by_node()
    assert budgets[NODE].source == capacity.SOURCE_DECLARED_EARNED
    assert budgets[undeclared].source == capacity.SOURCE_EARNED
    assert budgets[undeclared].known  # the floor still sizes it
    assert budgets[operator].source == capacity.SOURCE_TRUSTED
    assert budgets[unanchored_operator].source == capacity.SOURCE_UNKNOWN
    assert not budgets[unanchored_operator].known


def _fleet(monkeypatch: pytest.MonkeyPatch, *, earned_seed: int, anchored_seed: int | None) -> None:
    observe_chain_epoch(10)
    seeds = [earned_seed]
    make_dispatchable_identity(earned_seed)
    MinerCapacity.objects.create(
        miner_node_id=node_id(earned_seed),
        status=MinerStatusMirror.ACTIVE,
        capacity_slots=64,
        observed_epoch=10,
        data_epoch=10,
        refreshed_at=timezone.now(),
        trust_class=CapacityTrustClass.EARNED,
        **_declared(10, 40000, 9),
    )
    if anchored_seed is not None:
        seeds.append(anchored_seed)
        make_dispatchable_identity(anchored_seed)
        MinerCapacity.objects.create(
            miner_node_id=node_id(anchored_seed),
            status=MinerStatusMirror.ACTIVE,
            capacity_slots=64,
            observed_epoch=10,
            data_epoch=10,
            refreshed_at=timezone.now(),
            trust_class=CapacityTrustClass.OPERATOR,
            total_cpus=24,
            total_memory_mb=125000,
        )
    snapshot = make_snapshot(10, [make_miner(s) for s in seeds])
    monkeypatch.setattr(chain, "read_miner_status", lambda: snapshot)


@override_settings(VALI_SCHEDULER_RESOURCE_ADMISSION=True)
def test_feasibility_sizes_an_unanchored_earned_miner_and_says_so(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Claim: under v2 an unanchored earned miner is answered from its
    earned floor ∩ declaration — never `size_unknown` — and flagged
    `declared+earned`. small = 1 vCPU / 4 GiB (+256 overhead): floor 4 VMs
    / 8 vCPU / 32 GiB ∩ declared 10 vCPU / 40000 MiB / 6 VMs ⇒ 4."""
    _fleet(monkeypatch, earned_seed=1, anchored_seed=None)
    result = feasibility.assess("small")
    (host,) = result.hosts
    assert host.size_unknown is False
    assert host.capacity_source == capacity.SOURCE_DECLARED_EARNED
    assert host.headroom == 4
    assert result.verdict == "yes"
    assert result.capacity_source == capacity.SOURCE_DECLARED_EARNED


@override_settings(VALI_SCHEDULER_RESOURCE_ADMISSION=True)
def test_one_self_service_host_makes_the_answer_declared_earned(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _fleet(monkeypatch, earned_seed=1, anchored_seed=2)
    result = feasibility.assess("small")
    sources = {h.node_id: h.capacity_source for h in result.hosts}
    assert sources == {
        node_id(1): capacity.SOURCE_DECLARED_EARNED,
        node_id(2): capacity.SOURCE_TRUSTED,
    }
    assert result.capacity_source == capacity.SOURCE_DECLARED_EARNED


@override_settings(VALI_SCHEDULER_RESOURCE_ADMISSION=True)
def test_an_all_anchored_answer_is_trusted(monkeypatch: pytest.MonkeyPatch) -> None:
    _fleet(monkeypatch, earned_seed=1, anchored_seed=2)
    MinerCapacity.objects.filter(miner_node_id=node_id(1)).update(
        trust_class=CapacityTrustClass.OPERATOR, total_cpus=24, total_memory_mb=125000
    )
    result = feasibility.assess("small")
    assert {h.capacity_source for h in result.hosts} == {capacity.SOURCE_TRUSTED}
    assert result.capacity_source == capacity.SOURCE_TRUSTED


# ─── scheduler integration: earn, bounded by the declaration ────────


@CEILING_ON
@override_settings(VALI_SCHEDULER_RESOURCE_ADMISSION=True)
def test_a_self_service_miner_grows_by_proof_up_to_its_declaration(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """End to end through the scheduler's own budgets: a new miner sells
    the floor; held at full fill it grows, but only to what it declared;
    a failed start then halves it back down."""
    _fleet(monkeypatch, earned_seed=1, anchored_seed=None)
    nid = node_id(1)
    MinerCapacity.objects.filter(miner_node_id=nid).update(
        declared_cpu_budget=10, declared_memory_mb_budget=48000, declared_asid_capacity=11
    )
    # medium = 2 vCPU / 8 GiB + 256 MiB overhead: RAM binds, 32768 // 8448 = 3.
    assert feasibility.assess("medium").hosts[0].headroom == 3
    for i in range(4):
        make_placement(
            make_vm(f"vm-{i}", f"lease-{i}"),
            nid,
            status=PlacementStatus.BOUND.value,
            resource_class="medium",
        )
    assert feasibility.assess("medium").verdict == "not-now"  # floor is full
    t0 = timezone.now()
    full = Sample(vms=4, vcpus=8, memory_mb=32768)
    capacity_earn.tick(now=t0, sampler=lambda _n, _a: full)
    capacity_earn.tick(now=t0 + timedelta(minutes=31), sampler=lambda _n, _a: full)
    row = MinerCapacity.objects.get(miner_node_id=nid)
    # Unbounded: 6 / 12 / 49152. Declared: 8 VMs (11 − 3), 10 vCPU, 48000.
    assert (row.earned_vms, row.earned_vcpus, row.earned_memory_mb) == (6, 10, 48000)
    b = service.host_budgets_by_node()[nid]
    assert (b.vcpu_budget, b.vm_budget) == (10, 6)
    assert feasibility.assess("medium").hosts[0].headroom == 1  # (10 − 8) vCPU / 2
    capacity_earn.record_event(nid, capacity_earn.START_FAILED, incident="vm=vm-x")
    row.refresh_from_db()
    assert (row.earned_vms, row.earned_vcpus, row.earned_memory_mb) == (4, 8, 32768)
