"""Capacity v2 pure core (`capacity.host_budget` and friends) — no DB.

The claims these defend:

1. Every miner-controlled input (`declared_*`, `reported_free_mib`) can
   only LOWER a budget, a free figure, a fit, a headroom or a unit count.
2. RAM is never overcommitted, at any CPU ratio (SEV-SNP memory is pinned).
3. Admission (`fits`), feasibility (`headroom`) and units agree: N
   successive admissions of a flavor consume exactly its headroom.
4. A flavor consumes units in proportion to its size.
5. No single guest is wider than the host's usable threads.
6. The SEV-ES ASID capacity caps the VM count.
7. The ranking term is size-neutral.
"""

from __future__ import annotations

import random
from dataclasses import replace
from decimal import Decimal

import pytest

from apps.orchestration.services import flavors
from apps.scheduler.capacity import (
    BudgetInputs,
    HostBudget,
    big_enough,
    fits,
    free_fraction,
    headroom,
    host_budget,
    units,
)

OH = 256
UNIT = {"unit_cpus": 2, "unit_memory_mb": 8192}
SIZES = {n: flavors.resolve_flavor(n) for n in flavors.FLAVOR_NAMES}


def _inp(**over: object) -> BudgetInputs:
    """A 24-thread host shape: 24 threads (SMT off), 384 GB, operator-anchored."""
    base: dict[str, object] = dict(
        trust_class="operator",
        total_cpus=24,
        total_memory_mb=384_395,
        cpu_ratio=Decimal("2.0"),
        reserve_cpus=2,
        reserve_memory_mb=8192,
        per_vm_overhead_mb=OH,
        vm_ceiling=48,
        vm_hard_cap=96,
        asid_reserve=3,
        earned_vms=4,
        earned_vcpus=8,
        earned_memory_mb=32768,
        declared_cpu_budget=None,
        declared_memory_mb_budget=None,
        declared_asid_capacity=None,
        reported_free_mib=None,
        committed_vcpus=0,
        committed_memory_mb=0,
        committed_vms=0,
    )
    base.update(over)
    return BudgetInputs(**base)  # type: ignore[arg-type]


def _dims(name: str) -> dict[str, int]:
    return {"cpu_count": SIZES[name].cpu_count, "memory_mb": SIZES[name].memory_mb}


def _admit(inp: BudgetInputs, name: str) -> BudgetInputs:
    s = SIZES[name]
    return replace(
        inp,
        committed_vcpus=inp.committed_vcpus + s.cpu_count,
        committed_memory_mb=inp.committed_memory_mb + s.memory_mb,
        committed_vms=inp.committed_vms + 1,
    )


# ─── the budget ─────────────────────────────────────────────────────


def test_operator_budget_is_derived_from_the_anchor() -> None:
    b = host_budget(_inp())
    assert b.known
    assert b.vcpu_budget == 44  # (24 − 2) × 2.0
    assert b.memory_budget_mb == 384_395 - 8192  # RAM 1:1
    assert b.vm_budget == 48  # the operator ceiling binds
    assert b.max_vm_vcpus == 22  # usable threads, not the overcommitted budget
    assert b.binding == ("vcpu:anchor", "memory:anchor", "vms:ceiling")


def test_the_ratio_is_floored() -> None:
    assert host_budget(_inp(cpu_ratio=Decimal("1.5"), total_cpus=25)).vcpu_budget == 34  # 23 × 1.5


def test_operator_row_without_a_complete_anchor_is_unknown() -> None:
    for over in ({"total_cpus": None}, {"total_memory_mb": None}):
        b = host_budget(_inp(**over))
        assert not b.known
        assert not fits(b, **_dims("small"))
        assert not big_enough(b, **_dims("small"))
        assert units(b, **UNIT).total == 0
        assert free_fraction(b) == 0.0


def test_earned_budget_is_the_earned_ceiling() -> None:
    b = host_budget(_inp(trust_class="earned", total_cpus=None, total_memory_mb=None))
    assert (b.vcpu_budget, b.memory_budget_mb, b.vm_budget) == (8, 32768, 4)
    assert b.max_vm_vcpus == 8  # no trusted thread count: its whole budget
    assert b.binding == ("vcpu:earned", "memory:earned", "vms:earned")


def test_an_anchor_on_an_earned_row_is_an_extra_clamp_only() -> None:
    b = host_budget(
        _inp(trust_class="earned", total_cpus=4, total_memory_mb=16384, earned_vcpus=64)
    )
    assert b.vcpu_budget == 4  # (4 − 2) × 2 = 4 < earned 64
    assert b.memory_budget_mb == 16384 - 8192


def test_declared_budgets_and_asid_clamp_down() -> None:
    b = host_budget(
        _inp(declared_cpu_budget=40, declared_memory_mb_budget=98304, declared_asid_capacity=30)
    )
    assert (b.vcpu_budget, b.memory_budget_mb, b.vm_budget) == (40, 98304, 27)
    assert b.binding == ("vcpu:declared", "memory:declared", "vms:asid")


def test_declared_above_trusted_changes_nothing() -> None:
    honest = host_budget(_inp())
    liar = host_budget(
        _inp(
            declared_cpu_budget=10_000,
            declared_memory_mb_budget=10_000_000,
            declared_asid_capacity=10_000,
            reported_free_mib=10_000_000,
        )
    )
    assert (liar.vcpu_budget, liar.memory_budget_mb, liar.vm_budget) == (
        honest.vcpu_budget,
        honest.memory_budget_mb,
        honest.vm_budget,
    )
    assert (liar.free_vcpus, liar.free_memory_mb, liar.free_vms) == (
        honest.free_vcpus,
        honest.free_memory_mb,
        honest.free_vms,
    )
    assert liar.over_claim is True  # the alarm still fires


def test_reported_free_throttles_down_only() -> None:
    assert host_budget(_inp(reported_free_mib=4000)).free_memory_mb == 4000
    assert not fits(host_budget(_inp(reported_free_mib=4000)), **_dims("small"))


def test_overhead_is_charged_per_vm() -> None:
    b = host_budget(_inp(committed_vms=3, committed_memory_mb=3 * 4096, committed_vcpus=3))
    assert b.free_memory_mb == 384_395 - 8192 - 3 * (4096 + OH)


def test_asid_capacity_is_a_hard_cap_at_99_minus_the_reserve() -> None:
    b = host_budget(_inp(vm_ceiling=1024, vm_hard_cap=1024, declared_asid_capacity=99))
    assert b.vm_budget == 96
    assert b.binding[2] == "vms:asid"


def test_the_widest_guest_never_exceeds_the_vcpu_budget() -> None:
    """A declared budget below the host's threads also narrows the widest
    guest (the readout must not advertise a 22-vCPU VM on a 4-vCPU budget)."""
    assert host_budget(_inp(declared_cpu_budget=4)).max_vm_vcpus == 4


def test_no_guest_is_wider_than_the_hosts_threads_at_any_ratio() -> None:
    b = host_budget(_inp(cpu_ratio=Decimal("4.0")))
    assert b.vcpu_budget == 88
    assert b.max_vm_vcpus == 22
    # 4xlarge (32 vCPU) cannot run here even though 88 vCPU are "free".
    assert not big_enough(b, **_dims("4xlarge"))
    assert headroom(b, **_dims("4xlarge")) == 0
    assert big_enough(b, **_dims("2xlarge"))  # 16 ≤ 22


# ─── admission / feasibility / units agree ──────────────────────────


@pytest.mark.parametrize("name", ["small", "medium", "large", "xlarge", "2xlarge"])
@pytest.mark.parametrize("ratio", ["1.0", "2.0", "4.0"])
@pytest.mark.parametrize("vm_ceiling", [96, 3])
def test_headroom_is_exactly_the_number_of_admissions(
    name: str, ratio: str, vm_ceiling: int
) -> None:
    inp = _inp(cpu_ratio=Decimal(ratio), vm_ceiling=vm_ceiling)
    expected = headroom(host_budget(inp), **_dims(name))
    admitted = 0
    while fits(host_budget(inp), **_dims(name)):
        inp = _admit(inp, name)
        admitted += 1
        assert admitted <= 200
    assert admitted == expected


def test_units_are_resource_true() -> None:
    empty = host_budget(_inp())
    base = units(empty, **UNIT)
    for name, cost in (("2xlarge", 8), ("xlarge", 4), ("large", 2), ("medium", 1)):
        after = units(host_budget(_admit(_inp(), name)), **UNIT)
        assert base.free - after.free == cost, name
        assert after.total == after.committed + after.free
    two_small = units(host_budget(_admit(_admit(_inp(), "small"), "small")), **UNIT)
    assert base.free - two_small.free == 1


def test_units_total_on_the_live_fr_shape() -> None:
    """24 threads at 2:1 and a 98304 MiB declared budget: RAM binds."""
    b = host_budget(_inp(declared_memory_mb_budget=98304))
    assert units(b, **UNIT).total == min(44 // 2, 98304 // (8192 + OH), 48) == 11


def test_free_fraction_is_size_neutral() -> None:
    small = host_budget(_inp(total_cpus=8, total_memory_mb=32768 + 8192))
    big = host_budget(_inp(total_cpus=64, total_memory_mb=256000))
    assert free_fraction(small) == free_fraction(big) == 1.0
    half = host_budget(_inp(committed_vms=24, committed_vcpus=22, committed_memory_mb=0))
    assert free_fraction(half) == pytest.approx(0.5)
    # The VM count alone can be the tightest dimension.
    few_left = host_budget(_inp(committed_vms=45, committed_vcpus=0, committed_memory_mb=0))
    assert free_fraction(few_left) == pytest.approx(3 / 48)


# ─── the invariants, over many random hosts ─────────────────────────


def _outputs(b: HostBudget) -> list[int]:
    out = [
        b.vcpu_budget,
        b.memory_budget_mb,
        b.vm_budget,
        b.max_vm_vcpus,
        b.free_vcpus,
        b.free_memory_mb,
        b.free_vms,
    ]
    for name in SIZES:
        out.append(int(fits(b, **_dims(name))))
        out.append(int(big_enough(b, **_dims(name))))
        out.append(headroom(b, **_dims(name)))
    u = units(b, **UNIT)
    out += [u.total, u.free]
    return out


def _random_inp(rng: random.Random) -> BudgetInputs:
    cpus = rng.choice([4, 8, 16, 24, 32, 64, 96])
    mem = rng.choice([16384, 65536, 125_000, 256_000, 384_395])
    committed = rng.randint(0, 20)
    return _inp(
        trust_class=rng.choice(["operator", "earned"]),
        total_cpus=cpus if rng.random() > 0.1 else None,
        total_memory_mb=mem if rng.random() > 0.1 else None,
        cpu_ratio=Decimal(rng.choice(["1.0", "1.5", "2.0", "3.0", "4.0"])),
        vm_ceiling=rng.randint(1, 96),
        earned_vms=rng.randint(1, 64),
        earned_vcpus=rng.randint(1, 256),
        earned_memory_mb=rng.randint(1024, 512_000),
        committed_vms=committed,
        committed_vcpus=committed * rng.randint(1, 4),
        committed_memory_mb=committed * rng.choice([4096, 8192, 16384]),
    )


_UNTRUSTED = (
    "declared_cpu_budget",
    "declared_memory_mb_budget",
    "declared_asid_capacity",
    "reported_free_mib",
)


def test_no_untrusted_input_can_raise_any_output() -> None:
    """Supplying a claim — any claim, at any size — never raises a single
    output above what the same host gets with the claim absent."""
    rng = random.Random(20260927)
    for _ in range(3000):
        base = _random_inp(rng)
        without = _outputs(host_budget(base))
        field = rng.choice(_UNTRUSTED)
        claim = rng.choice([0, 1, 7, 96, 99, 4096, 98304, 10**7, rng.randint(0, 10**6)])
        with_claim = _outputs(host_budget(replace(base, **{field: claim})))
        assert all(w <= wo for w, wo in zip(with_claim, without, strict=True)), (field, claim)


def test_raising_a_claim_never_raises_any_output() -> None:
    rng = random.Random(7)
    for _ in range(3000):
        base = _random_inp(rng)
        field = rng.choice(_UNTRUSTED)
        lo = rng.randint(0, 10**6)
        hi = lo + rng.randint(0, 10**6)
        out_lo = _outputs(host_budget(replace(base, **{field: lo})))
        out_hi = _outputs(host_budget(replace(base, **{field: hi})))
        # A LOWER claim may cost the miner; a HIGHER one never beats the
        # trusted terms — and can never go above them.
        without = _outputs(host_budget(base))
        assert all(h <= wo for h, wo in zip(out_hi, without, strict=True))
        assert all(lo_ <= hi_ for lo_, hi_ in zip(out_lo, out_hi, strict=True))


def test_ram_is_never_overcommitted_at_any_ratio() -> None:
    rng = random.Random(99)
    names = [n for n in SIZES if n != "4xlarge"]
    for _ in range(300):
        inp = replace(
            _random_inp(rng),
            trust_class="operator",
            total_cpus=rng.choice([24, 64]),
            committed_vms=0,
            committed_vcpus=0,
            committed_memory_mb=0,
        )
        budget = host_budget(inp)
        for _ in range(200):
            name = rng.choice(names)
            if fits(host_budget(inp), **_dims(name)):
                inp = _admit(inp, name)
        used_mem = inp.committed_memory_mb + inp.committed_vms * OH
        assert used_mem <= budget.memory_budget_mb
        assert inp.committed_vcpus <= budget.vcpu_budget
        assert inp.committed_vms <= budget.vm_budget


def test_an_idle_host_reporting_nearly_all_its_ram_is_not_an_over_claim() -> None:
    """The reserve is policy: an idle host's `available` sits between
    `total − reserve` and `total`, honestly. Only more than `total` alarms."""
    assert host_budget(_inp(reported_free_mib=384_395 - 100)).over_claim is False
    assert host_budget(_inp(reported_free_mib=384_395)).over_claim is False
    assert host_budget(_inp(reported_free_mib=384_396)).over_claim is True
