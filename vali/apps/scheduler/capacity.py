"""Untrusted-miner-safe DYNAMIC capacity sizing for the §23 scheduler.

Spec of record: ARCHITECTURE.md §23 (admission bounded by proven
capacity) + the `dynamic-capacity-untrusted-miner` design.

The scheduler's admission bound was a flat static `capacity_slots` per
miner — a miner sat "full" long before its hardware was. This module
sizes the bound from REAL free resources while staying safe under a
**fully untrusted miner**.

The make-or-break invariant
---------------------------

    Self-reported miner data may ONLY REDUCE a miner's effective
    capacity, NEVER increase it past an operator-trusted bound.
    A miner must gain NOTHING by lying.

[`effective_capacity`] enforces this structurally:

1. **Trusted anchor** — `total_memory_mb` / `total_cpus` are
   OPERATOR-REGISTERED config (never self-reported). They are the
   immovable ceiling input. When they are `None` the function returns
   the flat operator `capacity_slots` unchanged (legacy behaviour, zero
   regression for un-seeded miners).

2. **vali-computed committed** — `committed_memory_mb` / `committed_cpus`
   / `committed_slots` are summed by the caller over the VMs **vali
   itself placed** (its own `Placement` ledger × the flavor table). No
   miner trust is involved.

3. **Trusted free** = `total − committed − host_reserve` (clamped ≥ 0).
   This is the CEILING on free capacity, computed entirely from trusted
   data.

4. **Down-only self-report clamp** — the heartbeat `reported_free_mib`
   may only LOWER the free figure:
   `effective_free = min(trusted_free, reported_free)`. A miner
   over-reporting free RAM is capped by vali's own math (step 3), so it
   wins nothing; a miner under-reporting throttles ITSELF down.

5. **Plausibility distrust** — the down-only clamp (step 4) already caps
   any over-report to the trusted value, so `over_claim` is a pure
   OBSERVABILITY alarm decoupled from capacity. It fires ONLY on a
   PHYSICALLY-IMPOSSIBLE claim — `reported_free > total`, i.e. more free
   RAM than the machine has. The host reserve is policy, not memory the
   host OS occupies, so anything up to `total` is plausible (placed VMs
   under-use their nominal RAM; an idle host reports nearly all of it as
   available) and is NOT flagged. The flag never feeds the slot
   computation.

6. **Operator upper clamp** — the result is finally bounded above by
   `operator_max` (`capacity_slots`), so an operator can always cap a
   miner BELOW its computed value.

There is NO path in which `reported_free` raises the returned slot count
above `committed_slots + f(trusted_free)`: it enters only via the two
`min`/clamp steps, both of which move DOWN.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from decimal import Decimal


@dataclass(frozen=True)
class CapacityInputs:
    """Everything [`effective_capacity`] needs — all explicit, so the
    function is pure and unit-testable without a DB.

    - `operator_max`        `capacity_slots` — the operator upper clamp
                            AND the fallback when no trusted anchor is
                            set.
    - `total_memory_mb` /
      `total_cpus`          the operator-registered TRUSTED hardware
                            anchor. `total_memory_mb is None` ⇒ fall
                            back to the flat `operator_max`.
    - `committed_memory_mb` /
      `committed_cpus` /
      `committed_slots`     summed by the caller over the ACTIVE
                            placements vali put on this miner (its own
                            ledger × the flavor table). `committed_slots`
                            is the active-placement COUNT (== `load`).
    - `reported_free_mib`   the miner's last self-reported free RAM
                            (MiB), or `None` when absent / stale. UNTRUSTED
                            — down-only throttle input.
    - `reserve_memory_mb` /
      `reserve_cpus`        host reserve kept for the hypervisor / host
                            OS (never handed to tenant VMs).
    - `slot_ref_memory_mb` /
      `slot_ref_cpus`       the reference-flavor size one admission slot
                            is worth, used to convert free resources into
                            an integer slot count.
    """

    operator_max: int
    total_memory_mb: int | None
    total_cpus: int | None
    committed_memory_mb: int
    committed_cpus: int
    committed_slots: int
    reported_free_mib: int | None
    reserve_memory_mb: int
    reserve_cpus: int
    slot_ref_memory_mb: int
    slot_ref_cpus: int


@dataclass(frozen=True)
class CapacityResult:
    """The computed admission bound + the distrust flag.

    - `slots`       the effective `capacity` slot count to feed
                    `decide_placement` (`free_slots = slots - load`).
    - `dynamic`     `True` when the trusted anchor drove the number
                    (vs the flat `operator_max` fallback).
    - `over_claim`  `True` when the miner's self-report claimed a
                    PHYSICALLY-IMPOSSIBLE amount of free RAM
                    (`> total`). Pure alarm — capacity is
                    already clamped down-only and is unaffected by it.
    - `free_memory_mb` / `free_cpus`
                    the trusted free resources the slot count was
                    DERIVED from, in real units. `None` when there is no
                    trusted anchor (the flat-cap fallback), which is the
                    honest answer: without `total_memory_mb` vali does
                    not know what the host has.

                    These exist so a caller asking "does THIS flavor
                    fit?" reads the very numbers admission used, instead
                    of recomputing `total − committed − reserve`
                    somewhere else and drifting from it. Slots are
                    denominated in the reference flavor, so they cannot
                    answer that question: one placement costs one slot
                    whatever its size, and a flavor larger than the
                    reference looks free when it is not.
    """

    slots: int
    dynamic: bool
    over_claim: bool
    free_memory_mb: int | None = None
    free_cpus: int | None = None
    #: The host's WHOLE tenant budget (`total − reserve`), independent of
    #: what is placed on it. Distinct from `free_*` on purpose: "is this
    #: flavor too big for the hardware" is a question about the budget,
    #: while "is there room right now" is about the free. Judging the
    #: first against the second makes a temporarily-full fleet report a
    #: flavor as permanently impossible.
    budget_memory_mb: int | None = None
    budget_cpus: int | None = None


def effective_capacity(inp: CapacityInputs) -> CapacityResult:
    """Compute the untrusted-miner-safe dynamic admission bound. Pure."""
    # No trusted anchor ⇒ flat static cap (legacy behaviour, no regression).
    if inp.total_memory_mb is None:
        return CapacityResult(
            slots=inp.operator_max, dynamic=False, over_claim=False
        )

    # (3) TRUSTED free from vali's OWN ledger — the immovable ceiling.
    trusted_free_mb = max(
        0, inp.total_memory_mb - inp.committed_memory_mb - inp.reserve_memory_mb
    )

    # (4) Down-only self-report clamp (SECURITY-CRITICAL, unchanged) +
    # (5) plausibility distrust ALARM (observability only — decoupled).
    effective_free_mb = trusted_free_mb
    over_claim = False
    if inp.reported_free_mib is not None:
        # CAPACITY CLAMP — `effective_free = min(trusted_free, reported)`.
        # A report at or below the trusted ceiling is honoured (genuine
        # down-throttle: host processes, fragmentation, …); anything above
        # is capped to the trusted value. This is the invariant — a miner
        # over-reporting gains NOTHING. It feeds the slot computation and
        # is independent of the alarm branch below.
        if inp.reported_free_mib <= trusted_free_mb:
            effective_free_mb = inp.reported_free_mib

        # DISTRUST ALARM (does NOT feed the slot computation) — flag ONLY a
        # PHYSICALLY-IMPOSSIBLE claim: more free RAM than the machine HAS.
        # The host reserve is a POLICY (what vali withholds from tenants),
        # not memory the host OS actually occupies: an idle host
        # legitimately reports far more than `total − reserve` available
        # (raising the reserve to 8192 made every idle host "over-claim"
        # on every scheduler call). Anything up to `total` is plausible;
        # the capacity clamp above is what bounds the miner either way.
        over_claim = inp.reported_free_mib > inp.total_memory_mb

    # (3) TRUSTED free vCPU (self-report never touches CPU — no down-clamp
    # signal for it, so it stays purely trusted).
    if inp.total_cpus is not None:
        trusted_free_cpus = max(
            0, inp.total_cpus - inp.committed_cpus - inp.reserve_cpus
        )
    else:
        trusted_free_cpus = None

    # Convert free resources → additional integer slots, sized by the
    # reference flavor and bounded by BOTH RAM and (trusted) vCPU so
    # neither dimension is oversubscribed.
    free_slots_mem = (
        effective_free_mb // inp.slot_ref_memory_mb
        if inp.slot_ref_memory_mb > 0
        else 0
    )
    if trusted_free_cpus is not None and inp.slot_ref_cpus > 0:
        free_slots_cpu = trusted_free_cpus // inp.slot_ref_cpus
        free_slots = min(free_slots_mem, free_slots_cpu)
    else:
        free_slots = free_slots_mem

    # Dynamic capacity = what is already committed + what still fits.
    # `committed_slots` (the active-placement count) is included so the
    # bound never drops BELOW the current load (no retro-eviction), and
    # `free_slots >= 0` guarantees `slots >= committed_slots`.
    dynamic = inp.committed_slots + int(free_slots)

    # (6) Operator upper clamp — never let the dynamic value exceed the
    # operator-set ceiling (`capacity_slots`); the operator can always
    # bound a miner BELOW its hardware. `operator_max <= 0` ⇒ no ceiling
    # (defensive; the mirror always seeds a positive default).
    slots = min(dynamic, inp.operator_max) if inp.operator_max > 0 else dynamic

    return CapacityResult(
        slots=slots,
        dynamic=True,
        over_claim=over_claim,
        # The SAME `effective_free_mb` / `trusted_free_cpus` the slot
        # arithmetic above consumed — reported verbatim, not recomputed.
        free_memory_mb=int(effective_free_mb),
        free_cpus=None if trusted_free_cpus is None else int(trusted_free_cpus),
        budget_memory_mb=max(0, inp.total_memory_mb - inp.reserve_memory_mb),
        budget_cpus=(
            None
            if inp.total_cpus is None
            else max(0, inp.total_cpus - inp.reserve_cpus)
        ),
    )


# ═══ Disk — the DATA-disk dimension ═════════════════════════════════
#
# Disk cannot be attested (SNP measures memory, not a filesystem), so the
# disk budget is built exactly like RAM's: vali's OWN ledger decides what
# is committed, and every miner-supplied figure is only a term of a `min`.
#
#     budget = min(operator anchor − reserve,       (trusted, optional)
#                  declared `cvm_disk_gb_budget`,    (untrusted, v4 hb)
#                  reported data-fs total − reserve, (untrusted, v4 hb)
#                  earned disk ceiling)              (vali-cut on faults)
#     free   = min(budget − committed, reported data-fs available − reserve)
#
# A missing / 0 / stale term is DROPPED from the min — it can never raise
# the budget above the terms that remain. No term at all ⇒ unknown.

#: How admission applies one host's disk budget (`HostBudget.disk_gate`).
#: `off` — not applied (gate off / record, or enforce + unknown + allow);
#: `apply` — enforce and the budget is known; `deny` — enforce, unknown,
#: and `VALI_SCHEDULER_DISK_UNKNOWN=deny`: nothing fits.
DISK_GATE_OFF = "off"
DISK_GATE_APPLY = "apply"
DISK_GATE_DENY = "deny"


@dataclass(frozen=True)
class DiskInputs:
    """Everything [`disk_budget`] needs — explicit, so it is pure. Every
    miner-controlled value is `None` when absent, 0 or stale.

    - `anchor_total_gb`       operator-registered data-disk size (trusted).
    - `declared_budget_gb`    heartbeat v4 `cvm_disk_gb_budget` (untrusted).
    - `reported_total_gb` / `reported_available_gb`
                              heartbeat v4 statvfs of the data fs (untrusted).
    - `earned_disk_gb`        the vali-cut ceiling (`None` = never cut).
    - `reserve_gb`            kept off the data fs for staging, the image
                              cache, §25 downloads and backup work.
    - `committed_gb`          vali's own ledger: Σ per-VM disk.
    - `overclaim_slack_gb`    tolerance of the over-claim alarm.
    """

    anchor_total_gb: int | None
    declared_budget_gb: int | None
    reported_total_gb: int | None
    reported_available_gb: int | None
    earned_disk_gb: int | None
    reserve_gb: int
    committed_gb: int
    overclaim_slack_gb: int


@dataclass(frozen=True)
class DiskBudget:
    """One host's data-disk budget in GiB. `known=False` ⇒ no term at all:
    every figure is 0 and the gate's unknown policy decides.

    `over_claim` is an ALARM only (see [`disk_budget`]); `binding` names
    the term that set the budget (`disk:declared`, `disk:reported`, …)."""

    known: bool
    budget_gb: int
    committed_gb: int
    free_gb: int
    over_claim: bool = False
    binding: str = ""


DISK_UNKNOWN = DiskBudget(known=False, budget_gb=0, committed_gb=0, free_gb=0)


def disk_budget(inp: DiskInputs) -> DiskBudget:
    """The untrusted-miner-safe data-disk budget of one host. Pure."""
    terms: list[tuple[str, int]] = []
    if inp.anchor_total_gb is not None:
        terms.append(("anchor", inp.anchor_total_gb - inp.reserve_gb))
    if inp.declared_budget_gb is not None:
        # The operator's own `[host] cvm_disk_gb_budget` is ALREADY the
        # tenant commitment: no reserve comes off it.
        terms.append(("declared", inp.declared_budget_gb))
    if inp.reported_total_gb is not None:
        terms.append(("reported", inp.reported_total_gb - inp.reserve_gb))
    if inp.earned_disk_gb is not None:
        terms.append(("earned", inp.earned_disk_gb))
    over_claim = False
    if inp.reported_available_gb is not None:
        # ALARM, not a verdict: per-VM disk files are SPARSE, so the fs
        # only loses space as guests write, and other usage (staging, the
        # image cache, logs) shares it. Less available than vali has
        # committed means the host could not absorb its VMs filling their
        # disks — worth an operator's look, not by itself proof of a lie.
        over_claim = inp.reported_available_gb < inp.committed_gb - inp.overclaim_slack_gb
    if not terms:
        return DiskBudget(
            known=False,
            budget_gb=0,
            committed_gb=inp.committed_gb,
            free_gb=0,
            over_claim=over_claim,
        )
    budget, binding = _tightest("disk", terms)
    free = max(0, budget - inp.committed_gb)
    if inp.reported_available_gb is not None:
        # CAPACITY CLAMP — down-only, as the RAM report: a host whose data
        # fs has less room than the ledger thinks gets fewer placements.
        # The reserve stays off it too: the last GiB of a measured-free fs
        # belong to staging / §25 downloads, not to the next tenant.
        free = min(free, max(0, inp.reported_available_gb - inp.reserve_gb))
    return DiskBudget(
        known=True,
        budget_gb=budget,
        committed_gb=inp.committed_gb,
        free_gb=free,
        over_claim=over_claim,
        binding=binding,
    )


def disk_gate_state(d: DiskBudget, *, mode: str, unknown: str) -> str:
    """How the gate applies `d` under `mode` (`off|record|enforce`) and
    the `unknown` policy (`allow|deny`) — see `DISK_GATE_*`. Record is
    never applied: it only reports what enforce would refuse."""
    if mode != "enforce":
        return DISK_GATE_OFF
    if d.known:
        return DISK_GATE_APPLY
    return DISK_GATE_DENY if unknown == "deny" else DISK_GATE_OFF


def disk_admits(d: DiskBudget, state: str, *, disk_gb: int, ever: bool = False) -> bool:
    """Does the disk dimension admit one more VM needing `disk_gb`?
    `ever=True` asks against the whole budget (hardware big enough)
    instead of what is free now."""
    if state == DISK_GATE_OFF:
        return True
    if state == DISK_GATE_DENY:
        return False
    return disk_gb <= (d.budget_gb if ever else d.free_gb)


def disk_headroom(d: DiskBudget, state: str, *, disk_gb: int) -> int:
    """How many VMs needing `disk_gb` the disk dimension still takes; a
    large sentinel when the gate does not apply (it bounds nothing)."""
    if state == DISK_GATE_DENY:
        return 0
    if state == DISK_GATE_OFF or disk_gb <= 0:
        return _NO_BOUND
    return d.free_gb // disk_gb


_NO_BOUND = 1 << 31


# ═══ Capacity v2 — resource-true budgets ════════════════════════════
#
# v1 above sizes an admission SLOT count; one placement costs one slot
# whatever its flavor. v2 accounts in real units — vCPU, RAM (+ a per-VM
# overhead), VM count — so a `2xlarge` consumes what it actually uses.
#
# The invariant is v1's, extended to every new untrusted input:
#
#     Every miner-controlled value (`declared_*`, `reported_free_mib`)
#     enters ONLY as a term of a `min`. None of them can raise a budget,
#     a free figure, a fit, a headroom or a unit count.
#
# Trusted terms: the operator anchor (`operator` class), the earned
# ceiling vali itself computed from attested proof (`earned` class), the
# operator VM ceiling, the configured hard caps. vali's own Placement
# ledger × the flavor table gives the committed load.


@dataclass(frozen=True)
class BudgetInputs:
    """Everything [`host_budget`] needs — explicit, so it is pure.

    - `trust_class`       `operator` | `earned`.
    - `total_cpus` / `total_memory_mb`
                          the operator anchor (may be None). For an
                          `operator` row it IS the budget source; for an
                          `earned` row it is only an extra clamp.
    - `cpu_ratio`         vCPU:thread overcommit applied to
                          `total_cpus − reserve_cpus`. RAM has no ratio.
    - `vm_ceiling`        the operator VM-count ceiling (`capacity_slots`).
    - `vm_hard_cap`       the configured VM cap for this trust class.
    - `earned_*`          the earned ceiling, floor already resolved.
    - `declared_*` / `reported_free_mib`
                          UNTRUSTED, fresh-only (None when absent/stale).
    - `committed_*`       vali's own ledger: Σ flavor vCPU, Σ flavor RAM
                          (the overhead is added here, per VM), VM count.
    """

    trust_class: str
    total_cpus: int | None
    total_memory_mb: int | None
    cpu_ratio: Decimal
    reserve_cpus: int
    reserve_memory_mb: int
    per_vm_overhead_mb: int
    vm_ceiling: int
    vm_hard_cap: int
    asid_reserve: int
    earned_vms: int
    earned_vcpus: int
    earned_memory_mb: int
    declared_cpu_budget: int | None
    declared_memory_mb_budget: int | None
    declared_asid_capacity: int | None
    reported_free_mib: int | None
    committed_vcpus: int
    committed_memory_mb: int
    committed_vms: int


@dataclass(frozen=True)
class HostBudget:
    """One host's v2 budget and what is free in it, in real units.

    `known=False` ⇒ vali cannot size this host (an `operator` row without
    a complete anchor): every number is 0 and nothing fits. Unknown is
    never "fits", and — for feasibility — never "too small" either.

    `binding` names the term that set each budget (`vcpu:declared`,
    `memory:anchor`, `vms:asid`, …) so an operator can see WHY a host
    is the size vali thinks it is.
    """

    known: bool
    vcpu_budget: int
    memory_budget_mb: int
    vm_budget: int
    max_vm_vcpus: int
    free_vcpus: int
    free_memory_mb: int
    free_vms: int
    per_vm_overhead_mb: int
    over_claim: bool = False
    binding: tuple[str, ...] = ()
    #: The host's DATA-disk budget (always computed, possibly unknown) and
    #: how admission applies it (`DISK_GATE_*`). The default — an unknown
    #: budget, not applied — is exactly the pre-disk behaviour.
    disk: DiskBudget = field(default_factory=lambda: DISK_UNKNOWN)
    disk_gate: str = "off"


_UNKNOWN = HostBudget(
    known=False,
    vcpu_budget=0,
    memory_budget_mb=0,
    vm_budget=0,
    max_vm_vcpus=0,
    free_vcpus=0,
    free_memory_mb=0,
    free_vms=0,
    per_vm_overhead_mb=0,
)
#: The budget of a host vali cannot size — nothing fits it.
HOST_BUDGET_UNKNOWN = _UNKNOWN


def _tightest(dim: str, terms: list[tuple[str, int]]) -> tuple[int, str]:
    """The smallest term (floored at 0) and its label, `dim:name`."""
    name, value = min(terms, key=lambda t: (t[1], t[0]))
    return max(0, value), f"{dim}:{name}"


def host_budget(inp: BudgetInputs) -> HostBudget:
    """The untrusted-miner-safe v2 budget of one host. Pure."""
    anchored = inp.total_cpus is not None and inp.total_memory_mb is not None
    earned = inp.trust_class == "earned"
    if not anchored and not earned:
        return _UNKNOWN

    vcpu_terms: list[tuple[str, int]] = []
    mem_terms: list[tuple[str, int]] = []
    thread_terms: list[tuple[str, int]] = []
    if anchored:
        assert inp.total_cpus is not None and inp.total_memory_mb is not None
        usable_threads = max(0, inp.total_cpus - inp.reserve_cpus)
        # Decimal × int, floored: 22 threads × 2.00 = 44 vCPU.
        vcpu_terms.append(("anchor", int(usable_threads * inp.cpu_ratio)))
        mem_terms.append(("anchor", inp.total_memory_mb - inp.reserve_memory_mb))
        # No single guest wider than the host's threads: overcommit shares
        # threads BETWEEN guests; inside one guest it is lock-holder
        # preemption, the worst case of overcommit.
        thread_terms.append(("anchor", usable_threads))
    if earned:
        vcpu_terms.append(("earned", inp.earned_vcpus))
        mem_terms.append(("earned", inp.earned_memory_mb))
    # Down-only untrusted clamps.
    if inp.declared_cpu_budget is not None:
        vcpu_terms.append(("declared", inp.declared_cpu_budget))
    if inp.declared_memory_mb_budget is not None:
        mem_terms.append(("declared", inp.declared_memory_mb_budget))

    vm_terms: list[tuple[str, int]] = [
        ("ceiling", inp.vm_ceiling),
        ("hard-cap", inp.vm_hard_cap),
    ]
    if earned:
        vm_terms.append(("earned", inp.earned_vms))
    if inp.declared_asid_capacity is not None:
        vm_terms.append(("asid", inp.declared_asid_capacity - inp.asid_reserve))

    vcpu_budget, vcpu_bind = _tightest("vcpu", vcpu_terms)
    mem_budget, mem_bind = _tightest("memory", mem_terms)
    vm_budget, vm_bind = _tightest("vms", vm_terms)
    # An earned host has no trusted thread count: its widest guest is
    # bounded by its whole vCPU budget.
    max_vm_vcpus, _ = _tightest("threads", thread_terms or [("budget", vcpu_budget)])
    max_vm_vcpus = min(max_vm_vcpus, vcpu_budget)

    committed_mem = inp.committed_memory_mb + inp.committed_vms * inp.per_vm_overhead_mb
    free_vcpus = max(0, vcpu_budget - inp.committed_vcpus)
    free_mem = max(0, mem_budget - committed_mem)
    over_claim = False
    if inp.reported_free_mib is not None:
        # CAPACITY CLAMP — down-only, as in v1.
        free_mem = min(free_mem, max(0, inp.reported_free_mib))
        # ALARM only — more free RAM than the machine has at all.
        if anchored:
            assert inp.total_memory_mb is not None
            over_claim = inp.reported_free_mib > inp.total_memory_mb
    free_vms = max(0, vm_budget - inp.committed_vms)

    return HostBudget(
        known=True,
        vcpu_budget=vcpu_budget,
        memory_budget_mb=mem_budget,
        vm_budget=vm_budget,
        max_vm_vcpus=max_vm_vcpus,
        free_vcpus=free_vcpus,
        free_memory_mb=free_mem,
        free_vms=free_vms,
        per_vm_overhead_mb=inp.per_vm_overhead_mb,
        over_claim=over_claim,
        binding=(vcpu_bind, mem_bind, vm_bind),
    )


def fits(b: HostBudget, *, cpu_count: int, memory_mb: int, disk_gb: int = 0) -> bool:
    """Could ONE more VM of this size start on the host right now?

    `disk_gb` counts only while the disk gate is ENFORCED on this host
    (`b.disk_gate`); off / record leave the answer to CPU, RAM and VMs."""
    return (
        b.known
        and cpu_count <= b.max_vm_vcpus
        and cpu_count <= b.free_vcpus
        and memory_mb + b.per_vm_overhead_mb <= b.free_memory_mb
        and b.free_vms >= 1
        and disk_admits(b.disk, b.disk_gate, disk_gb=disk_gb)
    )


def big_enough(b: HostBudget, *, cpu_count: int, memory_mb: int, disk_gb: int = 0) -> bool:
    """Could the host EVER run one, with nothing else placed on it?"""
    return (
        b.known
        and cpu_count <= b.max_vm_vcpus
        and cpu_count <= b.vcpu_budget
        and memory_mb + b.per_vm_overhead_mb <= b.memory_budget_mb
        and b.vm_budget >= 1
        and disk_admits(b.disk, b.disk_gate, disk_gb=disk_gb, ever=True)
    )


def headroom(b: HostBudget, *, cpu_count: int, memory_mb: int, disk_gb: int = 0) -> int:
    """How many more VMs of this size fit right now — bounded by every
    dimension admission checks, so N successive [`fits`] admissions of
    this size consume exactly this many."""
    if not fits(b, cpu_count=cpu_count, memory_mb=memory_mb, disk_gb=disk_gb):
        return 0
    return min(
        b.free_vcpus // cpu_count,
        b.free_memory_mb // (memory_mb + b.per_vm_overhead_mb),
        b.free_vms,
        disk_headroom(b.disk, b.disk_gate, disk_gb=disk_gb),
    )


def free_fraction(b: HostBudget) -> float:
    """The emptiest-dimension fraction left (0..1) — the ranking's
    load-balance term. Size-neutral: an empty small host and an empty big
    host both score 1.0, so a larger ceiling never buys rank."""
    if not b.known or min(b.vcpu_budget, b.memory_budget_mb, b.vm_budget) <= 0:
        return 0.0
    return min(
        b.free_vcpus / b.vcpu_budget,
        b.free_memory_mb / b.memory_budget_mb,
        b.free_vms / b.vm_budget,
    )


@dataclass(frozen=True)
class Units:
    """Capacity in reference-flavor units (`total = committed + free`)."""

    total: int
    committed: int
    free: int


def units(
    b: HostBudget, *, unit_cpus: int, unit_memory_mb: int, unit_disk_gb: int = 0
) -> Units:
    """Resource-true units: how many reference-flavor VMs the budget, and
    what is free of it, would hold. A flavor N× the reference consumes N
    units; a smaller one a fraction (so two `small` = one `medium`).
    Disk bounds the units only while the disk gate is enforced here."""
    if not b.known or unit_cpus <= 0 or unit_memory_mb <= 0:
        return Units(0, 0, 0)
    per_unit_mem = unit_memory_mb + b.per_vm_overhead_mb
    total = min(b.vcpu_budget // unit_cpus, b.memory_budget_mb // per_unit_mem, b.vm_budget)
    free = min(b.free_vcpus // unit_cpus, b.free_memory_mb // per_unit_mem, b.free_vms)
    if b.disk_gate == DISK_GATE_DENY:
        total = free = 0
    elif b.disk_gate == DISK_GATE_APPLY and unit_disk_gb > 0:
        total = min(total, b.disk.budget_gb // unit_disk_gb)
        free = min(free, b.disk.free_gb // unit_disk_gb)
    free = min(free, total)
    return Units(total=total, committed=max(0, total - free), free=free)

