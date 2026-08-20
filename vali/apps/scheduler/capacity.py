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
   PHYSICALLY-IMPOSSIBLE claim — `reported_free > total − reserve`, i.e.
   more free RAM than the host could have even with ZERO VMs. A report in
   the plausible band `[total − committed − reserve, total − reserve]` is
   legitimate (placed VMs under-use their nominal committed RAM, which the
   host reports as available buff/cache) and is NOT flagged. The flag
   never feeds the slot computation.

6. **Operator upper clamp** — the result is finally bounded above by
   `operator_max` (`capacity_slots`), so an operator can always cap a
   miner BELOW its computed value.

There is NO path in which `reported_free` raises the returned slot count
above `committed_slots + f(trusted_free)`: it enters only via the two
`min`/clamp steps, both of which move DOWN.
"""

from __future__ import annotations

from dataclasses import dataclass


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
                    (`> total − reserve`). Pure alarm — capacity is
                    already clamped down-only and is unaffected by it.
    """

    slots: int
    dynamic: bool
    over_claim: bool


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
        # PHYSICALLY-IMPOSSIBLE claim: more free RAM than the host could
        # ever have, i.e. more than `total − reserve` (its whole tenant
        # budget free, zero VMs). A report anywhere in the plausible band
        # `[total − committed − reserve, total − reserve]` is LEGITIMATE —
        # placed VMs routinely under-use their nominal committed RAM
        # (buff/cache the host counts as `available`) — so it does NOT
        # alarm. This threshold cries wolf only on a genuine over-claim.
        physical_max_free_mb = max(
            0, inp.total_memory_mb - inp.reserve_memory_mb
        )
        over_claim = inp.reported_free_mib > physical_max_free_mb

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

    return CapacityResult(slots=slots, dynamic=True, over_claim=over_claim)
