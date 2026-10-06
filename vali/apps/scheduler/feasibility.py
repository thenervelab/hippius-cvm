"""Can we place a VM of this flavor — BEFORE anyone sells it?

The question the operator's sales path needs answered is not "is the
fleet healthy" but "if I take money for a `2xlarge` right now, will it
run?". Getting that wrong is expensive in a way a failed launch is not:
the customer has already paid.

Two independent things have to be true, and they fail differently:

1. **The scheduler must be willing to choose someone.** Chain epoch
   freshness, stake, dispatchability, the CVM-capability ledger, the
   circuit breaker, anti-affinity — seven gates, any of which can empty
   the candidate set. This module does not re-implement them: it calls
   the very same [`decide_placement`] the launch path calls, with the
   very same arguments, via [`service.placement_arguments`]. A second
   implementation would drift, and a drifted feasibility check is worse
   than none — it lies with authority.

2. **The flavor must physically FIT on a host.** This is the half that
   surprises people, because vali's scheduler never checks it. Capacity
   is denominated in admission SLOTS sized by the reference flavor, and
   one placement costs one slot whatever its size. A `4xlarge` asking
   for 128 GiB and 32 vCPU therefore looks placeable on a host with one
   free slot. The component that actually refuses is the MINER, at
   preflight (`check_cpu_mem_budget` → 503 `insufficient-resources`),
   by which point vali has already picked it and has to re-place.

So a check that only asked (1) would answer "yes" for a flavor no host
in the fleet can ever run. Both halves are asked here.

## Disk, and what this CANNOT tell you

vali sizes each host's DATA disk from its own ledger (Σ flavor
`disk_gb` + rootfs per counted placement) against the down-only `min` of
the operator anchor, the heartbeat-v4 declared budget and the reported
data-fs total (`capacity.disk_budget`). Every host carries its disk
figures and `disk_checked` (vali HAS disk data for it). Disk joins `fits`
/ `big_enough` / `headroom` only while `VALI_SCHEDULER_DISK_GATE=enforce`
— the answer mirrors what admission actually does, so under `record` or
`off` a host's disk shortfall is reported but does not unsell it. The
top-level `disk_checked` is true only when the gate is enforced AND every
host counted as fitting had disk data.

What remains out of reach: disk cannot be attested. Every disk figure a
miner sends is its own word — vali only lets it LOWER the budget — and a
pre-v4 agent sends none (unknown: admitted unless
`VALI_SCHEDULER_DISK_UNKNOWN=deny`). The miner's own statvfs gate (507
`insufficient-disk`) stays the last word at dispatch. That is stated
rather than papered over: a feasibility answer that implies coverage it
does not have is the failure mode this module exists to prevent.

## Region

`region` narrows both halves to the miners the geo-probe has DETECTED
(and verified) in that country — the same map scheduler gate (f) uses.
It adds three verdicts ahead of the ladder, because "no miner in FR"
means three different things to a seller: the probe has not run yet
(`not-now` / `region-unknown` — missing data must never unsell), no
miner is there at all (`never` / `no-miner-in-region` — do not sell),
or miners are there but not yet proven (`not-now` / `region-unverified`).

Everything here is READ-ONLY. No `Vm` row, no `Placement`, no chain
write — asking whether a VM could be placed must never place one.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from apps.orchestration.services import flavors

from . import capacity, capacity_config, chain, service
from .placement import PlacementError, decide_placement


@dataclass(frozen=True)
class HostFit:
    """Whether ONE host could physically run the flavor right now."""

    node_id: str
    #: Is the HARDWARE big enough, ignoring what is placed on it? This is
    #: what makes a verdict `never` rather than `not-now`.
    big_enough: bool
    #: vali has no trusted hardware anchor for this host, so neither
    #: `big_enough` nor `fits` is an ANSWER — both are `False` because
    #: this must not read as a fit, but the host cannot count towards
    #: `never` either. Unknown is not "too small".
    size_unknown: bool
    #: Is there room RIGHT NOW? Implies `big_enough`.
    fits: bool
    #: `None` where vali has no trusted anchor for the host — reported as
    #: unknown, never silently as a fit.
    free_memory_mb: int | None
    free_cpus: int | None
    budget_memory_mb: int | None = None
    budget_cpus: int | None = None
    shortfall: str = ""
    #: Capacity v2 only (`None` under v1): VMs this host can still take
    #: (VM ceiling, hard cap, ASID), and how many of THIS flavor fit now.
    free_vms: int | None = None
    headroom: int | None = None
    #: The DATA-disk dimension (GiB): does vali have disk data for this
    #: host at all, its budget and what is free of it (`None` = unknown),
    #: and whether the gate is enforced here (`capacity.DISK_GATE_*`).
    disk_checked: bool = False
    budget_disk_gb: int | None = None
    free_disk_gb: int | None = None
    disk_gate: str = capacity.DISK_GATE_OFF


@dataclass(frozen=True)
class Feasibility:
    """The answer for one flavor.

    `verdict` is the field a caller should branch on:

    - `"yes"`      a miner would be chosen AND the flavor fits it.
    - `"not-now"`  the fleet could run this flavor, but nothing is free
                   or eligible at this instant. Retryable; capacity or a
                   decommission changes it.
    - `"never"`    no host in the fleet is big enough. Retrying cannot
                   help — this is the answer that must stop a sale.
    """

    flavor: str
    verdict: str
    placeable_now: bool
    #: Could the HARDWARE ever run this flavor? `False` is what makes a
    #: verdict `never`.
    fits_any_host: bool
    #: How many more VMs of this flavor the fleet could take right now,
    #: summed over hosts. A capacity figure, NOT a promise — it is a
    #: snapshot and any concurrent launch consumes it.
    headroom: int
    cpu_count: int
    memory_mb: int
    data_disk_size_gb: int
    reason: str = ""
    scheduler_error: str = ""
    hosts: list[HostFit] = field(default_factory=list)
    #: True only when the disk gate is ENFORCED and every host counted as
    #: fitting had disk data — i.e. `fits` covers the disk dimension. False
    #: means disk is still gated by the miner at dispatch. Surfaced so a
    #: caller knows exactly how far this answer reaches.
    disk_checked: bool = False
    #: The region the question was asked for (`""` = anywhere). Echoed so
    #: a caller holding several answers can tell which is which.
    region: str = ""


def _disk_fields(disk: capacity.DiskBudget, state: str) -> dict[str, object]:
    return {
        "disk_checked": disk.known,
        "budget_disk_gb": disk.budget_gb if disk.known else None,
        "free_disk_gb": disk.free_gb if disk.known else None,
        "disk_gate": state,
    }


def _disk_shortfall(
    disk: capacity.DiskBudget, state: str, need_gb: int, *, ever: bool
) -> str:
    """The disk shortfall `enforce` acts on here, `""` when there is none."""
    if capacity.disk_admits(disk, state, disk_gb=need_gb, ever=ever):
        return ""
    if state == capacity.DISK_GATE_DENY:
        return "disk data unknown"
    if ever:
        return f"host disk budget {disk.budget_gb} < {need_gb} GiB"
    return f"disk {disk.free_gb} < {need_gb} GiB"


def _fit_one(
    *,
    node_id: str,
    size: flavors.FlavorSize,
    res: service.HostResources,
    disk: capacity.DiskBudget = capacity.DISK_UNKNOWN,
    disk_state: str = capacity.DISK_GATE_OFF,
) -> HostFit:
    """Two separate questions about one host, fail-closed on unknown.

    `big_enough` compares the flavor to the host's whole tenant BUDGET —
    could this hardware ever run it. `fits` compares it to what is FREE
    — could it run it now. Collapsing them would make every full fleet
    report `never`, permanently unselling a flavor the hardware handles
    fine.
    """
    if (
        res.free_memory_mb is None
        or res.free_cpus is None
        or res.budget_memory_mb is None
        or res.budget_cpus is None
    ):
        return HostFit(
            node_id=node_id,
            # No trusted anchor ⇒ vali does not know the host's size. The
            # honest verdict is "cannot say", and for a sales gate that
            # has to read as "no" — an unknown host must never be the
            # reason we promised a customer a VM.
            big_enough=False,
            size_unknown=True,
            fits=False,
            free_memory_mb=res.free_memory_mb,
            free_cpus=res.free_cpus,
            budget_memory_mb=res.budget_memory_mb,
            budget_cpus=res.budget_cpus,
            shortfall="no-trusted-anchor",
            **_disk_fields(disk, disk_state),
        )

    need_disk = size.data_disk_size_gb + size.luks_disk_size_gb
    disk_ever = _disk_shortfall(disk, disk_state, need_disk, ever=True)
    big_enough = (
        res.budget_memory_mb >= size.memory_mb
        and res.budget_cpus >= size.cpu_count
        and not disk_ever
    )
    short: list[str] = []
    if not big_enough:
        if disk_ever:
            short.append(disk_ever)
        # Name the PERMANENT shortfall — this is the one an operator has
        # to act on (buy hardware or stop selling the flavor).
        if res.budget_memory_mb < size.memory_mb:
            short.append(
                f"host memory budget {res.budget_memory_mb} < {size.memory_mb} MiB"
            )
        if res.budget_cpus < size.cpu_count:
            short.append(f"host cpu budget {res.budget_cpus} < {size.cpu_count}")
    else:
        if res.free_memory_mb < size.memory_mb:
            short.append(f"memory {res.free_memory_mb} < {size.memory_mb} MiB")
        if res.free_cpus < size.cpu_count:
            short.append(f"cpu {res.free_cpus} < {size.cpu_count}")
        disk_now = _disk_shortfall(disk, disk_state, need_disk, ever=False)
        if disk_now:
            short.append(disk_now)
    return HostFit(
        node_id=node_id,
        big_enough=big_enough,
        size_unknown=False,
        fits=not short,
        free_memory_mb=res.free_memory_mb,
        free_cpus=res.free_cpus,
        budget_memory_mb=res.budget_memory_mb,
        budget_cpus=res.budget_cpus,
        shortfall="; ".join(short),
        **_disk_fields(disk, disk_state),
    )


def _fit_one_v2(
    *,
    node_id: str,
    size: flavors.FlavorSize,
    budget: capacity.HostBudget,
) -> HostFit:
    """[`_fit_one`] under capacity v2: the same two questions, answered by
    the functions admission uses (`capacity.fits` / `big_enough` /
    `headroom`), so feasibility and the launch cannot disagree."""
    if not budget.known:
        return HostFit(
            node_id=node_id,
            big_enough=False,
            size_unknown=True,
            fits=False,
            free_memory_mb=None,
            free_cpus=None,
            shortfall="no-trusted-anchor",
            **_disk_fields(budget.disk, budget.disk_gate),
        )
    need_disk = size.data_disk_size_gb + size.luks_disk_size_gb
    dims = {"cpu_count": size.cpu_count, "memory_mb": size.memory_mb, "disk_gb": need_disk}
    big = capacity.big_enough(budget, **dims)
    fit = capacity.fits(budget, **dims)
    need_mem = size.memory_mb + budget.per_vm_overhead_mb
    short: list[str] = []
    disk_short = _disk_shortfall(budget.disk, budget.disk_gate, need_disk, ever=not big)
    if disk_short:
        short.append(disk_short)
    if not big:
        if size.cpu_count > budget.max_vm_vcpus:
            short.append(f"host threads {budget.max_vm_vcpus} < {size.cpu_count} vCPU")
        if size.cpu_count > budget.vcpu_budget:
            short.append(f"host cpu budget {budget.vcpu_budget} < {size.cpu_count}")
        if need_mem > budget.memory_budget_mb:
            short.append(f"host memory budget {budget.memory_budget_mb} < {need_mem} MiB")
        if budget.vm_budget < 1:
            short.append("host VM budget 0")
    elif not fit:
        if size.cpu_count > budget.free_vcpus:
            short.append(f"cpu {budget.free_vcpus} < {size.cpu_count}")
        if need_mem > budget.free_memory_mb:
            short.append(f"memory {budget.free_memory_mb} < {need_mem} MiB")
        if budget.free_vms < 1:
            short.append(f"VM slots 0 of {budget.vm_budget}")
    return HostFit(
        node_id=node_id,
        big_enough=big,
        size_unknown=False,
        fits=fit,
        free_memory_mb=budget.free_memory_mb,
        free_cpus=budget.free_vcpus,
        budget_memory_mb=budget.memory_budget_mb,
        budget_cpus=budget.vcpu_budget,
        shortfall="; ".join(short),
        free_vms=budget.free_vms,
        headroom=capacity.headroom(budget, **dims),
        **_disk_fields(budget.disk, budget.disk_gate),
    )


def assess(
    flavor: str,
    *,
    tenant_id: str = "",
    user_id: str = "",
    region: str = "",
) -> Feasibility:
    """Answer "could a VM of `flavor` be placed right now?". Read-only.

    `tenant_id` / `user_id` are optional and only sharpen the answer:
    they feed anti-affinity and the per-owner sub-budget, so passing the
    real ones tells you whether THIS customer can place, not merely
    whether somebody could.

    `region` (ISO 3166-1 alpha-2, case-insensitive) asks the question for
    ONE country: only miners detected there count, and a launch with the
    same `region` is what the answer predicts. Shape is the caller's to
    validate (the view does); here an unparseable value simply matches
    no miner.

    Raises `flavors.UnknownFlavor` for a flavor outside the catalogue —
    the caller asked about something that does not exist, which is a
    different thing from "cannot place" and must not be flattened into
    it.
    """
    size = flavors.resolve_flavor(flavor)
    region = region.strip().upper()
    if not flavors.is_offered(flavor):
        # Not for sale, whatever the hardware could hold — the answer that
        # must stop a sale, so `never`, and before any chain read: the
        # verdict does not depend on the fleet.
        return Feasibility(
            flavor=flavor,
            verdict="never",
            placeable_now=False,
            fits_any_host=False,
            headroom=0,
            cpu_count=size.cpu_count,
            memory_mb=size.memory_mb,
            data_disk_size_gb=size.data_disk_size_gb,
            reason="flavor-not-offered",
            region=region,
        )

    try:
        snapshot = chain.read_miner_status()
    except chain.ChainReadUnavailable as exc:
        # vali cannot see the chain, so it cannot honestly say the fleet
        # is unable to run this — only that it cannot tell. `not-now`,
        # never `never`: a chain blip must not permanently unsell a
        # flavor.
        return Feasibility(
            flavor=flavor,
            verdict="not-now",
            placeable_now=False,
            fits_any_host=False,
            headroom=0,
            cpu_count=size.cpu_count,
            memory_mb=size.memory_mb,
            data_disk_size_gb=size.data_disk_size_gb,
            reason="chain-unavailable",
            scheduler_error=str(exc),
            region=region,
        )

    service.refresh_miner_capacity(snapshot)

    # ── Half 2 first: does the flavor fit ANYWHERE? ──────────────────
    # Computed over the DISPATCHABLE set only. A host vali cannot reach
    # is not somewhere this VM could run, so counting it would inflate
    # the headroom with capacity nobody can use. Under a region
    # constraint, further restricted to the hosts DETECTED there — the
    # exact map gate (f) will apply — so the headroom is what a launch
    # with that region could actually consume.
    dispatchable = service.dispatchable_node_ids()
    in_region = service.region_by_node() if region else None

    def counted(nid: str) -> bool:
        return nid in dispatchable and (in_region is None or in_region.get(nid) == region)

    budgets = service.host_budgets_by_node()
    if capacity_config.resource_admission_enabled():
        # Capacity v2: vCPU (with overcommit), RAM + per-VM overhead, VM
        # count — the same budgets and functions admission enforces.
        hosts = [
            _fit_one_v2(node_id=nid, size=size, budget=b)
            for nid, b in sorted(budgets.items())
            if counted(nid)
        ]
        headroom = sum(h.headroom or 0 for h in hosts if h.fits)
    else:
        resources = service.host_resources_by_node()
        need_disk = size.data_disk_size_gb + size.luks_disk_size_gb
        hosts = [
            _fit_one(
                node_id=nid,
                size=size,
                res=res,
                disk=budgets[nid].disk if nid in budgets else capacity.DISK_UNKNOWN,
                disk_state=(
                    budgets[nid].disk_gate if nid in budgets else capacity.DISK_GATE_OFF
                ),
            )
            for nid, res in sorted(resources.items())
            if counted(nid)
        ]
        # How many of this flavor each fitting host could still take.
        # Bounded by every dimension admission applies, same as the
        # miner's own gate.
        headroom = sum(
            min(
                (h.free_memory_mb or 0) // size.memory_mb,
                (h.free_cpus or 0) // size.cpu_count,
                capacity.disk_headroom(
                    budgets[h.node_id].disk if h.node_id in budgets else capacity.DISK_UNKNOWN,
                    h.disk_gate,
                    disk_gb=need_disk,
                ),
            )
            for h in hosts
            if h.fits
        )
    big_enough = [h for h in hosts if h.big_enough]
    unknown = [h for h in hosts if h.size_unknown]
    fitting = [h for h in hosts if h.fits]

    # ── Half 1: would the scheduler actually choose someone? ─────────
    scheduler_error = ""
    # The scheduler's own category, so a region refusal reads as one
    # instead of being flattened into `no-eligible-miner`.
    scheduler_category = ""
    try:
        decide_placement(
            snapshot=snapshot,
            **service.placement_arguments(
                snapshot=snapshot,
                tenant_id=tenant_id,
                user_id=user_id,
                flavor=flavor,
                region=region,
                shadow_log=False,
                budgets=budgets,
            ),
        )
        scheduler_ok = True
    except PlacementError as exc:
        scheduler_ok = False
        scheduler_error = exc.message
        scheduler_category = exc.category

    # ── Verdict ──────────────────────────────────────────────────────
    # `never` is reserved for the case retrying cannot fix: no host in
    # the reachable fleet is BIG ENOUGH. A fleet that is merely full
    # right now is `not-now`, and the distinction is the whole point —
    # one says "wait", the other says "do not sell this".
    #
    # Under a region constraint three answers come FIRST, because an
    # empty in-region host list has three causes a seller must tell
    # apart. "Located" is judged on `placeable_locations(verified_only=
    # False)` — fresh rows with a verified OR unverified verdict — so
    # "nobody is there" counts every miner the probe has credibly placed,
    # not only the proven ones, and never a stale or contradicted row.
    located = service.region_by_node(verified_only=False) if region else {}
    if region and region not in located.values():
        if located and dispatchable and dispatchable <= located.keys():
            # EVERY reachable miner has a fresh detected country, and
            # none of them is this one. Retrying cannot change geography:
            # do not sell.
            verdict, reason = "never", "no-miner-in-region"
        else:
            # Nobody is detected there, but the picture is incomplete:
            # the probe has never run (`MinerLocation` is empty), or has
            # not credibly placed every reachable miner yet (a located DE
            # miner next to three unlocated ones says nothing about FR).
            # That is missing data, and missing data must never unsell —
            # `never` has to be earned from knowledge of where the WHOLE
            # reachable fleet is.
            verdict, reason = "not-now", "region-unknown"
    elif region and region not in (in_region or {}).values():
        # Miners are detected there, but none passes the verification the
        # gate requires (latency contradicts the GeoIP, guests egress
        # elsewhere, peer stale). Retryable — a later probe cycle, or the
        # operator reading `verdict_reasons`, changes it.
        verdict, reason = "not-now", "region-unverified"
    elif not hosts:
        verdict, reason = "not-now", "no-dispatchable-miner"
    elif not big_enough and unknown:
        # `never` must be earned from KNOWLEDGE, never from missing data.
        # Every miner on the live fleet has `total_memory_mb = None` (the
        # operator anchor was never seeded, so admission runs on the flat
        # `capacity_slots` fallback), and the first version of this
        # function turned that into `never` for EVERY flavor — it declared
        # the whole catalogue permanently unsellable. Unknown is not "too
        # small": it is retryable, and the reason names what to fix.
        verdict, reason = "not-now", "host-size-unknown"
    elif not big_enough:
        verdict, reason = "never", "flavor-exceeds-every-host"
    elif not fitting:
        verdict, reason = "not-now", "fleet-full"
    elif not scheduler_ok:
        verdict, reason = "not-now", scheduler_category or "no-eligible-miner"
    elif headroom <= 0:
        verdict, reason = "not-now", "fleet-full"
    else:
        verdict, reason = "yes", ""

    return Feasibility(
        flavor=flavor,
        verdict=verdict,
        placeable_now=verdict == "yes",
        fits_any_host=bool(big_enough),
        headroom=headroom,
        cpu_count=size.cpu_count,
        memory_mb=size.memory_mb,
        data_disk_size_gb=size.data_disk_size_gb,
        reason=reason,
        scheduler_error=scheduler_error,
        hosts=hosts,
        disk_checked=(
            capacity_config.disk_gate_mode() == "enforce"
            and bool(fitting)
            and all(h.disk_checked for h in fitting)
        ),
        region=region,
    )


def assess_catalogue(
    *, tenant_id: str = "", user_id: str = "", region: str = ""
) -> list[Feasibility]:
    """[`assess`] for every catalogue flavor — the "what can I sell right
    now" board, in catalogue order."""
    return [
        assess(name, tenant_id=tenant_id, user_id=user_id, region=region)
        for name in flavors.FLAVOR_NAMES
    ]
