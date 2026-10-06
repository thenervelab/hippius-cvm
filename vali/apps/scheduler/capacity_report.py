"""v1-vs-v2 capacity, side by side — the evidence the shadow run is judged on.

`vali_capacity_report` prints it for the fleet and `vali_set_miner_capacity
--show` for one miner. Read-only: it only calls the same assembly functions
admission uses (`service._capacity_results_by_node` for v1,
`service.host_budgets_by_node` for v2), so what it prints is what the
scheduler would decide, not a re-derivation.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

from apps.orchestration.services import flavors

from . import capacity, capacity_config, service
from .models import ACTIVE_PLACEMENT_STATES, MinerCapacity, Placement


@dataclass(frozen=True)
class NodeReport:
    node_id: str
    trust_class: str
    dispatchable: bool
    v1_slots: int
    v1_load: int
    v1_free_slots: int
    v2_known: bool
    v2_vcpu_budget: int
    v2_memory_budget_mb: int
    v2_vm_budget: int
    v2_max_vm_vcpus: int
    v2_free_vcpus: int
    v2_free_memory_mb: int
    v2_free_vms: int
    #: vali's ledger in v2 terms (RAM includes the per-VM overhead).
    v2_committed_vcpus: int
    v2_committed_memory_mb: int
    v2_binding: tuple[str, ...]
    v2_units: capacity.Units
    #: `{flavor: (v1 headroom, v2 headroom)}` — v1 = `min(free_mem // m,
    #: free_cpu // v)` (feasibility's v1 figure, no slot clamp), v2 =
    #: `capacity.headroom`.
    headroom: dict[str, tuple[int | None, int]]

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def fleet_report(*, node_ids: set[str] | None = None) -> list[NodeReport]:
    """One [`NodeReport`] per mirror row (or per `node_ids`), sorted."""
    rows = list(MinerCapacity.objects.all().order_by("miner_node_id"))
    if node_ids is not None:
        rows = [r for r in rows if r.miner_node_id in node_ids]
    load: dict[str, int] = {}
    committed_mb: dict[str, int] = {}
    committed_cpus: dict[str, int] = {}
    for row in Placement.objects.filter(status__in=ACTIVE_PLACEMENT_STATES).values(
        "miner_node_id", "resource_class"
    ):
        nid = row["miner_node_id"]
        mem, cpus = service._committed_resources(row["resource_class"])
        load[nid] = load.get(nid, 0) + 1
        committed_mb[nid] = committed_mb.get(nid, 0) + mem
        committed_cpus[nid] = committed_cpus.get(nid, 0) + cpus
    v1 = service._capacity_results_by_node(load, committed_mb, committed_cpus, rows=rows)
    v2 = service.host_budgets_by_node(rows=rows)
    ledger = service._committed_by_node()
    dispatchable = service.dispatchable_node_ids()
    unit_cpus = service._slot_ref_cpus()
    unit_mem = service._slot_ref_memory_mb()

    out: list[NodeReport] = []
    for row in rows:
        nid = row.miner_node_id
        r1 = v1[nid]
        b = v2[nid]
        heads: dict[str, tuple[int | None, int]] = {}
        for name in flavors.FLAVOR_NAMES:
            size = flavors.resolve_flavor(name)
            if r1.free_memory_mb is None or r1.free_cpus is None:
                h1: int | None = None
            else:
                h1 = max(
                    0,
                    min(r1.free_memory_mb // size.memory_mb, r1.free_cpus // size.cpu_count),
                )
            heads[name] = (
                h1,
                capacity.headroom(
                    b,
                    cpu_count=size.cpu_count,
                    memory_mb=size.memory_mb,
                    disk_gb=size.data_disk_size_gb + size.luks_disk_size_gb,
                ),
            )
        out.append(
            NodeReport(
                node_id=nid,
                trust_class=row.trust_class,
                dispatchable=nid in dispatchable,
                v1_slots=r1.slots,
                v1_load=load.get(nid, 0),
                v1_free_slots=max(0, r1.slots - load.get(nid, 0)),
                v2_known=b.known,
                v2_vcpu_budget=b.vcpu_budget,
                v2_memory_budget_mb=b.memory_budget_mb,
                v2_vm_budget=b.vm_budget,
                v2_max_vm_vcpus=b.max_vm_vcpus,
                v2_free_vcpus=b.free_vcpus,
                v2_free_memory_mb=b.free_memory_mb,
                v2_free_vms=b.free_vms,
                v2_committed_vcpus=ledger[nid].vcpus if nid in ledger else 0,
                v2_committed_memory_mb=(
                    ledger[nid].memory_mb + ledger[nid].vms * b.per_vm_overhead_mb
                    if nid in ledger
                    else 0
                ),
                v2_binding=b.binding,
                v2_units=capacity.units(
                    b,
                    unit_cpus=unit_cpus,
                    unit_memory_mb=unit_mem,
                    unit_disk_gb=capacity_config.slot_ref_disk_gb() + flavors.ROOTFS_DISK_GB,
                ),
                headroom=heads,
            )
        )
    return out


def preflight_issues(report: NodeReport) -> list[str]:
    """Why switching `VALI_SCHEDULER_RESOURCE_ADMISSION` on would shrink or
    strand THIS dispatchable host — empty when the flip is safe for it.

    - `v2-unknown`         an `operator` row without a complete anchor:
                           v2 refuses every placement on it.
    - `v2-earned-floor`    an `earned` row: v2 sizes it at the earned
                           ceiling (the floor for a new miner) where v1
                           gave it the flat `capacity_slots`.
    - `v2-over-committed`  vali has already placed more vCPU / RAM / VMs
                           than the v2 budget — no new placements until
                           load drains (existing VMs are untouched).
    - `v2-full-v1-free`    v1 would still admit here but v2 would not
                           admit even a `small`.
    """
    if not report.dispatchable:
        return []
    if not report.v2_known:
        return ["v2-unknown"]
    issues: list[str] = []
    if report.trust_class == "earned":
        issues.append("v2-earned-floor")
    if (
        report.v2_committed_vcpus > report.v2_vcpu_budget
        or report.v2_committed_memory_mb > report.v2_memory_budget_mb
        or report.v1_load > report.v2_vm_budget
    ):
        issues.append("v2-over-committed")
    if report.headroom["small"][1] == 0 and report.v1_free_slots > 0:
        issues.append("v2-full-v1-free")
    return issues


def render(report: NodeReport) -> list[str]:
    """Human-readable lines for one node."""
    u = report.v2_units
    lines = [
        f"node {report.node_id}  trust={report.trust_class}  dispatchable={report.dispatchable}",
        f"  v1  slots {report.v1_slots}  load {report.v1_load}  free {report.v1_free_slots}",
    ]
    if not report.v2_known:
        lines.append("  v2  UNKNOWN (operator class without a complete anchor)")
    else:
        lines += [
            f"  v2  budget {report.v2_vcpu_budget} vCPU / {report.v2_memory_budget_mb} MiB / "
            f"{report.v2_vm_budget} VMs (widest VM {report.v2_max_vm_vcpus} vCPU)  "
            f"bound by {', '.join(report.v2_binding)}",
            f"      free   {report.v2_free_vcpus} vCPU / {report.v2_free_memory_mb} MiB / "
            f"{report.v2_free_vms} VMs",
            f"      units  total {u.total}  committed {u.committed}  free {u.free}",
        ]
    issues = preflight_issues(report)
    if issues:
        lines.append(f"  PREFLIGHT {', '.join(issues)}")
    lines.append(
        "  headroom v1/v2  "
        + "  ".join(
            f"{name} {'-' if h1 is None else h1}/{h2}"
            for name, (h1, h2) in report.headroom.items()
        )
    )
    return lines
