"""Operator fleet read model — `GET /v1/operator/fleet`.

The whole miner fleet in one response, for a staff observability page:
every miner vali knows about (bridged `MinerIdentity`, `MinerCapacity`
mirror row, or a node in the on-chain snapshot), each with the numbers
the scheduler itself acts on, plus fleet totals.

What runs where comes from the `Vm` ledger (`Vm.host`), reconciled with
the scheduler's `Placement` ledger: a VM the host runs but admission does
not count (e.g. its placement was drained while the miner was stale and
reboot-recovery relaunched it on the same host) is listed with
`admission_counted: false` and raises `vm-outside-admission`.

Built from the SAME predicates the scheduler uses, never re-derived:

- dispatchability     `scheduler.service.dispatchability`
- capacity            `scheduler.service._capacity_results_by_node` — the
                      admission bound, free/budget RAM + vCPU, over-claim
- CVM start ability   `scheduler.cvm_capability.capability_of_row`
- attestor coverage   `telemetry.release_service.attestor_coverage_by_node`
                      (evaluated whether or not the gate is armed, so an
                      operator sees what arming it WOULD do)
- zombie quarantine   `lifecycle.zombie.fresh_observations`
- reward weight       `scheduler.scoring.compute_epoch_weights`

Cost: one query per table (identities + locations, mirror, hosted VMs,
their placements + the live ones, attestors, attestor releases, usage, backups,
backup policies,
public IPs, zombie rows) and at most ONE chain read — never per miner.
The chain read is best-effort: when it fails the row keeps the DB mirror
of the on-chain status and `chain.available` says so; prices need the
chain and are `null` then.

Unlike `/v1/operator/nodes` (built for miner OWNERS, who may not see
tenants), this surface lists the hosted VMs by id with their tenant and
owner: it is for Hippius staff, behind the upstream's superuser gate. It
is still `OPERATOR_ONLY` — no tenant principal reaches it.

Not available here, by construction: the miner-agent version (the
heartbeat carries no version field) and the miner's owning family (the
chain holds `FamilyChildren`; vali keeps no family table).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from django.conf import settings
from django.db.models import Count, Exists, Max, OuterRef, Q, Subquery, Sum
from django.utils import timezone

from apps.backup import service as backup_service
from apps.backup.models import ACTIVE_RUN_STATUSES, BackupPolicy, BackupRun, RunStatus
from apps.lifecycle import zombie
from apps.lifecycle.models import Vm, VmPowerState, VmState
from apps.miners.models import MinerIdentity, MinerLocation
from apps.network.models import PublicIP, PublicIpState
from apps.orchestration.effects import EffectError
from apps.orchestration.services import flavors
from apps.orchestration.services.launch_digest import _vcpu_type_for_platform
from apps.scheduler import capacity_config, chain, cvm_capability, scoring
from apps.scheduler import service as scheduler_service
from apps.scheduler.capacity import DISK_GATE_OFF, DISK_UNKNOWN, HostBudget
from apps.scheduler.models import (
    ACTIVE_PLACEMENT_STATES,
    MinerCapacity,
    Placement,
    UsageAccrual,
)
from apps.scheduler.placement import MINER_ACTIVE
from apps.telemetry import guest_resources, release_service
from apps.telemetry.models import HostAttestor, HostAttestorRelease

from .service import _attestor_sort_key, _iso, _location_of, _serialize_location

#: Look-back of the per-miner backup summary.
BACKUP_WINDOW = timedelta(hours=24)


def _vcpu_model(platform_id: str, snp_generation: str | None) -> str | None:
    """The SNP vCPU model vali measures this host's guests with — exactly
    `launch_digest._vcpu_type_for_platform` (registered `snp_generation`,
    else the CHIP_ID length: 8 bytes ⇒ Turin, 64 ⇒ Genoa; a Milan host
    left NULL reads `EpycGenoa` here, which is what vali would launch it
    as). `None` when the pair does not resolve (not a real chip id, or a
    generation inconsistent with it) — vali refuses to launch there."""
    try:
        return _vcpu_type_for_platform((platform_id or "").strip(), snp_generation)
    except EffectError:
        return None


@dataclass
class _Committed:
    count: int = 0
    memory_mb: int = 0
    cpus: int = 0


#: VM states that still occupy a host: a `decommissioning` guest runs
#: until its §24 destroy lands, and a `migrating` one runs on its source
#: (and is being started on its destination).
HOSTED_VM_STATES = (VmState.ACTIVE, VmState.MIGRATING, VmState.DECOMMISSIONING)


@dataclass
class _Hosted:
    """One VM on one node, as the Vm ledger says, reconciled with the
    scheduler's Placement ledger.

    `live` is the placement admission counts for this VM on THIS node
    (pending/bound), or `None` when admission does not count it here —
    the VM still runs and still uses the host. `latest` is the VM's newest
    placement anywhere, whatever its status, for the operator to see why."""

    vm: Vm
    role: str  # "host" | "migration-dest" | "placement-only"
    live: Placement | None
    latest: Placement | None
    #: Whether admission counts `live` against this node's capacity — set
    #: per row, since the scheduler matches `miner_node_id` by exact
    #: spelling (see `_row`).
    counted: bool = False


def _hosted_by_node(
    identities: list[MinerIdentity],
) -> tuple[dict[str, list[_Hosted]], dict[str, _Committed], list[_Hosted]]:
    """What runs where, from TWO ledgers, in two queries (a third, for the
    launch records, when there are abandoned launches — `_never_placed`):

    - the `Vm` rows still on a host (`HOSTED_VM_STATES`), resolved to a node
      through `Vm.host` / `Vm.migration_dest` (a miner_id, else a node_id or
      NetBird IP) — the truth about what the host is running;
    - the pending/bound placements — what scheduler admission counts
      (`committed`, the same sums `scheduler_service.decision_inputs` makes).

    A VM without a live placement on its host is listed with `live=None`: the
    host carries it but admission does not. A live placement whose VM is no
    longer hosted is listed as `placement-only`. VMs whose host resolves to
    no known node come back as the third element — except a launch refused
    before any miner was ever chosen (see `_never_placed`): it is on no host
    at all, and `sweep_abandoned_launches` reaps it after its grace window."""
    # `Vm.host` is a miner_id (exact, it is the primary key); older rows may
    # carry a node_id or a NetBird IP, which only count when unambiguous.
    # An unbridged identity resolves to `None` (unresolved) but still takes
    # part in the ambiguity check.
    by_miner_id: dict[str, str | None] = {}
    by_node_id: dict[str, str] = {}
    by_ip: dict[str, set[str | None]] = {}
    for m in identities:
        nid = m.chain_node_id.lower() if m.chain_node_id else None
        by_miner_id[m.miner_id] = nid
        if nid is not None:
            by_node_id[nid] = nid
        if m.netbird_ip:
            by_ip.setdefault(str(m.netbird_ip), set()).add(nid)

    def node_of(host: str) -> str | None:
        if not host:
            return None
        if host in by_miner_id:
            return by_miner_id[host]
        if host.lower() in by_node_id:
            return by_node_id[host.lower()]
        candidates = by_ip.get(host, set())
        return next(iter(candidates)) if len(candidates) == 1 else None

    vms = list(Vm.objects.filter(state__in=HOSTED_VM_STATES))
    placements = (
        Placement.objects.filter(Q(vm__in=vms) | Q(status__in=ACTIVE_PLACEMENT_STATES))
        .select_related("vm")
        .order_by("decided_at")
    )
    latest: dict[Any, Placement] = {}
    live: dict[tuple[Any, str], Placement] = {}
    committed: dict[str, _Committed] = {}
    for p in placements:
        latest[p.vm_id] = p  # ordered oldest → newest
        if p.status not in ACTIVE_PLACEMENT_STATES:
            continue
        live[(p.vm_id, p.miner_node_id.lower())] = p
        # Keyed by the EXACT spelling, like `decision_inputs`: the capacity
        # numbers must be the ones the scheduler admits with.
        c = committed.setdefault(p.miner_node_id, _Committed())
        mem, cpus = scheduler_service._committed_resources(p.resource_class)
        c.count += 1
        c.memory_mb += mem
        c.cpus += cpus

    never_placed = _never_placed(vms, placed={p.vm_id for p in placements})
    by_node: dict[str, list[_Hosted]] = {}
    unresolved: list[_Hosted] = []
    seen: set[tuple[Any, str]] = set()
    for vm in sorted(vms, key=lambda v: v.created_at):
        targets = [("host", vm.host)]
        if vm.state == VmState.MIGRATING and vm.migration_dest:
            targets.append(("migration-dest", vm.migration_dest))
        for role, host in targets:
            nid = node_of(host or "")
            entry = _Hosted(vm=vm, role=role, live=None, latest=latest.get(vm.pk))
            if nid is None:
                if vm.pk in never_placed:
                    continue
                unresolved.append(entry)
                continue
            entry.live = live.get((vm.pk, nid))
            seen.add((vm.pk, nid))
            by_node.setdefault(nid, []).append(entry)
    for (vm_pk, nid), p in live.items():
        if (vm_pk, nid) not in seen:
            by_node.setdefault(nid, []).append(
                _Hosted(vm=p.vm, role="placement-only", live=p, latest=latest.get(vm_pk))
            )
    return by_node, committed, unresolved


def _never_placed(vms: list[Vm], *, placed: set[Any]) -> set[Any]:
    """The pks of the abandoned launches no vali record ever named a miner
    for — `orchestration.service.no_miner_was_ever_chosen`, in bulk: no
    `Vm.host`, no `Placement`, no `LaunchJob.miner_id`.

    The abandoned marker alone is not enough: a dispatch that timed out
    marks the row too, and its guest may be up on the miner it was sent to.
    Such a row stays listed until the sweep proves otherwise."""
    from apps.orchestration.models import LaunchJob

    candidates = {
        vm.vm_id: vm.pk
        for vm in vms
        if not vm.host and vm.launch_abandoned_at is not None and vm.pk not in placed
    }
    if not candidates:
        return set()
    named = set(
        LaunchJob.objects.filter(vm_id__in=candidates)
        .exclude(miner_id="")
        .values_list("vm_id", flat=True)
    )
    return {pk for vm_id, pk in candidates.items() if vm_id not in named}


def _v2_budget(budget: HostBudget | None) -> dict[str, Any] | None:
    if budget is None:
        return None
    return {
        "known": budget.known,
        "vcpu_budget": budget.vcpu_budget,
        "memory_budget_mb": budget.memory_budget_mb,
        "vm_budget": budget.vm_budget,
        "max_vm_vcpus": budget.max_vm_vcpus,
        "free_vcpus": budget.free_vcpus,
        "free_memory_mb": budget.free_memory_mb,
        "free_vms": budget.free_vms,
        "binding": list(budget.binding),
    }


def _disk_row(mirror: MinerCapacity, budget: HostBudget | None) -> dict[str, Any]:
    """The host's DATA-disk picture (GiB): every input of the down-only
    `min` (`capacity.disk_budget`), vali's committed ledger, the result, the
    over-claim alarm and how the gate applies it here."""
    disk = budget.disk if budget is not None else DISK_UNKNOWN
    return {
        "gate_mode": capacity_config.disk_gate_mode(),
        # `off` / `apply` / `deny` — see `capacity.DISK_GATE_*`.
        "gate_state": budget.disk_gate if budget is not None else DISK_GATE_OFF,
        "known": disk.known,
        "anchor_total_gb": mirror.total_disk_gb,
        "declared_budget_gb": mirror.declared_disk_gb_budget,
        "reported_total_gb": mirror.reported_data_disk_total_gb,
        "reported_free_gb": mirror.reported_data_disk_available_gb,
        "reported_staging_free_gb": mirror.reported_staging_disk_available_gb,
        "reported_at": _iso(mirror.disk_reported_at),
        "earned_disk_gb": mirror.earned_disk_gb,
        "committed_gb": disk.committed_gb,
        "effective_gb": disk.budget_gb if disk.known else None,
        "free_gb": disk.free_gb if disk.known else None,
        "binding": disk.binding or None,
        "over_claim": disk.over_claim,
    }


def _flavor_headroom(
    result: Any,
    view: scheduler_service.CapacityView | None = None,
    budget: HostBudget | None = None,
) -> dict[str, dict[str, Any]]:
    """Per flavor: how many more fit right now, and whether the host's
    budget could ever hold one. `null` counts when vali has no trusted
    hardware anchor for the host (it cannot answer).

    Under v2 (resource admission on) the figures are v2's, so the page
    shows what v2 would admit; under v1 they are the v1 resource
    arithmetic, byte-identical to before (the admission-true per-flavor
    count is the separate `free_by_flavor`)."""
    out: dict[str, dict[str, Any]] = {}
    disk = budget.disk if budget is not None else DISK_UNKNOWN

    def _disk(name: str) -> dict[str, Any]:
        # The disk dimension alone, whatever the gate mode — so `record`
        # shows what `enforce` would do. `null` = vali has no disk data.
        need = scheduler_service.flavor_disk_gb(name)
        return {
            "need_gb": need,
            "fits_now": disk.free_gb // need if disk.known else None,
            "fits_hardware": disk.budget_gb >= need if disk.known else None,
        }

    if view is not None and view.model == "v2":
        for name in flavors.FLAVOR_NAMES:
            hardware = view.fits_hardware[name]
            out[name] = {
                "fits_now": view.free_by_flavor[name] if hardware is not None else None,
                "fits_hardware": hardware,
                "offered": flavors.is_offered(name),
                "disk": _disk(name),
            }
        return out
    for name in flavors.FLAVOR_NAMES:
        size = flavors.resolve_flavor(name)
        offered = flavors.is_offered(name)
        if result is None or result.free_memory_mb is None or result.free_cpus is None:
            out[name] = {
                "fits_now": None,
                "fits_hardware": None,
                "offered": offered,
                "disk": _disk(name),
            }
            continue
        fits_now = min(result.free_memory_mb // size.memory_mb, result.free_cpus // size.cpu_count)
        fits_hardware = (
            result.budget_memory_mb is not None
            and result.budget_cpus is not None
            and result.budget_memory_mb >= size.memory_mb
            and result.budget_cpus >= size.cpu_count
        )
        out[name] = {
            "fits_now": max(0, fits_now),
            "fits_hardware": fits_hardware,
            # Hardware can hold it but it is not SOLD (`VALI_SCHEDULER_MAX_FLAVOR`).
            "offered": offered,
            "disk": _disk(name),
        }
    return out


def _serialize_vm(
    h: _Hosted,
    public_ips: dict[str, str],
    shortfalls: dict[str, guest_resources.GuestResourceShortfallView],
) -> dict[str, Any]:
    vm, placement = h.vm, h.live or h.latest
    shortfall = shortfalls.get(vm.vm_id)
    return {
        "vm_id": vm.vm_id,
        "flavor": placement.resource_class if placement is not None else None,
        "role": h.role,
        # Counted by scheduler admission on this node. `False` = the host
        # runs it but the scheduler's capacity does not include it.
        "admission_counted": h.counted,
        "placement_status": placement.status if placement is not None else None,
        "placement_reason": (placement.reason or None) if placement is not None else None,
        "state": vm.state,
        "power_state": vm.power_state,
        "boot_phase": vm.boot_phase or None,
        "tenant_id": vm.tenant_id or None,
        "owner": (placement.owner or None) if placement is not None else None,
        "netbird_ip": vm.netbird_ip or None,
        "public_ip": public_ips.get(vm.vm_id),
        "created_at": _iso(vm.created_at),
        "placed_at": _iso(placement.decided_at) if placement is not None else None,
        "bound_at": _iso(placement.bound_at) if placement is not None else None,
        # The guest attested fewer vCPUs / less RAM than its flavor within
        # the flag window (`apps.telemetry.guest_resources`): degraded.
        "resource_shortfall": shortfall.as_dict() if shortfall is not None else None,
    }


def _flavor_of(h: _Hosted) -> str:
    placement = h.live or h.latest
    return placement.resource_class if placement is not None else ""


def _outside_admission(h: _Hosted) -> bool:
    """A VM the host runs but admission does not count — the over-booking
    risk. A `decommissioning` VM is dropped from admission on purpose
    (`drain:vm-terminal`) and a destination leg is counted once the move
    completes, so neither is flagged."""
    return not h.counted and h.role == "host" and h.vm.state == VmState.ACTIVE


def _attestors(
    now: datetime,
) -> tuple[release_service.AttestorCoverageMap, dict[str, tuple[HostAttestor, str | None]]]:
    """The host-attestor gate for every node (the same map
    `release_service.attestor_coverage_by_node` builds, from one query) and,
    per node, the row that DECIDES it with that row's own reason — so the
    row shown is the one the gate judged, never a fresher row that does not
    cover the node."""
    desired = release_service._desired_measurement_set()
    live_cutoff = now - timedelta(seconds=release_service._liveness_window_seconds())
    rank = release_service._REASON_RANK
    chosen: dict[str, tuple[HostAttestor, str | None]] = {}
    for row in HostAttestor.objects.all():
        key = row.node_id.lower()
        reason = release_service._row_coverage_reason(
            row, desired_set=desired, live_cutoff=live_cutoff
        )
        cur = chosen.get(key)
        if cur is None:
            chosen[key] = (row, reason)
            continue
        cur_row, cur_reason = cur
        mine = (-1 if reason is None else rank[reason], _attestor_sort_key(row))
        theirs = (-1 if cur_reason is None else rank[cur_reason], _attestor_sort_key(cur_row))
        if mine < theirs:
            chosen[key] = (row, reason)
    coverage = release_service.AttestorCoverageMap(
        release_pinned=bool(desired),
        by_node={k: reason for k, (_row, reason) in chosen.items()},
    )
    return coverage, chosen


def _read_chain() -> tuple[chain.ChainSnapshot | None, str | None]:
    try:
        return chain.read_miner_status(), None
    except chain.ChainReadUnavailable as exc:
        return None, str(exc)


def _usage_by_node(epoch: int | None) -> dict[str, dict[str, int]]:
    if epoch is None:
        return {}
    rows = (
        UsageAccrual.objects.filter(epoch=epoch)
        .values("miner_node_id")
        .annotate(units=Sum("unit_seconds"), billable=Sum("billable_seconds"), vms=Count("id"))
    )
    return {
        r["miner_node_id"].lower(): {
            "unit_seconds": int(r["units"] or 0),
            "billable_seconds": int(r["billable"] or 0),
            "vm_rows": int(r["vms"]),
        }
        for r in rows
    }


def _backups_by_miner(since: datetime) -> dict[str, dict[str, Any]]:
    rows = (
        BackupRun.objects.filter(created_at__gte=since)
        .values("miner_id")
        .annotate(
            done=Count("id", filter=Q(status=RunStatus.DONE.value)),
            failed=Count("id", filter=Q(status=RunStatus.FAILED.value)),
            running=Count(
                "id", filter=Q(status__in=[RunStatus.PENDING.value, RunStatus.RUNNING.value])
            ),
            last_done_at=Max("finished_at", filter=Q(status=RunStatus.DONE.value)),
            last_failed_at=Max("finished_at", filter=Q(status=RunStatus.FAILED.value)),
        )
    )
    return {
        r["miner_id"]: {
            "done_24h": r["done"],
            "failed_24h": r["failed"],
            "in_flight": r["running"],
            "last_done_at": _iso(r["last_done_at"]),
            "last_failed_at": _iso(r["last_failed_at"]),
        }
        for r in rows
    }


def _backup_attention(now: datetime) -> dict[str, str]:
    """`{vm_id: "failing" | "overdue"}` for the VMs whose backups an
    operator must look at. Only VMs the backup tick owes a backup: the
    feature on, an ENABLED policy on an active, running, hosted VM
    (`_maybe_start`'s own conditions) — a disabled policy raises nothing.

    - failing: the VM's newest finished run failed (a failure a later
      success superseded is history, not news);
    - overdue: no run in flight and nothing done for longer than
      `backup_service.fresh_for`, counted from the newest done run (any
      boot: a reboot makes the old chain unrestorable but the tick starts
      the new full at once, which is not lateness), the policy's creation
      or the VM's last power change, whichever is latest. A run in flight
      is the tick doing its job; one that never concludes fails.

    One query."""
    if not backup_service.enabled():
        return {}
    runs = BackupRun.objects.filter(vm=OuterRef("vm"))
    policies = (
        BackupPolicy.objects.filter(
            enabled=True, vm__state=VmState.ACTIVE, vm__power_state=VmPowerState.RUNNING
        )
        .exclude(vm__host="")
        .select_related("vm")
        .annotate(
            last_outcome=Subquery(
                runs.filter(status__in=[RunStatus.DONE.value, RunStatus.FAILED.value])
                .order_by("-created_at")
                .values("status")[:1]
            ),
            last_done_at=Subquery(
                runs.filter(status=RunStatus.DONE.value)
                .order_by("-finished_at")
                .values("finished_at")[:1]
            ),
            in_flight=Exists(runs.filter(status__in=ACTIVE_RUN_STATUSES)),
        )
    )
    out: dict[str, str] = {}
    for policy in policies:
        if policy.last_outcome == RunStatus.FAILED.value:
            out[policy.vm.vm_id] = "failing"
            continue
        since = max(
            t
            for t in (policy.last_done_at, policy.created_at, policy.vm.power_state_at)
            if t is not None
        )
        if not policy.in_flight and now - since > backup_service.fresh_for(policy):
            out[policy.vm.vm_id] = "overdue"
    return out


def _backups_of(
    hosted: list[_Hosted], counts: dict[str, Any] | None, attention: dict[str, str]
) -> dict[str, Any] | None:
    """The row's `backups`: the look-back counts (history, whatever the
    policy is now) plus the VMs this host runs whose backups need a look.
    `None` when there is neither."""
    vm_ids = sorted({h.vm.vm_id for h in hosted if h.role == "host"})
    failing = [v for v in vm_ids if attention.get(v) == "failing"]
    overdue = [v for v in vm_ids if attention.get(v) == "overdue"]
    if counts is None and not failing and not overdue:
        return None
    base = counts or {
        "done_24h": 0,
        "failed_24h": 0,
        "in_flight": 0,
        "last_done_at": None,
        "last_failed_at": None,
    }
    return {**base, "failing_vm_ids": failing, "overdue_vm_ids": overdue}


def _zombies_by_node(now: datetime) -> dict[str, dict[str, Any]]:
    """Nodes still relaying frames from a crypto-erased VM. `quarantined`
    is the scheduler's own set (strong frames only); a node with only
    weak frames is listed but not quarantined."""
    quarantined = zombie.quarantined_node_ids(now)
    out: dict[str, dict[str, Any]] = {}
    for row in zombie.fresh_observations(now):
        nid = (row.miner_node_id or "").lower()
        if not nid:
            continue
        entry = out.setdefault(
            nid, {"quarantined": nid in quarantined, "vm_ids": [], "last_seen_at": None}
        )
        entry["vm_ids"].append(row.vm_id)
        seen = _iso(row.last_seen_at)
        if entry["last_seen_at"] is None or (seen and seen > entry["last_seen_at"]):
            entry["last_seen_at"] = seen
    for entry in out.values():
        entry["vm_ids"].sort()
    return out


def _alerts(row: dict[str, Any], *, now: datetime) -> list[str]:
    """Closed vocabulary of conditions an operator should look at."""
    alerts: list[str] = []
    if row["on_chain"] is False:
        alerts.append("not-on-chain")
    if row["identity"] is None:
        # Nothing vali could launch onto: the host-side checks below
        # (attestor, anchor, heartbeat) would only repeat that.
        alerts.append("no-identity")
    else:
        if row["heartbeat_stale"]:
            alerts.append("heartbeat-stale")
        attestor = row["attestor"]
        if attestor is None:
            alerts.append("attestor-missing")
        else:
            if attestor["gate_reason"] is not None:
                alerts.append("attestor-not-covered")
            # Certs are short-lived and renewed continuously; only an
            # EXPIRED one is news.
            if attestor["cert_expiry_at_dt"] <= now:
                alerts.append("attestor-cert-expired")
        if row["capacity"] is not None and row["capacity"]["dynamic"] is False:
            alerts.append("no-hardware-anchor")
    if row["cvm_start"]["verdict"] in (cvm_capability.DEGRADED, cvm_capability.INCAPABLE):
        alerts.append(f"cvm-{row['cvm_start']['verdict']}")
    if row["zombie"] is not None:
        alerts.append("zombie-quarantined" if row["zombie"]["quarantined"] else "zombie-frames")
    if row["status"] == "quarantined":
        alerts.append("quarantined")
    chain_status = (row["chain"] or {}).get("status")
    if chain_status and chain_status != "active":
        alerts.append(f"chain-{chain_status}")
    if row["capacity"] is not None and row["capacity"]["over_claim"]:
        alerts.append("memory-over-claim")
    if row["capacity"] is not None and row["capacity"]["disk"]["over_claim"]:
        # Reported free data disk below what vali committed there: an
        # alarm (sparse disks), not a verdict — see `capacity.disk_budget`.
        alerts.append("disk-over-claim")
    if row["capacity"] is not None and row["capacity"]["uncounted_vms"]:
        alerts.append("vm-outside-admission")
    if any(vm["role"] == "placement-only" for vm in row["vms"]):
        alerts.append("stale-placement")
    if any(vm["resource_shortfall"] is not None for vm in row["vms"]):
        alerts.append("guest-resource-shortfall")
    # Not `failed_24h`: that counts failures a later success superseded
    # and failures of policies since disabled.
    if row["backups"] is not None and row["backups"]["failing_vm_ids"]:
        alerts.append("backup-failures")
    if row["backups"] is not None and row["backups"]["overdue_vm_ids"]:
        alerts.append("backup-overdue")
    return alerts


def operator_fleet(*, include_chain: bool = True) -> dict[str, Any]:
    """`GET /v1/operator/fleet` — every miner + fleet totals. See the
    module docstring for sources and cost."""
    now = timezone.now()
    snapshot, chain_error = _read_chain() if include_chain else (None, "not-requested")
    chain_by_node = {m.node_id.lower(): m for m in snapshot.miners} if snapshot is not None else {}

    identities = list(MinerIdentity.objects.select_related("location").all())
    mirror = list(MinerCapacity.objects.all())
    mirror_by_node = {r.miner_node_id.lower(): r for r in mirror}
    hosted_by_node, committed, unresolved = _hosted_by_node(identities)
    load_of = {r.miner_node_id: committed.get(r.miner_node_id, _Committed()) for r in mirror}
    capacity = scheduler_service._capacity_results_by_node(
        {k: v.count for k, v in load_of.items()},
        {k: v.memory_mb for k, v in load_of.items()},
        {k: v.cpus for k, v in load_of.items()},
        rows=mirror,
    )
    capacity = {k.lower(): v for k, v in capacity.items()}
    raw_budgets = scheduler_service.host_budgets_by_node(rows=mirror)
    views = {
        k.lower(): v
        for k, v in scheduler_service.capacity_views(rows=mirror, budgets=raw_budgets).items()
    }
    budgets = {k.lower(): v for k, v in raw_budgets.items()}

    attestor_map, best_attestor = _attestors(now)
    gate = attestor_map if scheduler_service.attestor_gate_enforced() else None
    failed_over = scheduler_service.failover_quarantined_miner_ids()
    release_version = dict(HostAttestorRelease.objects.values_list("measurement", "version"))

    billing_epoch = scoring.billing_epoch()
    usage = _usage_by_node(billing_epoch)
    weights = {k.lower(): v for k, v in scoring.compute_epoch_weights().items()}
    owed: dict[str, int] = {}
    if snapshot is not None and billing_epoch is not None:
        owed = {
            k.lower(): v
            for k, v in scoring.compute_owed_micro_usd(
                scheduler_service.price_by_node(snapshot)
            ).items()
        }
    backups = _backups_by_miner(now - BACKUP_WINDOW)
    backup_attention = _backup_attention(now)
    zombies = _zombies_by_node(now)
    shortfalls = guest_resources.flagged(now)
    public_ips = dict(
        PublicIP.objects.filter(state=PublicIpState.ATTACHED.value, vm__isnull=False).values_list(
            "vm__vm_id", "address"
        )
    )
    liveness_s = scheduler_service.miner_liveness_timeout_s()
    # The epoch the stale-epoch gate compares against: the chain's, else
    # the last one mirrored (what the scheduler saw on its last read).
    current_epoch = snapshot.current_epoch if snapshot is not None else billing_epoch

    identity_by_node: dict[str, MinerIdentity] = {}
    unbridged: list[MinerIdentity] = []
    for m in identities:
        if m.chain_node_id:
            identity_by_node[m.chain_node_id.lower()] = m
        else:
            unbridged.append(m)
    node_ids = sorted(set(identity_by_node) | set(mirror_by_node) | set(chain_by_node))

    rows: list[dict[str, Any]] = []
    for nid in node_ids:
        miner = identity_by_node.get(nid)
        rows.append(
            _row(
                nid=nid,
                miner=miner,
                mirror=mirror_by_node.get(nid),
                chain_view=chain_by_node.get(nid),
                chain_ok=snapshot is not None,
                result=capacity.get(nid),
                view=views.get(nid),
                budget=budgets.get(nid),
                hosted=hosted_by_node.get(nid, []),
                attestor=best_attestor[nid][0] if nid in best_attestor else None,
                attestor_gate_reason=attestor_map.reason_for(nid),
                release_version=release_version,
                gate=gate,
                failed_over=failed_over,
                usage=usage.get(nid),
                weight=weights.get(nid),
                owed=owed.get(nid),
                backups=_backups_of(
                    hosted_by_node.get(nid, []),
                    backups.get(miner.miner_id) if miner is not None else None,
                    backup_attention,
                ),
                zombie=zombies.get(nid),
                public_ips=public_ips,
                shortfalls=shortfalls,
                liveness_s=liveness_s,
                current_epoch=current_epoch,
                now=now,
            )
        )
    for m in unbridged:
        rows.append(
            _row(
                nid=None,
                miner=m,
                mirror=None,
                chain_view=None,
                chain_ok=snapshot is not None,
                result=None,
                hosted=[],
                attestor=None,
                attestor_gate_reason=None,
                release_version=release_version,
                gate=gate,
                failed_over=failed_over,
                usage=None,
                weight=None,
                owed=None,
                backups=_backups_of([], backups.get(m.miner_id), backup_attention),
                zombie=None,
                public_ips=public_ips,
                shortfalls=shortfalls,
                liveness_s=liveness_s,
                current_epoch=current_epoch,
                now=now,
            )
        )
    for row in rows:
        row["alerts"] = _alerts(row, now=now)
        # Internal helper for `_alerts`; never on the wire.
        if row["attestor"] is not None:
            row["attestor"].pop("cert_expiry_at_dt")

    return {
        "miners": rows,
        "totals": _totals(rows),
        "chain": {
            "available": snapshot is not None,
            "error": chain_error,
            "current_epoch": snapshot.current_epoch if snapshot is not None else None,
            "pallet_live": snapshot.pallet_live if snapshot is not None else None,
        },
        "billing_epoch": billing_epoch,
        "policy": {
            "attestor_gate_enforced": gate is not None,
            "liveness_timeout_s": liveness_s,
            "epoch_weight_source": str(getattr(settings, "VALI_EPOCH_WEIGHT_SOURCE", "snapshot")),
            "disk_gate": capacity_config.disk_gate_mode(),
            "disk_unknown": capacity_config.disk_unknown_policy(),
            "disk_reserve_gb": capacity_config.disk_reserve_gb(),
            "flavors": {
                name: {
                    "cpu_count": flavors.resolve_flavor(name).cpu_count,
                    "memory_mb": flavors.resolve_flavor(name).memory_mb,
                    # The tenant DATA disk (`hippius.disk_gb`), and what one VM
                    # commits on its host's data fs (+ the rootfs).
                    "disk_gb": flavors.resolve_flavor(name).data_disk_size_gb,
                    "committed_disk_gb": scheduler_service.flavor_disk_gb(name),
                    "offered": flavors.is_offered(name),
                }
                for name in flavors.FLAVOR_NAMES
            },
        },
        # Hosted VMs whose `Vm.host` names no known miner — shown so a VM is
        # never silently missing from the page.
        "unresolved_vms": [
            {
                **_serialize_vm(h, public_ips, shortfalls),
                "host": h.vm.host if h.role == "host" else h.vm.migration_dest,
            }
            for h in unresolved
        ],
        "generated_at": _iso(now),
    }


def _row(
    *,
    nid: str | None,
    miner: MinerIdentity | None,
    mirror: MinerCapacity | None,
    chain_view: chain.MinerView | None,
    chain_ok: bool,
    result: Any,
    hosted: list[_Hosted],
    attestor: HostAttestor | None,
    attestor_gate_reason: str | None,
    release_version: dict[str, str],
    gate: Any,
    failed_over: frozenset[str],
    usage: dict[str, int] | None,
    weight: int | None,
    owed: int | None,
    backups: dict[str, Any] | None,
    zombie: dict[str, Any] | None,
    public_ips: dict[str, str],
    shortfalls: dict[str, guest_resources.GuestResourceShortfallView],
    liveness_s: int,
    current_epoch: int | None,
    now: datetime,
    view: scheduler_service.CapacityView | None = None,
    budget: HostBudget | None = None,
) -> dict[str, Any]:
    last_seen = miner.last_seen_at if miner is not None else None
    location: MinerLocation | None = _location_of(miner) if miner is not None else None

    for h in hosted:
        # Admission sums placements under the mirror row's exact node id.
        h.counted = h.live is not None and (
            mirror is None or h.live.miner_node_id == mirror.miner_node_id
        )
    vms = [_serialize_vm(h, public_ips, shortfalls) for h in hosted]
    # One placement counts once, even when two entries point at it (a §25
    # move whose source and destination name the same node).
    counted = list({h.live.pk: h.live for h in hosted if h.counted and h.live is not None}.values())
    outside = [h for h in hosted if _outside_admission(h)]
    running_here = [h for h in hosted if h.role == "host"]
    by_state: dict[str, int] = {}
    for h in running_here:
        vm = h.vm
        key = vm.state if vm.state != VmState.ACTIVE else f"active:{vm.power_state}"
        by_state[key] = by_state.get(key, 0) + 1

    cap: dict[str, Any] | None = None
    if mirror is not None:
        used = len(counted)
        slots = result.slots if result is not None else mirror.capacity_slots
        cap = {
            "operator_max_slots": mirror.capacity_slots,
            "effective_slots": slots,
            "used_slots": used,
            "free_slots": max(0, slots - used),
            "dynamic": bool(result.dynamic) if result is not None else False,
            "over_claim": bool(result.over_claim) if result is not None else False,
            "total_memory_mb": mirror.total_memory_mb,
            "total_cpus": mirror.total_cpus,
            "budget_memory_mb": result.budget_memory_mb if result is not None else None,
            "budget_cpus": result.budget_cpus if result is not None else None,
            "free_memory_mb": result.free_memory_mb if result is not None else None,
            "free_cpus": result.free_cpus if result is not None else None,
            "committed_memory_mb": sum(
                scheduler_service._committed_resources(p.resource_class)[0] for p in counted
            ),
            "committed_cpus": sum(
                scheduler_service._committed_resources(p.resource_class)[1] for p in counted
            ),
            # Running here, not counted by admission (see `_outside_admission`):
            # the scheduler believes this much more is free than really is.
            "uncounted_vms": len(outside),
            "uncounted_memory_mb": sum(
                scheduler_service._committed_resources(_flavor_of(h))[0] for h in outside
            ),
            "uncounted_cpus": sum(
                scheduler_service._committed_resources(_flavor_of(h))[1] for h in outside
            ),
            "reported_memory_available_mib": mirror.reported_memory_available_mib,
            "reported_at": _iso(mirror.reported_at),
            "flavor_headroom": _flavor_headroom(result, view, budget),
            # What admission would take here NOW, per flavor (see
            # `service.CapacityView.free_by_flavor`).
            "free_by_flavor": dict(view.free_by_flavor) if view is not None else None,
            # The ACTIVE admission model and its units (`CapacityView`) —
            # the same numbers `/v1/operator/regions` sums.
            "model": view.model if view is not None else None,
            "units": (
                {
                    "total": view.total_units,
                    "committed": view.committed_units,
                    "free": view.free_units,
                }
                if view is not None
                else None
            ),
            "trust_class": mirror.trust_class,
            "cpu_ratio": str(mirror.cpu_ratio) if mirror.cpu_ratio is not None else None,
            # Capacity v2 budget, ALWAYS shown (also while v1 decides) — the
            # shadow run is judged by comparing it with the v1 figures above.
            "v2": _v2_budget(budget),
            # The DATA-disk dimension (storage-aware placement).
            "disk": _disk_row(mirror, budget),
        }

    chain_row: dict[str, Any] | None = None
    if chain_view is not None:
        chain_row = {
            "source": "chain",
            "status": chain_view.status,
            "quality": str(chain_view.quality),
            "data_epoch": chain_view.data_epoch,
            "last_transition_epoch": chain_view.last_transition_epoch,
            "price": chain_view.price,
            "refreshed_at": None,
        }
    elif mirror is not None:
        # Chain not read, or this node is absent from a chain read that
        # worked (a leftover mirror row): the last mirrored on-chain view,
        # stamped with when it was taken. Never counted as on-chain active.
        chain_row = {
            "source": "mirror" if not chain_ok else "mirror-absent-from-chain",
            "status": mirror.status,
            "quality": str(mirror.quality),
            "data_epoch": mirror.data_epoch,
            "last_transition_epoch": None,
            "price": None,
            "refreshed_at": _iso(mirror.refreshed_at),
        }

    attestor_row: dict[str, Any] | None = None
    if attestor is not None:
        attestor_row = {
            "status": attestor.status,
            "gate_reason": attestor_gate_reason,
            "cert_expiry_at": _iso(attestor.cert_expiry_at),
            "cert_expiry_at_dt": attestor.cert_expiry_at,
            "measurement": attestor.measurement,
            "release_version": release_version.get(attestor.measurement) or None,
            "last_seen_at": _iso(attestor.last_seen_at),
        }

    cvm: dict[str, Any] = {
        "verdict": cvm_capability.UNKNOWN,
        "last_ok_at": None,
        "last_fail_at": None,
        "fail_streak": 0,
        "last_fail_reason": None,
    }
    if mirror is not None:
        cvm = {
            "verdict": cvm_capability.capability_of_row(mirror, now=now),
            "last_ok_at": _iso(mirror.cvm_last_ok_at),
            "last_fail_at": _iso(mirror.cvm_last_fail_at),
            "fail_streak": mirror.cvm_fail_streak,
            "last_fail_reason": mirror.cvm_last_fail_reason or None,
        }

    identity: dict[str, Any] | None = None
    platform_id = ""
    snp_generation: str | None = None
    if miner is not None:
        platform_id = miner.platform_id
        snp_generation = miner.snp_generation
        identity = {
            "miner_id": miner.miner_id,
            "platform_id": miner.platform_id,
            "snp_generation": miner.snp_generation or None,
            "netbird_ip": miner.netbird_ip,
            "netbird_peer_id": miner.netbird_peer_id or None,
            "registered_at": _iso(miner.registered_at),
        }

    if miner is not None:
        verdict = scheduler_service.dispatchability(
            miner, now=now, attestor=gate, failover_quarantined=failed_over
        )
        dispatchable, dispatch_reason = verdict.dispatchable, verdict.reason
    else:
        dispatchable, dispatch_reason = False, "no-identity"
    schedulable, reason = _placement_verdict(
        dispatchable=dispatchable,
        dispatch_reason=dispatch_reason,
        zombie_quarantined=zombie is not None and zombie["quarantined"],
        chain_row=chain_row,
        on_chain=(chain_view is not None) if chain_ok else None,
        current_epoch=current_epoch,
        cvm_verdict=cvm["verdict"],
        cap=cap,
        # `decide_placement` looks capacity up under the chain's spelling of
        # the node id; a mirror row spelled otherwise is invisible to it.
        capacity_visible=mirror is None
        or mirror.miner_node_id == (chain_view.node_id if chain_view is not None else nid),
        cordoned=mirror is not None and mirror.cordoned_at is not None,
    )

    return {
        "node_id": nid,
        "miner_id": miner.miner_id if miner is not None else None,
        "status": miner.status if miner is not None else None,
        "identity": identity,
        # `None` when the chain was not read; `False` for a node vali
        # still mirrors but the chain no longer lists.
        "on_chain": (chain_view is not None) if chain_ok else None,
        "vcpu_model": (_vcpu_model(platform_id, snp_generation) if platform_id else None),
        "last_seen_at": _iso(last_seen),
        "heartbeat_age_s": (
            int((now - last_seen).total_seconds()) if last_seen is not None else None
        ),
        "heartbeat_stale": last_seen is None or now - last_seen > timedelta(seconds=liveness_s),
        # `dispatchable`: vali can reach + attest it (`/v1/operator/nodes`'s
        # `schedulable`). `schedulable`: a launch could land here NOW — every
        # hard gate of `decide_placement`, in its order, first failure named.
        "dispatchable": dispatchable,
        "dispatchable_reason": dispatch_reason,
        "schedulable": schedulable,
        "schedulable_reason": reason,
        "chain": chain_row,
        "location": _serialize_location(location),
        "capacity": cap,
        # VMs this host runs (the Vm ledger), not what admission counts —
        # that is `capacity.used_slots`; the gap is `capacity.uncounted_*`.
        "vm_count": len(running_here),
        # §25 moves landing here: the guest still runs on its source (and is
        # counted there) until the move completes.
        "incoming_migrations": sum(1 for h in hosted if h.role == "migration-dest"),
        "vm_count_by_state": dict(sorted(by_state.items())),
        "vms": vms,
        "attestor": attestor_row,
        "cvm_start": cvm,
        "zombie": zombie,
        "usage": {
            "epoch_unit_seconds": (usage or {}).get("unit_seconds", 0),
            "epoch_billable_seconds": (usage or {}).get("billable_seconds", 0),
            "epoch_weight": int(weight) if weight is not None else 0,
            "epoch_owed_usd_micros": int(owed) if owed is not None else None,
        },
        "backups": backups,
    }


def _placement_verdict(
    *,
    dispatchable: bool,
    dispatch_reason: str | None,
    zombie_quarantined: bool,
    chain_row: dict[str, Any] | None,
    on_chain: bool | None,
    current_epoch: int | None,
    cvm_verdict: str,
    cap: dict[str, Any] | None,
    capacity_visible: bool = True,
    cordoned: bool = False,
) -> tuple[bool, str | None]:
    """Could `decide_placement` choose this node right now? Its hard gates
    in its own order (`apps.scheduler.placement`); the first one failed is
    the reason. Per-launch gates (region, family cap, owner budget, pin)
    are not properties of the node and are not judged here."""
    if zombie_quarantined:
        return False, "zombie-quarantined"
    if not dispatchable:
        return False, dispatch_reason
    if on_chain is False:
        return False, "not-on-chain"
    if chain_row is None:
        return False, "no-chain-record"
    if chain_row["status"] != MINER_ACTIVE:
        return False, "chain-not-active"
    if (
        current_epoch is not None
        and current_epoch - chain_row["data_epoch"] > scheduler_service.max_epoch_lag()
    ):
        return False, "epoch-stale"
    if cvm_verdict == cvm_capability.INCAPABLE:
        return False, "cvm-incapable"
    if cap is None or not capacity_visible:
        return False, "no-capacity-record"
    # Gate (h), the operator cordon: no new placement, so not schedulable.
    # Reported as the existing `full` ("takes nothing now") rather than a
    # new value, so no consumer of this field has to learn one; the cordon
    # itself and its reason are in `GET /v1/scheduler/capacity` and
    # `vali_set_miner_capacity --show`.
    if cordoned:
        return False, "full"
    # "Full" in the ACTIVE model: under v2 a host is full when no offered
    # flavor fits (it can admit past the v1 slot count, or refuse a host
    # v1 still has slots on); under v1 when no slot is free.
    if cap.get("model") == "v2":
        if not any((cap.get("free_by_flavor") or {}).values()):
            return False, "full"
    elif cap["free_slots"] <= 0:
        return False, "full"
    return True, None


def _totals(rows: list[dict[str, Any]]) -> dict[str, Any]:
    regions: dict[str, int] = {}
    alerts: dict[str, int] = {}
    registered = [r for r in rows if r["identity"] is not None]
    totals: dict[str, Any] = {
        "rows": len(rows),
        # Miners vali holds an identity for — the only ones it can launch
        # onto. Capacity totals sum over these alone, so a leftover mirror
        # row never inflates what the fleet can sell.
        "miners": len(registered),
        "bridged": sum(1 for r in registered if r["node_id"] is not None),
        "schedulable": sum(1 for r in rows if r["schedulable"]),
        "chain_active": sum(
            1
            for r in rows
            if r["chain"] is not None
            and r["chain"]["source"] == "chain"
            and r["chain"]["status"] == "active"
        ),
        "heartbeat_fresh": sum(1 for r in registered if not r["heartbeat_stale"]),
        "vms": sum(r["vm_count"] for r in rows),
        "effective_slots": 0,
        "used_slots": 0,
        "total_memory_mb": 0,
        "total_cpus": 0,
        "free_memory_mb": 0,
        "free_cpus": 0,
        "schedulable_free_slots": 0,
    }
    for r in registered:
        cap = r["capacity"]
        if cap is not None:
            totals["effective_slots"] += cap["effective_slots"]
            totals["used_slots"] += cap["used_slots"]
            totals["total_memory_mb"] += cap["total_memory_mb"] or 0
            totals["total_cpus"] += cap["total_cpus"] or 0
            totals["free_memory_mb"] += cap["free_memory_mb"] or 0
            totals["free_cpus"] += cap["free_cpus"] or 0
            if r["schedulable"]:
                totals["schedulable_free_slots"] += cap["free_slots"]
        loc = r["location"]
        if loc and loc.get("region"):
            regions[loc["region"]] = regions.get(loc["region"], 0) + 1
    for r in rows:
        for a in r["alerts"]:
            alerts[a] = alerts.get(a, 0) + 1
    totals["regions"] = dict(sorted(regions.items()))
    totals["alerts"] = dict(sorted(alerts.items()))
    return totals
