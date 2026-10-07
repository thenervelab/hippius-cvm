"""Scheduler orchestration shared by the views + the re-eval loop.

Spec of record: ARCHITECTURE.md §23 / §13.

This module glues the pure pieces together:

- [`refresh_miner_capacity`] rebuilds the `MinerCapacity` mirror
  cache from a live chain snapshot — preserving the operator-managed
  `capacity_slots` across refreshes.
- [`decision_inputs`] gathers the DB-side accounting
  ([`decide_placement`] needs) for one placement decision.
- [`reeval_once`] is one cycle of the continuous re-evaluation loop:
  refresh the mirror, then §13-drain any `Bound` placement whose
  miner has left `Active` state (or gone stale) — unless the VM is
  still live on that miner, in which case the placement is HELD.
- [`live_vm_placement_drift`] finds every live VM whose active
  placement does not name the host it runs on (the invariant the
  orchestration tick repairs).
- [`move_placement_to_node`] hands a VM's placement custody to a §25
  destination — the one write that makes `Placement` follow the VM
  instead of being stamped once at launch.

Nothing here reaches HTTP — the views translate exceptions to status
codes; the management command drives [`reeval_once`] in a loop.
"""

from __future__ import annotations

import dataclasses
import logging
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import timedelta
from typing import TYPE_CHECKING, Any

from django.conf import settings
from django.db import IntegrityError, transaction
from django.db.models import Count
from django.utils import timezone

from apps.lifecycle.models import VmState

from . import capacity_config, chain
from .capacity import (
    DISK_GATE_DENY,
    DISK_GATE_OFF,
    DISK_UNKNOWN,
    HOST_BUDGET_UNKNOWN,
    BudgetInputs,
    CapacityInputs,
    CapacityResult,
    DiskBudget,
    DiskInputs,
    HostBudget,
    big_enough,
    disk_admits,
    disk_budget,
    disk_gate_state,
    disk_headroom,
    effective_capacity,
    fits,
    free_fraction,
    headroom,
    host_budget,
    units,
)
from .models import (
    ACTIVE_PLACEMENT_STATES,
    MinerCapacity,
    Placement,
    PlacementFailureSource,
    PlacementStatus,
)
from .placement import MINER_ACTIVE, ResourceFit, SelectionWeights, log_disk_would_reject

if TYPE_CHECKING:
    from datetime import datetime

    from apps.lifecycle.models import Vm
    from apps.miners.models import MinerIdentity
    from apps.telemetry.release_service import AttestorCoverageMap

log = logging.getLogger("apps.scheduler.service")


def _default_capacity_slots() -> int:
    return int(getattr(settings, "VALI_SCHEDULER_DEFAULT_CAPACITY_SLOTS", 8))


def _host_reserve_memory_mb() -> int:
    """RAM (MiB) kept for the host OS / hypervisor and never handed to
    tenant VMs when sizing dynamic capacity from the trusted anchor.
    Default 8192: host OS + miner-agent + the host-attestor VM + backup
    workers. The old 2048 was sized for eight VMs, not thirty."""
    return int(getattr(settings, "VALI_SCHEDULER_HOST_RESERVE_MEMORY_MB", 8192))


def _host_reserve_cpus() -> int:
    """vCPU kept for the host OS / hypervisor (dynamic-capacity reserve)."""
    return int(getattr(settings, "VALI_SCHEDULER_HOST_RESERVE_CPUS", 2))


def _slot_ref_memory_mb() -> int:
    """RAM (MiB) one admission slot is worth — the reference flavor used
    to convert free resources into an integer slot count. Default 8192
    (the `large` flavor)."""
    return int(getattr(settings, "VALI_SCHEDULER_SLOT_REF_MEMORY_MB", 8192))


def _slot_ref_cpus() -> int:
    """vCPU one admission slot is worth (reference flavor). Default 4."""
    return int(getattr(settings, "VALI_SCHEDULER_SLOT_REF_CPUS", 4))


def _committed_resources(resource_class: str) -> tuple[int, int]:
    """`(memory_mb, cpus)` one active placement of `resource_class`
    commits, resolved from the TRUSTED flavor table (vali's own data —
    never the miner's word).

    An unknown / legacy `resource_class` (e.g. a pre-flavor `"std"` row)
    conservatively counts as the reference-flavor size, so it still
    consumes committed capacity — fail-closed: unknown load can only
    REDUCE the computed free, never inflate it.
    """
    from apps.orchestration.services.flavors import UnknownFlavor, resolve_flavor

    try:
        size = resolve_flavor(resource_class)
    except UnknownFlavor:
        return _slot_ref_memory_mb(), _slot_ref_cpus()
    return size.memory_mb, size.cpu_count


def _committed_disk_gb(resource_class: str) -> int:
    """DATA-disk GiB one active placement of `resource_class` commits on
    its host, from the TRUSTED flavor table.

    = the flavor's `disk_gb` + `ROOTFS_DISK_GB`. The agent reserves
    `hippius.disk_gb` (= the flavor's `disk_gb`) per VM: the data disk
    (legacy) or the golden overlay upper. The rootfs term is on top of
    that — a legacy VM's per-VM `tenant.qcow2` lives on the same fs, a
    golden VM's base is shared — so this is a CONSERVATIVE SUPERSET of
    what the agent reserves, never less. An unknown / legacy class counts
    as the reference disk (`VALI_SCHEDULER_SLOT_REF_DISK_GB`) — fail
    closed, exactly as `_committed_resources` does for RAM."""
    from apps.orchestration.services.flavors import (
        ROOTFS_DISK_GB,
        UnknownFlavor,
        resolve_flavor,
    )

    try:
        return resolve_flavor(resource_class).data_disk_size_gb + ROOTFS_DISK_GB
    except UnknownFlavor:
        return capacity_config.slot_ref_disk_gb() + ROOTFS_DISK_GB


def max_epoch_lag() -> int:
    """Stale-epoch threshold (§23 fail-closed gate)."""
    return int(getattr(settings, "VALI_SCHEDULER_MAX_EPOCH_LAG", 2))


def max_host_share() -> float:
    """Concentration cap: the max share of all active placements one
    miner may host before it's deprioritised (soft) — bounds the blast
    radius of a single miner going dark. `1.0` ⇒ no cap (default)."""
    return float(getattr(settings, "VALI_SCHEDULER_MAX_HOST_SHARE", 1.0))


def max_recent_failures() -> int:
    """Circuit-breaker: a miner with `≥` this many launch FAILURES inside
    `failure_window_s()` is routed around (soft). `0` ⇒ disabled."""
    return int(getattr(settings, "VALI_SCHEDULER_MAX_RECENT_FAILURES", 3))


def max_owner_placements_per_miner() -> int:
    """Per-owner sub-budget: a miner where one OWNER already holds `≥` this
    many active placements is deprioritised for that owner (soft — audit
    M-per-tenant-cap). `0` ⇒ disabled."""
    return int(getattr(settings, "VALI_SCHEDULER_MAX_OWNER_PLACEMENTS_PER_MINER", 4))


def max_booting_per_miner() -> int:
    """Gate (g): the most guests one miner may be booting at once before
    the launch path stops placing on it (`booting_by_node`). `0` ⇒ no cap."""
    return max(0, int(getattr(settings, "VALI_SCHEDULER_MAX_BOOTING_PER_MINER", 3)))


def booting_by_node(*, now: datetime | None = None) -> dict[str, int]:
    """`{node_id: guests booting there now}` — gate (g)'s input.

    A guest is booting on a node when its active placement there is:

    - `Pending` while its VM's `LaunchJob` is `running` and the row is
      younger than `stale_pending_after_s` — a launch being dispatched (the
      miner preflight can take minutes, the boot follows). The live job:
      a launch that died with its row still `Pending` (an exception out of
      the dispatch) must not hold a boot slot until the stale-Pending
      sweep. The age: a worker killed between the row and its `dispatching`
      phase leaves a job the orphan reaper deliberately keeps `running`;
    - `Bound`, the VM `active` and powered `running`/`starting`, and its
      CURRENT boot (`Vm.boot_started_at`, else `created_at`) has produced
      neither an in-guest signal nor a `running` milestone yet — while
      inside the boot-stall deadline for its disk (`boot_stall.deadline_s`).

    The boot clock is restamped by every new boot — first launch, §25
    destination, reboot-recovery, power start, resize and guest-upgrade
    relaunches — so all of them count against their host. None of those
    paths places through gate (g), so they can never wait on it themselves
    (nor do operator-named launches or `/v1/scheduler/place`): this is
    admission control for scheduled launches, not a global boot cap.

    A count at decision time, not a reservation: two placements decided at
    the same instant could both see room. The launch tick runs one job at a
    time (deployed as a single instance), so the bound holds in practice.

    Past its deadline a boot is STALLED, not booting, and stops counting:
    a guest that never comes up cannot hold its host's boot slots forever.
    An image WITHOUT the telemetry agent never signals, so each of its
    boots holds a slot for the whole deadline (every in-cluster bake
    installs the agent; `boot_stall` documents the same limit)."""
    from django.db.models import F, Q
    from django.db.models.functions import Coalesce

    from apps.lifecycle import boot_stall
    from apps.lifecycle.models import VmBootPhase, VmPowerState
    from apps.orchestration.models import LaunchJob, LaunchJobState

    now = now or timezone.now()
    out: dict[str, int] = {}
    dispatching = LaunchJob.objects.filter(state=LaunchJobState.RUNNING.value).values("vm_id")
    for nid in Placement.objects.filter(
        status=PlacementStatus.PENDING.value,
        vm__vm_id__in=dispatching,
        decided_at__gte=now - timedelta(seconds=stale_pending_after_s()),
    ).values_list("miner_node_id", flat=True):
        out[nid] = out.get(nid, 0) + 1
    rows = (
        Placement.objects.filter(
            status=PlacementStatus.BOUND.value,
            vm__state=VmState.ACTIVE,
            vm__power_state__in=(VmPowerState.RUNNING, VmPowerState.STARTING),
        )
        .annotate(boot_clock=Coalesce("vm__boot_started_at", "vm__created_at"))
        .filter(Q(vm__guest_signal_at__isnull=True) | Q(vm__guest_signal_at__lt=F("boot_clock")))
        .exclude(vm__boot_phase=VmBootPhase.RUNNING, vm__boot_phase_at__gte=F("boot_clock"))
        .values_list("miner_node_id", "resource_class", "data_disk_gb", "boot_clock")
    )
    for nid, resource_class, data_disk_gb, boot_clock in rows:
        disk_gb = data_disk_gb or _flavor_data_disk_gb(resource_class)
        if (now - boot_clock).total_seconds() <= boot_stall.deadline_s(disk_gb):
            out[nid] = out.get(nid, 0) + 1
    return out


def failure_window_s() -> int:
    """The look-back window (seconds) for the circuit-breaker's recent-
    failure count."""
    return int(getattr(settings, "VALI_SCHEDULER_FAILURE_WINDOW_S", 600))


def recent_failures_by_node() -> dict[str, int]:
    """`{node_id: count}` of `Placement`s that went FAILED within the
    circuit-breaker window — the signal `decide_placement` routes around a
    broken miner with. Reuses the existing FAILED placement rows (each
    carries `failed_at`), so no new schema. Empty when the breaker is
    disabled (`max_recent_failures() == 0`) — skip the query entirely."""
    if max_recent_failures() <= 0:
        return {}
    cutoff = timezone.now() - timedelta(seconds=failure_window_s())
    out: dict[str, int] = {}
    for row in (
        Placement.objects.filter(status=PlacementStatus.FAILED.value, failed_at__gte=cutoff)
        .values("miner_node_id")
        .annotate(n=Count("id"))
    ):
        out[row["miner_node_id"]] = row["n"]
    return out


def cvm_capability_by_node() -> dict[str, str]:
    """`{node_id: "proven"|"unknown"|"incapable"}` — the OBSERVED SEV-SNP
    start-capability ledger `decide_placement` takes as
    `cvm_capability_by_node`.

    A thin re-export so every `decide_placement` input is reached the
    same way (`service.<something>_by_node()`) at each of the five call
    sites; the policy itself lives in [`cvm_capability`].
    """
    from .cvm_capability import capability_by_node

    return capability_by_node()


def miner_liveness_timeout_s() -> int:
    """Max age of a miner's last accepted heartbeat before it is treated
    as dark and excluded from NEW placements (§23 liveness gate). Default
    180s — heartbeats arrive ~every minute, so this tolerates a couple of
    missed beats before fail-closing."""
    return int(getattr(settings, "VALI_MINER_LIVENESS_TIMEOUT_S", 180))


# The AMD CHIP_ID length is generation-dependent: Milan/Genoa report a
# 64-byte id (128 hex), Turin an 8-byte id (16 hex — same value AMD's
# KDS keys the Turin VCEK URL on). Require ≥ 8 bytes of VALID hex so a
# real chip_id of EITHER generation passes, while a human-readable
# placeholder label ("epyc-9255-miner3", the auto-provision
# `onchain:<node_id>`) is rejected — those are not valid hex (and the
# auto-provision placeholder is refused explicitly besides), and a
# launch ticket pinned to a label cannot bind the miner's SNP/VCEK
# identity (it would fail attestation). The exact length is not
# load-bearing here: the KBS attestation is the real check; this gate
# only keeps the scheduler off un-attestable miners.
_CHIP_ID_MIN_HEX = 16


def _is_real_chip_id(platform_id: str) -> bool:
    from apps.miners.models import is_autoprovision_placeholder

    pid = (platform_id or "").strip()
    if is_autoprovision_placeholder(pid):
        return False
    if len(pid) < _CHIP_ID_MIN_HEX or len(pid) % 2:
        return False
    try:
        bytes.fromhex(pid)
    except ValueError:
        return False
    return True


def dispatchable_node_ids() -> frozenset[str]:
    """On-chain `node_id`s vali can ACTUALLY launch onto — i.e. those
    with a complete + live local `MinerIdentity`. Passed to
    [`decide_placement`] as `dispatchable=…` so a node the chain marks
    `Active` but vali cannot reach/attest is never even a candidate.

    This is the testnet↔mainnet equaliser: on mainnet the §23 attested
    keepalive keeps the on-chain `Active` set honest; on testnet that
    enforcement is absent (phantom registrations linger `Active`). This
    gate makes placement behave identically either way — vali only
    schedules onto a miner it can reach (NetBird) and attest (real
    CHIP_ID), and only while it is heart-beating.

    A node qualifies iff its `MinerIdentity`:
    - has a `chain_node_id` (bridged to the chain) and a `netbird_ip`,
    - carries a real AMD CHIP_ID in `platform_id` (hex, not a label),
    - is locally `ACTIVE` (not operator-quarantined), and
    - heart-beat within `miner_liveness_timeout_s()`.

    Blackbox host-attestor gate (PR-11), behind `VALI_HOST_ATTESTOR_GATE_ENFORCE`
    (DEFAULT FALSE ⇒ this returns exactly the set above): when armed, the set
    is ADDITIVELY narrowed to nodes that ALSO carry an `attested` (NEVER
    `pending`) host-attestor seen within the liveness window on a desired
    measurement. The gate can only REMOVE candidates, never add — the
    existing on-chain-Active + heartbeat + reachable gates always apply first.

    The per-node verdict is [`dispatchability`] — this is its set
    projection. The DB filter below is a superset pre-filter for the
    common case (most rows are live); the predicate itself is applied by
    `dispatchability`, so the two cannot disagree.
    """
    from apps.miners.models import MinerIdentity, MinerStatus

    now = timezone.now()
    cutoff = now - timedelta(seconds=miner_liveness_timeout_s())
    attestor = attestor_gate(now=now)
    ok: set[str] = set()
    rows = MinerIdentity.objects.filter(
        status=MinerStatus.ACTIVE,
        chain_node_id__isnull=False,
        netbird_ip__isnull=False,
        last_seen_at__gte=cutoff,
    ).only("chain_node_id", "platform_id", "status", "netbird_ip", "last_seen_at")
    quarantined = failover_quarantined_miner_ids()
    for m in rows:
        if dispatchability(
            m, now=now, attestor=attestor, failover_quarantined=quarantined
        ).dispatchable:
            ok.add(m.chain_node_id.lower())
    return frozenset(ok)


def failover_quarantined_miner_ids() -> frozenset[str]:
    """`miner_id`s a manual failover declared dead and no operator cleared
    yet (`orchestration.FailoverQuarantine`)."""
    from apps.orchestration.models import FailoverQuarantine

    return frozenset(
        FailoverQuarantine.objects.filter(cleared_at__isnull=True).values_list(
            "miner_id", flat=True
        )
    )


# ─── per-node dispatchability (the predicate behind the set) ─────────
#
# Reason vocabulary: each value names the FIRST gate a node fails, in the
# order `dispatchable_node_ids` applies them. Defined ONCE in
# `apps.scheduler.reasons` (shared with the host-attestor gate in
# `apps.telemetry.release_service` and with the operator serializer, so
# the predicate and the readout cannot drift); re-exported here.

from .reasons import (  # noqa: E402,F401  — re-exported, deliberately late
    REASON_FAILOVER_QUARANTINED,
    REASON_HEARTBEAT_STALE,
    REASON_NOT_ACTIVE,
    REASON_NOT_BRIDGED,
    REASON_PLATFORM_ID_INVALID,
    REASON_QUARANTINED,
    REASON_UNREACHABLE,
)


@dataclass(frozen=True)
class Dispatchability:
    """One node's verdict: `dispatchable` and, when `False`, the single
    gate it failed (`reason`, from the vocabulary above + the attestor
    reasons). `reason is None` iff `dispatchable`."""

    dispatchable: bool
    reason: str | None


def attestor_gate_enforced() -> bool:
    return bool(getattr(settings, "VALI_HOST_ATTESTOR_GATE_ENFORCE", False))


def attestor_gate(*, now: datetime | None = None) -> AttestorCoverageMap | None:
    """The host-attestor coverage map when the gate is armed, else `None`
    (gate off ⇒ the attestor predicate is simply absent). Evaluated ONCE
    per fleet pass and handed to every `dispatchability` call."""
    if not attestor_gate_enforced():
        return None
    from apps.telemetry.release_service import attestor_coverage_by_node

    return attestor_coverage_by_node(now=now)


def dispatchability(
    node: MinerIdentity,
    *,
    now: datetime | None = None,
    attestor: AttestorCoverageMap | None = None,
    failover_quarantined: frozenset[str] | None = None,
) -> Dispatchability:
    """Whether vali can launch onto `node` RIGHT NOW, and if not, why.

    The single predicate `dispatchable_node_ids` is built from — the
    operator readout calls this too, so "schedulable" on the dashboard and
    "candidate" in the scheduler are the same computation. Gates in the
    order the scheduler applies them; the first failure is the reason.

    `attestor` is the fleet-wide coverage map when the host-attestor gate
    is armed (see `attestor_gate`), `None` when it is off — pass the SAME
    map to every node of one pass so the gate is read once. Same for
    `failover_quarantined` (`failover_quarantined_miner_ids`); `None` reads
    this node's quarantine on its own.
    """
    from apps.miners.models import MinerStatus

    now = now or timezone.now()
    if node.status != MinerStatus.ACTIVE:
        if node.status == MinerStatus.QUARANTINED:
            return Dispatchability(False, REASON_QUARANTINED)
        return Dispatchability(False, REASON_NOT_ACTIVE)
    if failover_quarantined is None:
        from apps.orchestration.models import FailoverQuarantine

        failed_over = FailoverQuarantine.objects.filter(
            miner_id=node.miner_id, cleared_at__isnull=True
        ).exists()
    else:
        failed_over = node.miner_id in failover_quarantined
    if failed_over:
        return Dispatchability(False, REASON_FAILOVER_QUARANTINED)
    if not node.chain_node_id:
        return Dispatchability(False, REASON_NOT_BRIDGED)
    if not node.netbird_ip:
        return Dispatchability(False, REASON_UNREACHABLE)
    cutoff = now - timedelta(seconds=miner_liveness_timeout_s())
    if node.last_seen_at is None or node.last_seen_at < cutoff:
        return Dispatchability(False, REASON_HEARTBEAT_STALE)
    if not _is_real_chip_id(node.platform_id):
        return Dispatchability(False, REASON_PLATFORM_ID_INVALID)
    if attestor is not None:
        reason = attestor.reason_for(node.chain_node_id)
        if reason is not None:
            return Dispatchability(False, reason)
    return Dispatchability(True, None)


def refresh_miner_capacity(snapshot: chain.ChainSnapshot) -> None:
    """Upsert the `MinerCapacity` mirror from a chain snapshot.

    The chain-sourced fields (`status`, `quality`, epochs) are
    overwritten every refresh; `capacity_slots` is operator-managed
    and **preserved** on existing rows (only seeded with the default
    on first sight of a miner).
    """
    now = timezone.now()
    default_slots = _default_capacity_slots()
    for miner in snapshot.miners:
        chain_fields = {
            "status": miner.status,
            "quality": miner.quality,
            "observed_epoch": snapshot.current_epoch,
            "data_epoch": miner.data_epoch,
            "refreshed_at": now,
        }
        existing = MinerCapacity.objects.filter(miner_node_id=miner.node_id).first()
        if existing is None:
            try:
                MinerCapacity.objects.create(
                    miner_node_id=miner.node_id,
                    capacity_slots=default_slots,
                    **chain_fields,
                )
            except IntegrityError:
                # A concurrent refresh created the row between the
                # SELECT and the INSERT — fall through to an update
                # so `capacity_slots` is left at whatever it has.
                MinerCapacity.objects.filter(miner_node_id=miner.node_id).update(**chain_fields)
        else:
            MinerCapacity.objects.filter(pk=existing.pk).update(**chain_fields)


def price_by_node(snapshot: chain.ChainSnapshot) -> dict[str, int]:
    """`{node_id: announced_price}` for the §23 marketplace price term —
    only miners that have actually announced a `MinerPrice` on-chain. A
    miner with no price is omitted (the scheduler treats it as
    price-neutral; the tenant ceiling never trips on it)."""
    return {m.node_id: m.price for m in snapshot.miners if m.price is not None}


def max_family_per_node(family: str = "") -> int | None:
    """Hard ceiling on same-family VMs per host for `family` (a tenant id),
    or `None` for no cap.

    `None` is the deliberate default: the RANKING already spreads (see
    `SelectionWeights.spread`), and a numeric cap here is a capacity
    policy, not a safety property. Set `VALI_MAX_FAMILY_PER_NODE` to a
    positive integer to enforce one.

    The CDN fleet is the exception (docs/design/cdn.md, CDN plan N2): one
    CDN node per host, whatever the setting, while `VALI_CDN_ENABLED` is
    on — two nodes on one miner would fail together and halve the
    region's spread for nothing.
    """
    from django.conf import settings

    from apps.common.cdn import cdn_role

    if cdn_role(family):
        return 1

    raw = getattr(settings, "VALI_MAX_FAMILY_PER_NODE", None)
    try:
        n = int(raw)
    except (TypeError, ValueError):
        return None
    return n if n > 0 else None


def cdn_family_cap(family: str) -> int | None:
    """The CDN fleet's one-node-per-host cap alone (`1` under `cdn_role`,
    else `None`), for the placement paths that never applied
    `VALI_MAX_FAMILY_PER_NODE` — re-placement, auto-migration, the
    price-watch suggestion — so they change for nobody else."""
    from apps.common.cdn import cdn_role

    return 1 if cdn_role(family) else None


def decision_inputs(
    vm_family: str,
) -> tuple[dict[str, int], dict[str, int], dict[str, int]]:
    """Gather the DB accounting for one [`decide_placement`] call.

    Returns `(capacity_by_node, load_by_node, family_load_by_node)`:

    - `capacity_by_node` — `{node_id: effective admission slots}`. The
                           DYNAMIC, untrusted-miner-safe bound (see
                           `capacity.effective_capacity`): sized from the
                           operator-registered trusted hardware anchor
                           minus vali's own committed load, throttled
                           DOWN-only by the miner's self-report, and
                           clamped by the operator `capacity_slots`
                           ceiling. A miner with NO trusted anchor set
                           falls back to the flat `capacity_slots` (no
                           regression).
    - `load_by_node`     — `{node_id: active placement count}`.
    - `family_load_by_node` — `{node_id: active placements of THIS
                           family}`. A COUNT: anti-affinity ranks a host
                           down per same-family VM rather than excluding
                           it, so a tenant is no longer capped at one VM
                           per miner.
    """
    load: dict[str, int] = {}
    committed_mb: dict[str, int] = {}
    committed_cpus: dict[str, int] = {}
    # COUNT per node, not a set: anti-affinity is a preference with a
    # ceiling now, so the ranking needs to know HOW MANY, not merely
    # whether. A set silently capped a tenant at one VM per miner.
    family_load: dict[str, int] = {}
    # Sum vali's OWN committed load per miner from the Placement ledger —
    # the TRUSTED view (no miner input): count + Σ flavor mem/cpu.
    for row in Placement.objects.filter(status__in=ACTIVE_PLACEMENT_STATES).values(
        "miner_node_id", "vm_family", "resource_class"
    ):
        node_id = row["miner_node_id"]
        load[node_id] = load.get(node_id, 0) + 1
        mem, cpus = _committed_resources(row["resource_class"])
        committed_mb[node_id] = committed_mb.get(node_id, 0) + mem
        committed_cpus[node_id] = committed_cpus.get(node_id, 0) + cpus
        if row["vm_family"] == vm_family:
            family_load[node_id] = family_load.get(node_id, 0) + 1
    from apps.common.cdn import cdn_role

    if cdn_role(vm_family):
        # One CDN node per host is a hard rule: count every node a host
        # carries or is about to, not only the placement ledger.
        for node_id, n in cdn_node_load(vm_family).items():
            family_load[node_id] = max(family_load.get(node_id, 0), n)

    capacity = _effective_capacity_by_node(load, committed_mb, committed_cpus)
    return capacity, load, family_load


def cdn_node_load(tenant_id: str, *, exclude_vm_id: str = "") -> dict[str, int]:
    """`{chain node_id: CDN nodes on it or headed to it}` for the CDN tenant
    (CDN plan N2), from vali's own records: each live VM's host
    (`Vm.host`, else its launch's miner), its `migration_dest` once fenced,
    and the destination of any §25 / restore job still in flight — which
    the placement ledger only learns at activation. A host gone dark still
    counts: the node may come back there. `exclude_vm_id` leaves one VM
    out (the one being moved)."""
    from apps.lifecycle.models import Vm
    from apps.miners.models import MinerIdentity
    from apps.orchestration.effects import _bound_miner_id
    from apps.orchestration.models import TERMINAL_MIGRATION_STATES, MigrationJob

    rows = Vm.objects.filter(tenant_id=tenant_id).exclude(state=VmState.DESTROYED)
    if exclude_vm_id:
        rows = rows.exclude(vm_id=exclude_vm_id)
    vms = list(rows)
    if not vms:
        return {}
    miners: dict[int, set[str]] = {vm.pk: {_bound_miner_id(vm), vm.migration_dest} for vm in vms}
    for vm_pk, dest in (
        MigrationJob.objects.filter(vm_id__in=miners)
        .exclude(state__in=TERMINAL_MIGRATION_STATES)
        .values_list("vm_id", "dest_node_id")
    ):
        miners[vm_pk].add(dest)
    chain_by_miner = dict(
        MinerIdentity.objects.filter(miner_id__in=set().union(*miners.values()) - {""})
        .exclude(chain_node_id__isnull=True)
        .values_list("miner_id", "chain_node_id")
    )
    load: dict[str, int] = {}
    for held in miners.values():
        for node_id in {chain_by_miner.get(m) for m in held} - {None, ""}:
            load[node_id] = load.get(node_id, 0) + 1
    return load


def cdn_edge_arguments(family: str, vm_id: str = "") -> dict[str, Any]:
    """Gate (j)'s [`decide_placement`] argument for `family`: under
    `cdn_role`, the nodes whose VERIFIED country is one the CDN node may run
    in (`network.service.cdn_edge_regions` — its address's edge region, else
    a region with a free CDN address on an attachable edge). `{}` — no
    query — for every other family."""
    from apps.common.cdn import cdn_role

    if not cdn_role(family):
        return {}
    from apps.network.service import cdn_edge_regions

    regions = cdn_edge_regions(vm_id)
    return {
        "cdn_local_edge": frozenset(
            nid for nid, cc in region_by_node(verified_only=True).items() if cc in regions
        )
    }


def cdn_edge_reason(tenant_id: str, vm_id: str, miner_id: str) -> str | None:
    """Gate (j) for a miner a caller names: why `miner_id` must not take
    the CDN node `vm_id`, or `None`. Always `None` outside `cdn_role`."""
    from apps.common.cdn import cdn_role

    if not cdn_role(tenant_id):
        return None
    from apps.network.service import cdn_edge_regions, cdn_host_region

    country = cdn_host_region(miner_id)
    regions = cdn_edge_regions(vm_id)
    if country and country in regions:
        return None
    return (
        f"miner {miner_id!r} (verified country {country or 'unknown'}) has no local edge "
        f"for this CDN node (allowed: {sorted(regions) or 'none'})"
    )


def cdn_dest_reason(tenant_id: str, vm_id: str, miner_id: str) -> str | None:
    """Every CDN rule for a miner a caller names: one node per host and a
    local edge."""
    return cdn_colocation_reason(tenant_id, vm_id, miner_id) or cdn_edge_reason(
        tenant_id, vm_id, miner_id
    )


def cdn_colocation_reason(tenant_id: str, vm_id: str, miner_id: str) -> str | None:
    """Why `miner_id` must not take the CDN node `vm_id` — another CDN node
    is on it or headed to it — or `None`. For the paths that name a miner
    instead of asking [`decide_placement`] (an explicit §25 or restore
    destination, `vali_create_vm`). Always `None` outside `cdn_role`."""
    from apps.common.cdn import cdn_role
    from apps.miners.models import MinerIdentity

    if not cdn_role(tenant_id):
        return None
    node_id = (
        MinerIdentity.objects.filter(miner_id=miner_id)
        .values_list("chain_node_id", flat=True)
        .first()
    )
    if node_id and cdn_node_load(tenant_id, exclude_vm_id=vm_id).get(node_id):
        return f"miner {miner_id!r} already carries a CDN node (one per host)"
    return None


@dataclass(frozen=True)
class HostResources:
    """What one host has free NOW, and what it could ever offer.

    Both are needed and they answer different questions. `free_*` says
    whether there is room at this instant; `budget_*` (`total − reserve`)
    says whether the hardware is big enough at all. Confusing the two
    makes a full fleet look permanently incapable.
    """

    free_memory_mb: int | None
    free_cpus: int | None
    budget_memory_mb: int | None
    budget_cpus: int | None


def region_by_node(*, verified_only: bool | None = None) -> dict[str, str]:
    """`{chain node_id (lower): country_code (upper)}` — the regions the
    geo-probe has DETECTED miners in. The input [`decide_placement`] takes
    as `region_by_node` and the feasibility check filters hosts on.

    WHICH rows count is not decided here: `geo.placeable_locations` is the
    one rule shared with `GET /v1/operator/regions`, so the regions API
    never advertises a miner this gate would refuse. It admits a row only
    when a country is known, the miner is chain-bridged, the row is FRESH
    (`VALI_GEO_MAX_AGE_S` — a probe that stopped must not leave a
    `verified` standing forever) and the verdict is `verified` (plus
    `unverified` when `verified_only` / `VALI_GEO_REQUIRE_VERIFIED` is
    off; never `mismatch`). Everything else is simply absent — and absent
    means "in no region" to the gate, which is the fail-closed direction:
    an unprobed or stale fleet refuses a region-constrained launch instead
    of placing it anywhere.
    """
    from apps.miners import geo

    return {
        str(nid).lower(): str(cc).upper()
        for nid, cc in geo.placeable_locations(verified_only=verified_only).values_list(
            "miner__chain_node_id", "country_code"
        )
    }


def region_arguments(region: str) -> dict[str, Any]:
    """The two gate-(f) arguments for one [`decide_placement`] call.

    One helper so every call site that assembles its arguments by hand
    (`/place`, `_replace`, the graceful-exit drain, the price watch) pays
    the same cost: NO query when the VM is unconstrained — which is every
    VM launched before regions existed and every CLI launch — and the
    verified-only map when it is.
    """
    region = (region or "").strip().upper()
    return {
        "region": region,
        "region_by_node": region_by_node() if region else None,
    }


def launch_region_for_vm(vm_id: str) -> str:
    """The region the VM's launch asked for, or `""` when it asked for
    none — read back from the `LaunchJob.spec_json` that PUT the VM where
    it is: the newest SUCCEEDED job, or, while none has succeeded yet,
    the newest job of any state.

    Re-placement after `/fail`, the graceful-exit migration and the price
    watch all choose a NEW host for an existing VM, and none of them sees
    the original intent — so without this a VM sold as "in FR" would be
    moved to wherever ranks best. SUCCEEDED first because the API accepts
    a second launch POST for a VM that is already running (it fails later
    with `placement-conflict`): until it does, its queued row is the
    newest, and "newest by any state" would let a stray POST with no
    region strip a running VM of its constraint. The any-state fallback
    covers the `/fail` that arrives while the FIRST launch is still
    RUNNING. A VM with no job at all (CLI-launched, or pre-dating the
    async path) has no recorded region and stays unconstrained — the only
    honest reading of "nothing was asked".
    """
    from apps.orchestration.models import LaunchJob, LaunchJobState

    jobs = LaunchJob.objects.filter(vm_id=vm_id).order_by("-started_at")
    row = (
        jobs.filter(state=LaunchJobState.SUCCEEDED.value)
        .values_list("spec_json", flat=True)
        .first()
    ) or jobs.values_list("spec_json", flat=True).first()
    if not row:
        return ""
    return str(row.get("region") or "").strip().upper()


def placement_arguments(
    *,
    snapshot: chain.ChainSnapshot,
    tenant_id: str,
    user_id: str,
    flavor: str,
    excluded: frozenset[str] = frozenset(),
    region: str = "",
    platform_id: str = "",
    shadow_log: bool = True,
    budgets: dict[str, HostBudget] | None = None,
    boot_gate: bool = False,
    vm_id: str = "",
) -> dict[str, Any]:
    """Every [`decide_placement`] argument EXCEPT `snapshot`, assembled
    from settings + the DB exactly as a real launch assembles them.

    `boot_gate` adds gate (g), concurrent boots per miner — the launch path
    only. It is transient by construction (the launch WAITS for a boot slot
    rather than failing), so the feasibility check must not answer "not
    now" on it, and a resize destination is a §25 move, not a disk format.

    This exists so the seven admission gates have ONE assembly site. The
    launch path and the feasibility check
    (`apps.scheduler.feasibility`) must ask the scheduler the same
    question or the second one lies: a preflight that answers "yes" from
    a slightly different gate set is worse than no preflight, because a
    caller acts on it. Anything added to `decide_placement` therefore
    reaches both by construction, instead of by someone remembering.

    `snapshot` is passed IN rather than read here: the launch path
    stamps `Placement.chain_epoch` from the same object, and a second
    `read_miner_status()` would both cost a round-trip and let the
    prices ranking disagree with the epoch the placement records.
    """
    return {
        "capacity_by_node": (inputs := decision_inputs(tenant_id))[0],
        "load_by_node": inputs[1],
        "family_load_by_node": inputs[2],
        "max_family_per_node": max_family_per_node(tenant_id),
        "max_epoch_lag": max_epoch_lag(),
        "excluded": excluded,
        "dispatchable": dispatchable_node_ids(),
        "weights": SelectionWeights.from_settings(),
        "max_host_share": max_host_share(),
        # §23 marketplace — cheaper announced prices rank up.
        "price_by_node": price_by_node(snapshot),
        # Circuit-breaker — route around a miner with too many recent
        # launch failures (AUDIT-4).
        "recent_failures_by_node": recent_failures_by_node(),
        "max_recent_failures": max_recent_failures(),
        # Per-owner sub-budget — spread one owner's VMs across the fleet
        # instead of monopolising a miner (audit M-per-tenant-cap).
        "owner_load_by_node": owner_load_by_node(user_id),
        "max_owner_placements_per_miner": max_owner_placements_per_miner(),
        # Gate (e) — the OBSERVED SEV-SNP start-capability ledger.
        "cvm_capability_by_node": cvm_capability_by_node(),
        # Gate (f) — the detected-region constraint; no query when the
        # caller asked for no region.
        **region_arguments(region),
        # Pin — a launch that names a `platform_id` lands on that chip or
        # nowhere.
        **pin_arguments(platform_id),
        # Zombie quarantine — a miner still running a VM whose §24
        # crypto-erase already ran takes no new VMs while that persists.
        "zombie_quarantined": zombie_quarantined_node_ids(),
        # Gate (h) — an operator-cordoned miner takes no new work.
        "cordoned": cordoned_node_ids(),
        # Gate (i) — an edge-region miner without a fresh net-policy ack.
        "net_policy_unready": net_policy_unready_node_ids(),
        # Capacity v2 — does THIS flavor fit, in real units (shadow while
        # `VALI_SCHEDULER_RESOURCE_ADMISSION` is off).
        "resource_fit": resource_fit(flavor, shadow_log=shadow_log, budgets=budgets),
        # Gate (g) — concurrent boots per miner (launch path only).
        **(boot_gate_arguments() if boot_gate else {}),
        # Gate (j) — a CDN node only where its edge is local.
        **cdn_edge_arguments(tenant_id, vm_id),
    }


def boot_gate_arguments() -> dict[str, Any]:
    """Gate (g)'s [`decide_placement`] arguments: the fleet cap, the
    per-miner overrides, and the live boot count — `{}` (no count query)
    when neither a fleet cap nor any override is set."""
    fleet = max_booting_per_miner()
    overrides = max_booting_overrides()
    if fleet <= 0 and not overrides:
        return {}
    return {
        "booting_by_node": booting_by_node(),
        "max_booting_per_node": fleet,
        "max_booting_by_node": overrides,
    }


def max_booting_overrides() -> dict[str, int]:
    """`{node_id: MinerCapacity.max_booting}` for every miner whose
    operator set one (NULL = follows the fleet value)."""
    return dict(
        MinerCapacity.objects.filter(max_booting__isnull=False).values_list(
            "miner_node_id", "max_booting"
        )
    )


def miner_cordon_reason(miner_id: str) -> str | None:
    """The cordon reason of the miner registered as `miner_id` (`""` when
    cordoned without one), or `None` when it is not cordoned. For the paths
    that take an operator-NAMED destination and never consult
    [`decide_placement`]: a cordon refuses new work whoever chose the host."""
    from apps.miners.models import MinerIdentity

    node_id = (
        MinerIdentity.objects.filter(miner_id=miner_id)
        .values_list("chain_node_id", flat=True)
        .first()
    )
    if not node_id:
        return None
    return cordoned_node_ids().get(node_id.lower())


def cordoned_node_ids() -> dict[str, str]:
    """`{lower-case node_id: cordon_reason}` of the operator-cordoned miners
    (`MinerCapacity.cordoned_at` set) — gate (h). Every caller that places
    NEW work passes it; nothing else reads it, which is the whole contract
    of a cordon: the miner's status, telemetry, drains and the VMs already
    on it are untouched."""
    return {
        nid.lower(): reason
        for nid, reason in MinerCapacity.objects.filter(cordoned_at__isnull=False).values_list(
            "miner_node_id", "cordon_reason"
        )
    }


def net_policy_unready_node_ids() -> dict[str, str]:
    """`{lower-case node_id: reason}` of the miners gate (i) skips: in an
    edge-mode egress region without a fresh ack of their edge-mode
    net-policy. One query, `{}`, while every region is local. Lazy import —
    the scheduler must not couple to the network app at module load."""
    from apps.network.net_policy import unready_node_ids

    return unready_node_ids()


def zombie_quarantined_node_ids() -> frozenset[str]:
    """The miners [`decide_placement`] must skip because they are still
    relaying frames from a crypto-erased VM. Derived fresh on every call
    (`apps.lifecycle.zombie`); lazy import — the scheduler must not couple
    to the lifecycle app at module load."""
    from apps.lifecycle.zombie import quarantined_node_ids

    return quarantined_node_ids()


def pin_arguments(platform_id: str) -> dict[str, Any]:
    """The `pinned` [`decide_placement`] argument for a launch that
    names a `platform_id`.

    `None` (no pin, no query) when it names none — the scheduler chooses,
    which is every API launch that leaves it empty. Otherwise the
    `chain_node_id`s of the miners registered with that CHIP_ID
    (case-insensitive; `platform_id` is DB-unique, so at most one). An id
    no miner is registered with yields an EMPTY set, i.e. no placement,
    never "place anywhere": the ticket binds that chip's VCEK and the C2
    recompute uses its CPU family, so a VM placed on any other host could
    only fail later, after vali has minted and registered it.
    """
    pid = (platform_id or "").strip().lower()
    if not pid:
        return {"pinned": None}
    from apps.miners.models import MinerIdentity

    nodes = (
        MinerIdentity.objects.filter(platform_id__iexact=pid)
        .exclude(chain_node_id="")
        .values_list("chain_node_id", flat=True)
    )
    return {"pinned": frozenset(nodes)}


@dataclass(frozen=True)
class CapacityView:
    """What a host can still take, in the units of the ACTIVE admission
    model — the one figure every capacity readout (regions, the scheduler
    capacity view, the operator fleet) publishes, so none of them can
    advertise room admission would refuse.

    - `model`            `"v1"` (slots) or `"v2"` (resource-true), per
                         `VALI_SCHEDULER_RESOURCE_ADMISSION`.
    - `total_units` / `committed_units` / `free_units`
                         v1: effective slots / active placements / the
                         difference. v2: reference-flavor units
                         (`capacity.units`) — a flavor N× the reference
                         costs N. `total = committed + free` in both.
    - `free_vms`         v2 only: VMs still admissible (ceiling, hard cap,
                         ASID). `None` under v1.
    - `free_by_flavor`   how many more of each flavor admission would take
                         here NOW; 0 for a flavor not offered
                         (`VALI_SCHEDULER_MAX_FLAVOR`).
    - `fits_hardware`    per flavor: could this host EVER run one (`None`
                         = vali cannot size the host).
    """

    model: str
    total_units: int
    committed_units: int
    free_units: int
    free_vms: int | None
    free_by_flavor: dict[str, int]
    fits_hardware: dict[str, bool | None]
    #: Active placements on the host (vali's ledger), in both models.
    placements: int = 0


def capacity_views(
    *,
    rows: Iterable[MinerCapacity] | None = None,
    budgets: dict[str, HostBudget] | None = None,
) -> dict[str, CapacityView]:
    """`{node_id: CapacityView}` for every mirror row, under the active model.

    `free_by_flavor` is what would actually RUN: under v1 a placement takes
    one free slot and the miner's own #668 gate then refuses a flavor that
    does not fit its RAM/vCPU, so the v1 figure is bounded by both. `rows`
    / `budgets` let a caller that already loaded them avoid a second
    ledger scan (and a second, possibly different, snapshot)."""
    from apps.orchestration.services import flavors

    rows = list(MinerCapacity.objects.all() if rows is None else rows)
    committed = _committed_by_node()
    empty = _Committed()
    sizes = {name: flavors.resolve_flavor(name) for name in flavors.FLAVOR_NAMES}
    offered = {name: flavors.is_offered(name) for name in flavors.FLAVOR_NAMES}
    out: dict[str, CapacityView] = {}

    disk_of = {name: s.data_disk_size_gb + flavors.ROOTFS_DISK_GB for name, s in sizes.items()}
    if capacity_config.resource_admission_enabled():
        unit_cpus, unit_mem = _slot_ref_cpus(), _slot_ref_memory_mb()
        unit_disk = capacity_config.slot_ref_disk_gb() + flavors.ROOTFS_DISK_GB
        if budgets is None:
            budgets = host_budgets_by_node(rows=rows)
        for nid, b in budgets.items():
            u = units(b, unit_cpus=unit_cpus, unit_memory_mb=unit_mem, unit_disk_gb=unit_disk)
            out[nid] = CapacityView(
                model="v2",
                total_units=u.total,
                committed_units=u.committed,
                free_units=u.free,
                free_vms=b.free_vms if b.known else 0,
                free_by_flavor={
                    name: (
                        headroom(
                            b, cpu_count=s.cpu_count, memory_mb=s.memory_mb, disk_gb=disk_of[name]
                        )
                        if offered[name]
                        else 0
                    )
                    for name, s in sizes.items()
                },
                fits_hardware={
                    name: (
                        big_enough(
                            b, cpu_count=s.cpu_count, memory_mb=s.memory_mb, disk_gb=disk_of[name]
                        )
                        # Unknown disk under `deny` cannot size the host
                        # either: "cannot say", never "too small".
                        if b.known and b.disk_gate != DISK_GATE_DENY
                        else None
                    )
                    for name, s in sizes.items()
                },
                placements=committed.get(nid, empty).vms,
            )
        return out

    results = _capacity_results_by_node(
        {nid: c.vms for nid, c in committed.items()},
        {nid: c.memory_mb for nid, c in committed.items()},
        {nid: c.vcpus for nid, c in committed.items()},
        rows=rows,
    )
    disks = disk_budgets_by_node(rows=rows, committed=committed)
    for nid, r in results.items():
        load = committed.get(nid, empty).vms
        free_slots = max(0, r.slots - load)
        by_flavor: dict[str, int] = {}
        hardware: dict[str, bool | None] = {}
        disk = disks.get(nid, DISK_UNKNOWN)
        disk_state = disk_gate_state_of(disk)
        for name, s in sizes.items():
            if r.free_memory_mb is None or r.free_cpus is None:
                # No anchor: v1 admits any flavor into a free slot (the
                # miner's own gate decides) and cannot size the host.
                fit_now = free_slots
                hardware[name] = None
            else:
                fit_now = min(
                    free_slots, r.free_memory_mb // s.memory_mb, r.free_cpus // s.cpu_count
                )
                hardware[name] = (
                    r.budget_memory_mb is not None
                    and r.budget_cpus is not None
                    and r.budget_memory_mb >= s.memory_mb
                    and r.budget_cpus >= s.cpu_count
                )
            # The disk gate, when enforced, bounds v1 exactly as v2.
            fit_now = min(fit_now, disk_headroom(disk, disk_state, disk_gb=disk_of[name]))
            if hardware[name] is not None and not disk_admits(
                disk, disk_state, disk_gb=disk_of[name], ever=True
            ):
                hardware[name] = False
            by_flavor[name] = max(0, fit_now) if offered[name] else 0
        out[nid] = CapacityView(
            model="v1",
            total_units=r.slots,
            committed_units=min(load, r.slots),
            free_units=free_slots,
            free_vms=None,
            free_by_flavor=by_flavor,
            fits_hardware=hardware,
            placements=load,
        )
    return out


def hard_gated_node_ids(rows: Iterable[MinerCapacity] | None = None) -> frozenset[str]:
    """Mirror rows `decide_placement` would hard-refuse whatever their free
    capacity: not on-chain `active`, epoch-stale, observed CVM-incapable,
    zombie-quarantined, or operator-cordoned. Read from the mirror
    (refreshed on every chain read) so a capacity readout needs no chain
    round-trip of its own; a
    readout zeroes these hosts' FREE figures instead of advertising room
    placement would never use."""
    from .cvm_capability import INCAPABLE

    lag = max_epoch_lag()
    capability = cvm_capability_by_node()
    zombies = {z.lower() for z in zombie_quarantined_node_ids()}
    out: set[str] = set()
    for row in MinerCapacity.objects.all() if rows is None else rows:
        nid = row.miner_node_id
        if (
            row.status != MINER_ACTIVE
            or row.observed_epoch - row.data_epoch > lag
            or capability.get(nid) == INCAPABLE
            or nid.lower() in zombies
            or row.cordoned_at is not None
        ):
            out.add(nid)
    return frozenset(out)


def host_resources_by_node() -> dict[str, HostResources]:
    """`{node_id: (free_memory_mb, free_cpus)}` — the trusted free
    resources in REAL units, from the same pass that computes admission.

    Slots cannot answer "does this flavor fit?": a slot is denominated in
    the reference flavor and one placement costs one slot whatever its
    size, so a `4xlarge` on a host with one free slot looks placeable and
    is not. The miner is the component that actually refuses
    (`check_cpu_mem_budget`, 503 `insufficient-resources` at preflight),
    and by then vali has already chosen it.

    `None` anywhere means vali has no trusted anchor for that host and
    therefore cannot answer — never "it fits".
    """
    load: dict[str, int] = {}
    committed_mb: dict[str, int] = {}
    committed_cpus: dict[str, int] = {}
    for row in Placement.objects.filter(status__in=ACTIVE_PLACEMENT_STATES).values(
        "miner_node_id", "resource_class"
    ):
        node_id = row["miner_node_id"]
        load[node_id] = load.get(node_id, 0) + 1
        mem, cpus = _committed_resources(row["resource_class"])
        committed_mb[node_id] = committed_mb.get(node_id, 0) + mem
        committed_cpus[node_id] = committed_cpus.get(node_id, 0) + cpus

    out: dict[str, HostResources] = {}
    for nid, result in _capacity_results_by_node(load, committed_mb, committed_cpus).items():
        out[nid] = HostResources(
            free_memory_mb=result.free_memory_mb,
            free_cpus=result.free_cpus,
            budget_memory_mb=result.budget_memory_mb,
            budget_cpus=result.budget_cpus,
        )
    return out


def _effective_capacity_by_node(
    load: dict[str, int],
    committed_mb: dict[str, int],
    committed_cpus: dict[str, int],
) -> dict[str, int]:
    """`{node_id: effective admission slots}` — the slot projection of
    [`_capacity_results_by_node`]. See it for the computation."""
    return {
        nid: result.slots
        for nid, result in _capacity_results_by_node(load, committed_mb, committed_cpus).items()
    }


def _capacity_results_by_node(
    load: dict[str, int],
    committed_mb: dict[str, int],
    committed_cpus: dict[str, int],
    *,
    rows: Iterable[MinerCapacity] | None = None,
) -> dict[str, CapacityResult]:
    """`{node_id: CapacityResult}` — the dynamic bound for every mirror
    row, from the TRUSTED anchor + vali's committed load, throttled
    DOWN-only by the miner's fresh self-report.

    See `capacity.effective_capacity` for the invariant proof. This is
    the only place the self-report (`reported_memory_available_mib`)
    enters the admission path, and it can only reduce the result.

    Returns the whole result rather than just `slots` so that a caller
    needing the free RAM/vCPU (the flavor-fit question) reads the
    numbers admission was computed FROM, instead of a second
    reimplementation of the same subtraction.

    `rows` lets a caller that already loaded the mirror (the operator
    fleet readout) reuse it instead of querying it twice.
    """
    now = timezone.now()
    stale_cutoff = now - timedelta(seconds=miner_liveness_timeout_s())
    reserve_mb = _host_reserve_memory_mb()
    reserve_cpus = _host_reserve_cpus()
    ref_mb = _slot_ref_memory_mb()
    ref_cpus = _slot_ref_cpus()

    out: dict[str, CapacityResult] = {}
    for row in MinerCapacity.objects.all() if rows is None else rows:
        nid = row.miner_node_id
        # Only honour a FRESH self-report — a stale one is ignored (the
        # trusted computed value stands). Ignoring it can never RAISE the
        # bound above the trusted value, so this is safe either way.
        reported = None
        if (
            row.reported_memory_available_mib is not None
            and row.reported_at is not None
            and row.reported_at >= stale_cutoff
        ):
            reported = int(row.reported_memory_available_mib)
        result = effective_capacity(
            CapacityInputs(
                operator_max=row.capacity_slots,
                total_memory_mb=row.total_memory_mb,
                total_cpus=row.total_cpus,
                committed_memory_mb=committed_mb.get(nid, 0),
                committed_cpus=committed_cpus.get(nid, 0),
                committed_slots=load.get(nid, 0),
                reported_free_mib=reported,
                reserve_memory_mb=reserve_mb,
                reserve_cpus=reserve_cpus,
                slot_ref_memory_mb=ref_mb,
                slot_ref_cpus=ref_cpus,
            )
        )
        if result.over_claim:
            # A miner claiming MORE free RAM than physically possible given
            # the VMs vali placed on it. Clamped to the trusted value above;
            # log it (over-claiming is inert, but flag it for the operator).
            log.warning(
                "miner over-reported free memory (clamped to trusted): "
                "node=%s reported_mib=%s total_mb=%s committed_mb=%s",
                nid,
                row.reported_memory_available_mib,
                row.total_memory_mb,
                committed_mb.get(nid, 0),
            )
        out[nid] = result
    return out


@dataclass(frozen=True)
class _Committed:
    vcpus: int = 0
    memory_mb: int = 0
    vms: int = 0
    disk_gb: int = 0


def _committed_by_node() -> dict[str, _Committed]:
    """vali's OWN ledger per node: Σ flavor vCPU, Σ flavor RAM, count,
    Σ per-VM disk — over the placements admission counts."""
    acc: dict[str, list[int]] = {}
    for row in Placement.objects.filter(status__in=ACTIVE_PLACEMENT_STATES).values(
        "miner_node_id", "resource_class", "data_disk_gb"
    ):
        mem, cpus = _committed_resources(row["resource_class"])
        entry = acc.setdefault(row["miner_node_id"], [0, 0, 0, 0])
        entry[0] += cpus
        entry[1] += mem
        entry[2] += 1
        entry[3] += placement_disk_gb(row["resource_class"], row["data_disk_gb"])
    return {nid: _Committed(v, m, n, d) for nid, (v, m, n, d) in acc.items()}


def _fresh_gb(value: int | None, fresh: bool) -> int | None:
    """A heartbeat disk figure as a `min` term: `None` when stale, absent
    or 0 (the wire's "unknown") — dropping a term can only leave the
    others in charge, never raise the budget above them."""
    return value if fresh and value else None


def disk_inputs(
    row: MinerCapacity, committed_gb: int, *, now: datetime | None = None
) -> DiskInputs:
    """The [`disk_budget`] inputs for one mirror row. Heartbeat figures
    count only while fresh (the same liveness timeout as the RAM report)."""
    now = now or timezone.now()
    stale_cutoff = now - timedelta(seconds=miner_liveness_timeout_s())
    fresh = row.disk_reported_at is not None and row.disk_reported_at >= stale_cutoff
    reported_total = _fresh_gb(row.reported_data_disk_total_gb, fresh)
    return DiskInputs(
        anchor_total_gb=row.total_disk_gb or None,
        declared_budget_gb=_fresh_gb(row.declared_disk_gb_budget, fresh),
        reported_total_gb=reported_total,
        # A stored 0 next to a known total is a FULL disk (the ingest keeps
        # it only then) — a real, down-only figure, not "unknown".
        reported_available_gb=(
            row.reported_data_disk_available_gb
            if fresh and reported_total is not None
            and row.reported_data_disk_available_gb is not None
            else _fresh_gb(row.reported_data_disk_available_gb, fresh)
        ),
        # Unlike the others, a 0 here is REAL: a ceiling cut to nothing.
        earned_disk_gb=row.earned_disk_gb,
        reserve_gb=capacity_config.disk_reserve_gb(),
        committed_gb=committed_gb,
        overclaim_slack_gb=capacity_config.disk_overclaim_slack_gb(),
    )


def disk_budgets_by_node(
    *,
    rows: Iterable[MinerCapacity] | None = None,
    committed: dict[str, _Committed] | None = None,
) -> dict[str, DiskBudget]:
    """`{node_id: DiskBudget}` for every mirror row — vali's ledger vs the
    down-only `min` of the trusted and untrusted disk terms."""
    committed = _committed_by_node() if committed is None else committed
    now = timezone.now()
    empty = _Committed()
    return {
        row.miner_node_id: disk_budget(
            disk_inputs(row, committed.get(row.miner_node_id, empty).disk_gb, now=now)
        )
        for row in (MinerCapacity.objects.all() if rows is None else rows)
    }


def disk_gate_state_of(d: DiskBudget) -> str:
    """How admission applies `d` under the configured disk gate."""
    return disk_gate_state(
        d,
        mode=capacity_config.disk_gate_mode(),
        unknown=capacity_config.disk_unknown_policy(),
    )


def disk_refusal(d: DiskBudget, disk_gb: int) -> str:
    """Why ENFORCE would refuse a VM needing `disk_gb` here, or `""` when
    it would admit it. Evaluated with enforce semantics whatever the mode,
    so `record` can report exactly what `enforce` would do."""
    state = disk_gate_state(d, mode="enforce", unknown=capacity_config.disk_unknown_policy())
    if disk_admits(d, state, disk_gb=disk_gb):
        return ""
    if state == DISK_GATE_DENY:
        return "disk-unknown"
    return f"disk free {d.free_gb} < {disk_gb} GiB"


def disk_gate_refusal(
    node_id: str, resource_class: str, *, context: str, data_disk_gb: int | None = None
) -> str:
    """The disk gate for a destination vali did NOT choose through
    `decide_placement` (an explicit §25 migration / restore / failover
    target). Returns the refusal reason under `enforce`, `""` otherwise;
    under `record` a would-be refusal is logged and admitted.
    `data_disk_gb`: the VM's real data disk when it is not the flavor's (a
    resized VM — `Placement.data_disk_gb`)."""
    mode = capacity_config.disk_gate_mode()
    if mode == "off":
        return ""
    row = MinerCapacity.objects.filter(miner_node_id=node_id).first()
    need = placement_disk_gb(resource_class, data_disk_gb)
    if row is None:
        d = DISK_UNKNOWN
    else:
        d = disk_budgets_by_node(rows=[row])[node_id]
    reason = disk_refusal(d, need)
    if not reason:
        return ""
    if mode == "record":
        log_disk_would_reject(
            node_id=node_id,
            resource_class=resource_class,
            disk_gb=need,
            reason=reason,
            context=context,
        )
        return ""
    return reason


def warn_disk_over_claims(budgets: dict[str, DiskBudget]) -> list[str]:
    """Log every host whose reported free data disk is below what vali has
    committed there (minus the slack) — the disk twin of the RAM
    over-claim warning. An ALARM: sparse disks and shared fs usage make it
    a reason to look, not a penalty. Returns the flagged node ids."""
    flagged = sorted(nid for nid, d in budgets.items() if d.over_claim)
    for nid in flagged:
        d = budgets[nid]
        log.warning(
            "miner disk over-claim (alarm only): node=%s committed_gb=%s budget_gb=%s "
            "free_gb=%s binding=%s",
            nid,
            d.committed_gb,
            d.budget_gb,
            d.free_gb,
            d.binding or "-",
        )
    return flagged


def budget_inputs(
    row: MinerCapacity, committed: _Committed, *, now: datetime | None = None
) -> BudgetInputs:
    """The [`host_budget`] inputs for one mirror row.

    Untrusted fields are passed ONLY when fresh (same liveness timeout as
    the v1 self-report); a stale claim is dropped, which can only move the
    budget back UP to the trusted value, never above it."""
    from .models import CapacityTrustClass

    now = now or timezone.now()
    stale_cutoff = now - timedelta(seconds=miner_liveness_timeout_s())
    reported_fresh = row.reported_at is not None and row.reported_at >= stale_cutoff
    declared_fresh = row.declared_at is not None and row.declared_at >= stale_cutoff
    earned = row.trust_class == CapacityTrustClass.EARNED
    return BudgetInputs(
        trust_class=row.trust_class,
        total_cpus=row.total_cpus,
        total_memory_mb=row.total_memory_mb,
        cpu_ratio=(
            row.cpu_ratio if row.cpu_ratio is not None else capacity_config.cpu_overcommit_default()
        ),
        reserve_cpus=_host_reserve_cpus(),
        reserve_memory_mb=_host_reserve_memory_mb(),
        per_vm_overhead_mb=capacity_config.per_vm_overhead_mb(),
        vm_ceiling=row.capacity_slots,
        vm_hard_cap=(
            capacity_config.earn_hard_cap_vms()
            if earned
            else capacity_config.operator_vm_hard_cap()
        ),
        asid_reserve=capacity_config.asid_reserve(),
        # NULL is the floor; 0 is a real (penalised-to-nothing) ceiling.
        earned_vms=(
            capacity_config.earn_floor_vms() if row.earned_vms is None else row.earned_vms
        ),
        earned_vcpus=(
            capacity_config.earn_floor_vcpus() if row.earned_vcpus is None else row.earned_vcpus
        ),
        earned_memory_mb=(
            capacity_config.earn_floor_memory_mb()
            if row.earned_memory_mb is None
            else row.earned_memory_mb
        ),
        declared_cpu_budget=row.declared_cpu_budget if declared_fresh else None,
        declared_memory_mb_budget=row.declared_memory_mb_budget if declared_fresh else None,
        declared_asid_capacity=row.declared_asid_capacity if declared_fresh else None,
        reported_free_mib=(
            int(row.reported_memory_available_mib)
            if reported_fresh and row.reported_memory_available_mib is not None
            else None
        ),
        committed_vcpus=committed.vcpus,
        committed_memory_mb=committed.memory_mb,
        committed_vms=committed.vms,
    )


def host_budgets_by_node(
    *, rows: Iterable[MinerCapacity] | None = None
) -> dict[str, HostBudget]:
    """`{node_id: HostBudget}` — capacity v2 for every mirror row, from the
    trusted anchor / earned ceiling + vali's own ledger, clamped DOWN-only
    by the miner's fresh claims. The ONE place v2 budgets are assembled:
    admission, feasibility, units and the operator readouts all read it."""
    rows = list(MinerCapacity.objects.all() if rows is None else rows)
    committed = _committed_by_node()
    disks = disk_budgets_by_node(rows=rows, committed=committed)
    now = timezone.now()
    empty = _Committed()
    out: dict[str, HostBudget] = {}
    for row in rows:
        # `over_claim` is not logged here: v1's `_capacity_results_by_node`
        # already warns on the same report, and this runs several times per
        # decision. The flag stays on the budget for the readouts. Same for
        # the disk over-claim (`warn_disk_over_claims`, once per reeval).
        disk = disks[row.miner_node_id]
        out[row.miner_node_id] = dataclasses.replace(
            host_budget(budget_inputs(row, committed.get(row.miner_node_id, empty), now=now)),
            disk=disk,
            disk_gate=disk_gate_state_of(disk),
        )
    return out


def flavor_size(resource_class: str) -> tuple[int, int]:
    """`(cpu_count, memory_mb)` for a flavor; an unknown / legacy class
    counts as the reference slot, exactly as committed load does."""
    mem, cpus = _committed_resources(resource_class)
    return cpus, mem


def placement_disk_gb(resource_class: str, data_disk_gb: int | None) -> int:
    """The disk one placement commits: its VM's real data disk when the row
    names one (a resized VM keeps its launch disk), else the flavor's — plus
    the rootfs either way (see `_committed_disk_gb`)."""
    from apps.orchestration.services.flavors import ROOTFS_DISK_GB

    if data_disk_gb is not None:
        return int(data_disk_gb) + ROOTFS_DISK_GB
    return _committed_disk_gb(resource_class)


def carried_data_disk_gb(vm: Vm) -> int | None:
    """The real data disk (GiB) a re-placement of `vm` must carry, resolved
    from its launch record — the authority on the disk a resized VM kept
    (`launch_record.data_disk_gb`), whatever flavor the re-placement names
    and whatever a held placement row implies. None when vali has no record
    (the requested flavor's disk then)."""
    from apps.orchestration.services.launch_record import vm_data_disk_gb

    return vm_data_disk_gb(vm.vm_id) or None


def flavor_disk_gb(resource_class: str) -> int:
    """The disk one VM of `resource_class` commits (`_committed_disk_gb`)."""
    return _committed_disk_gb(resource_class)


def inflight_saturated_node_ids() -> frozenset[str]:
    """`earned` miners already holding `VALI_CAPACITY_EARNED_INFLIGHT_MAX`
    PENDING (unbound) placements. v2 admits nothing more there until one
    binds or fails — so a miner lying about what it can run burns at most
    that many tenant launches before a penalty can land on it. `operator`
    miners are never limited.

    Like every v2 input it acts only once `VALI_SCHEDULER_RESOURCE_ADMISSION`
    is on (under v1 an `earned` row is sized by its flat `capacity_slots`),
    and it is a count at decision time, not a lock: two placements decided
    at the same instant could both see room. The launch tick claims one job
    at a time, so in practice the bound holds; it is a blast-radius limit,
    not a safety invariant."""
    from .models import CapacityTrustClass

    limit = capacity_config.earned_inflight_max()
    earned = set(
        MinerCapacity.objects.filter(trust_class=CapacityTrustClass.EARNED).values_list(
            "miner_node_id", flat=True
        )
    )
    if not earned:
        return frozenset()
    pending: dict[str, int] = {}
    for nid in Placement.objects.filter(
        status=PlacementStatus.PENDING.value, miner_node_id__in=earned
    ).values_list("miner_node_id", flat=True):
        pending[nid] = pending.get(nid, 0) + 1
    return frozenset(nid for nid, n in pending.items() if n >= limit)


def resource_fit(
    resource_class: str,
    *,
    shadow_log: bool = True,
    budgets: dict[str, HostBudget] | None = None,
    disk_gb: int | None = None,
) -> ResourceFit | None:
    """The capacity v2 answer for placing ONE VM of `resource_class`:
    which hosts it fits and how empty each is.

    `enforce` follows `VALI_SCHEDULER_RESOURCE_ADMISSION`. Off, the v1 slot
    gate still decides and `decide_placement` logs where v2 would have
    disagreed (the shadow run); on, v2 is the admission gate.

    In SHADOW a failure computing v2 is logged and swallowed (`None` ⇒ v1
    alone): an observer must never be able to stop the v1 placements it
    observes. Enforced, it propagates — v2 IS the gate then, and a gate
    that cannot be computed must refuse, not wave through.

    `budgets` lets a caller that asks for several flavors (the feasibility
    board) compute the fleet's budgets once. `disk_gb` overrides the disk
    the flavor would commit (a resized VM carries its own launch disk)."""
    enforce = capacity_config.resource_admission_enabled()
    disk_mode = capacity_config.disk_gate_mode()
    try:
        cpus, mem = flavor_size(resource_class)
        disk_gb = flavor_disk_gb(resource_class) if disk_gb is None else disk_gb
        budgets = host_budgets_by_node() if budgets is None else budgets
        saturated = inflight_saturated_node_ids()
        return ResourceFit(
            resource_class=resource_class,
            fits_by_node={
                nid: fits(b, cpu_count=cpus, memory_mb=mem, disk_gb=disk_gb)
                and nid not in saturated
                for nid, b in budgets.items()
            },
            free_fraction_by_node={nid: free_fraction(b) for nid, b in budgets.items()},
            enforce=enforce,
            shadow_log=shadow_log,
            # The disk gate runs under BOTH admission models: the verdict
            # `enforce` would reach, per node (`""` = admits).
            disk_mode=disk_mode,
            disk_gb=disk_gb,
            disk_refusal_by_node=(
                {}
                if disk_mode == "off"
                else {nid: disk_refusal(b.disk, disk_gb) for nid, b in budgets.items()}
            ),
        )
    except Exception:
        if enforce or disk_mode == "enforce":
            raise
        log.exception("capacity-v2 shadow failed for %s — v1 decides alone", resource_class)
        return None


def owner_load_by_node(owner: str) -> dict[str, int]:
    """`{node_id: count of `owner`'s active placements on it}` — the input
    to `decide_placement`'s per-owner sub-budget (audit M-per-tenant-cap).

    Empty `owner` ⇒ `{}` (the cap is inert for a legacy / unknown owner).
    """
    if not owner:
        return {}
    load: dict[str, int] = {}
    for row in (
        Placement.objects.filter(status__in=ACTIVE_PLACEMENT_STATES, owner=owner)
        .values("miner_node_id")
        .annotate(n=Count("id"))
    ):
        load[row["miner_node_id"]] = row["n"]
    return load


def release_placements_for_vm(vm: Vm, reason: str) -> int:
    """Release every active (`Pending`|`Bound`) `Placement` for `vm` —
    CAS-transition each to `Failed` so its capacity slot is freed the
    instant the VM reaches a terminal state.

    Called synchronously from the destroy paths (`orchestration._destroy_vm`
    and the manual `→ Destroyed` transition) so a destroyed VM never leaves
    a `Bound` placement pinning the miner's admission bound — the §13
    capacity leak that filled every miner to its slot cap with placements
    pointing at long-dead VMs.

    Idempotent + race-safe: each row is CAS'd on `(id, version, status)`
    exactly like the §13 drain, so a placement already `Failed` (or one
    raced by a concurrent `/fail` or a reeval drain) simply loses the race
    (0 rows). Returns the number of rows actually released.
    """
    now = timezone.now()
    released = 0
    active = Placement.objects.filter(vm=vm, status__in=ACTIVE_PLACEMENT_STATES).only(
        "id", "version"
    )
    for placement in active:
        released += Placement.objects.filter(
            id=placement.id,
            version=placement.version,
            status__in=ACTIVE_PLACEMENT_STATES,
        ).update(
            status=PlacementStatus.FAILED,
            version=placement.version + 1,
            failed_at=now,
            reason=reason,
            # Provenance: the VM ended, not the node. Never a refusal.
            failure_source=PlacementFailureSource.RELEASE,
        )
    return released


class PlacementMoveConflict(Exception):
    """A concurrent writer holds the VM's active `Placement` — the custody
    hand-over could not be completed on this attempt.

    Raised (never swallowed) so the §25 caller aborts its whole activation
    transaction and retries on the next tick: a half-moved custody, where
    `Vm.host` names the destination and the ledger still names the source,
    is exactly the state this whole change exists to make impossible.
    """


def mirror_epoch(node_id: str) -> int:
    """The chain epoch the local `MinerCapacity` mirror was last refreshed
    at for `node_id` — `0` when the miner has no mirror row.

    `Placement.chain_epoch` is an audit field (no gate reads it), so this
    best-effort local number is the honest answer for a placement that was
    not taken against a fresh snapshot of its own — and it avoids adding a
    chain-read failure mode to paths that deliberately have none (the
    operator-forced launch, and the §25 custody hand-over which runs inside
    the activation CAS and must not be able to block it on an RPC blip).
    """
    epoch = (
        MinerCapacity.objects.filter(miner_node_id=node_id)
        .values_list("observed_epoch", flat=True)
        .first()
    )
    return int(epoch or 0)


def move_placement_to_node(
    vm: Vm,
    *,
    node_id: str,
    decided_by: Any,
    reason: str,
    release_ref: str = "",
    resource_class: str = "",
) -> Placement | None:
    """Move a VM's PLACEMENT CUSTODY to `node_id` (a chain `node_id`) —
    close the active row `Migrated` and open a fresh `Bound` one.

    `resource_class` (a resize that migrates, `MigrationJob.resize_to_flavor`)
    opens the destination row at that flavor instead of the closed row's, so
    the room the resize was admitted for is held from the activation on.

    This is the §23 half of "the VM moved": `Placement` was written only by
    the launch path, so after a §25 migration `Vm.host` named the
    destination while the bound placement still named the SOURCE. Four
    consumers read that row and all four were wrong afterwards —
    `scoring._snapshot_weights` (the `snapshot` reward source) paid the
    source; `decision_inputs` counted the VM's slot AND its RAM/CPU against
    the source, so the §13 admission bound and the #668 fit gate both saw
    the destination emptier than it was; and the graceful-exit drain
    (`orchestration.service.enroll_departing_miner_migrations`) enrols by
    BOUND placement, so a miner asking to leave cleanly was never actually
    drained of the VMs it had received.

    APPEND, NOT MUTATE. Re-pointing `miner_node_id` on the existing row
    would be one UPDATE, but that row is an §23/§15 audit record of a
    decision that was TAKEN: `decided_by`, `decided_at`, `chain_epoch` and
    `kbs_release_ref` all describe the LAUNCH decision on the SOURCE, and
    after an in-place rewrite they would describe a destination decision
    that never happened, with a KBS release reference from another miner's
    launch. The model already says so ("re-placement is a fresh `Placement`
    row"), and this keeps the same shape as the billing custody history
    (#938). Note the reason differs from #938's: `VmBillingBinding` is
    immutable because it is a GATE (the guest declares that identity from
    its SNP-measured cmdline, which §25 carries verbatim), whereas
    `Placement` gates nothing — its one authorization use, the vm-progress
    ownership fallback in `apps.telemetry.views`, is consulted ONLY while a
    VM has no host binding at all, a window a migrated VM has long left.

    The new row is `Bound`, not `Pending`: the caller reaches this only
    after the KBS released the KEK to the destination at `new_gen` and the
    destination reported its restore/boot `done`. A `Pending` row would
    leave the two consumers that filter on `Bound` — the snapshot reward
    source and the graceful-exit drain — still broken.

    FAIL-SAFE, in this order:

    - a blank `node_id` (destination with no registered `chain_node_id`)
      moves NOTHING. The alternative — closing the source row and opening
      one on an unnameable miner — would leave the VM with NO active
      placement, i.e. invisible to the #668 fit gate, which is the #939
      hazard by another route: the destination could then be oversubscribed
      by exactly this VM's RAM and CPU. A placement on the wrong miner is
      wrong accounting; NO placement is unbounded accounting.
    - a VM with no `Placement` row at all (a pre-#939 forced launch) is
      left alone and logged: there is no `resource_class` / `vm_family` /
      `owner` to state, and inventing them would put fabricated resource
      figures into the admission maths.
    - an active row already on `node_id` is a NO-OP (returns `None`), so a
      re-driven activation — and a reboot-recovery relaunch on the SAME
      host — never opens a second placement.

    Returns the new `Placement`, or `None` when nothing moved. Raises
    [`PlacementMoveConflict`] if the active row could not be closed.
    """
    if not node_id:
        log.error(
            "placement custody: vm=%s cannot move to an unnameable destination "
            "(no chain node_id) — LEAVING the placement on %s; the miner "
            "accounting for this VM is now wrong, but it is not MISSING",
            vm.vm_id,
            ", ".join(
                Placement.objects.filter(vm=vm, status__in=ACTIVE_PLACEMENT_STATES).values_list(
                    "miner_node_id", flat=True
                )
            )
            or "<none>",
        )
        return None

    active = list(Placement.objects.filter(vm=vm, status__in=ACTIVE_PLACEMENT_STATES))
    # Idempotence: already in custody of `node_id` ⇒ nothing to record.
    # (At most one row can be active — the partial unique index.)
    if any(row.miner_node_id == node_id for row in active):
        return None

    # The template carries the fields that describe the VM, not the
    # decision: its anti-affinity family, its owner and its reserved
    # flavor. They travel WITH the VM, so they are copied from the row
    # being closed — or, if the §13 re-eval already drained it (the
    # graceful-exit case: the source is quarantined, so the drain fires
    # mid-migration), from the most recent row of any status.
    template = (
        active[0] if active else (Placement.objects.filter(vm=vm).order_by("-decided_at").first())
    )
    if template is None:
        log.error(
            "placement custody: vm=%s has NO placement ledger at all — cannot "
            "open one on %s (unknown resource_class/family/owner). This VM is "
            "invisible to the §13 admission bound and the #668 fit gate; it "
            "was before this migration too (P9/#18).",
            vm.vm_id,
            node_id[:12],
        )
        return None

    for row in active:
        closed = Placement.objects.filter(
            id=row.id, version=row.version, status__in=ACTIVE_PLACEMENT_STATES
        ).update(
            status=PlacementStatus.MIGRATED,
            version=row.version + 1,
            reason=reason[:256],
            failure_source=PlacementFailureSource.MIGRATION,
        )
        if not closed:
            # Lost the CAS. Either a concurrent writer already closed the
            # row (fine — re-check below) or it moved it somewhere else.
            log.warning(
                "placement custody: vm=%s lost the CAS closing placement=%s",
                vm.vm_id,
                row.id,
            )
    if Placement.objects.filter(vm=vm, status__in=ACTIVE_PLACEMENT_STATES).exists():
        # An active row survives — inserting now would violate the
        # one-active-placement-per-VM index anyway. Fail the whole
        # activation transaction so `Vm.host` and the ledger move together
        # or not at all.
        raise PlacementMoveConflict(
            f"vm {vm.vm_id!r} still holds an active placement — cannot hand "
            f"custody to {node_id[:12]}"
        )

    placement = Placement.objects.create(
        vm=vm,
        vm_family=template.vm_family,
        owner=template.owner,
        resource_class=resource_class or template.resource_class,
        data_disk_gb=(
            template.data_disk_gb
            if template.data_disk_gb is not None or not resource_class
            else _flavor_data_disk_gb(template.resource_class)
        ),
        miner_node_id=node_id,
        status=PlacementStatus.BOUND,
        chain_epoch=mirror_epoch(node_id),
        bound_at=timezone.now(),
        kbs_release_ref=release_ref[:256],
        decided_by=decided_by,
    )
    log.info(
        "placement custody: vm=%s %s → %s (placement=%s, %s)",
        vm.vm_id,
        template.miner_node_id[:12],
        node_id[:12],
        placement.id,
        reason,
    )
    return placement


# ── Resize — swap a VM's reserved flavor on the host it stays on ──────


def _flavor_data_disk_gb(resource_class: str) -> int | None:
    from apps.orchestration.services.flavors import UnknownFlavor, resolve_flavor

    try:
        return resolve_flavor(resource_class).data_disk_size_gb
    except UnknownFlavor:
        return None


class PlacementSwapConflict(Exception):
    """The VM's active placement is not the single row on the expected host
    a resize swap needs — a concurrent move, drain or release got there
    first. Raised, never swallowed: the resize must not guess."""


class ResizeNoRoom(Exception):
    """The host cannot hold the VM at its new flavor, even once its current
    reservation is released. Carries the shortfall, operator-readable."""

    def __init__(self, shortfall: str) -> None:
        super().__init__(shortfall)
        self.shortfall = shortfall


def resize_budget(
    *, node_id: str, old_class: str, vm_running: bool, stopped_at: datetime | None = None
) -> HostBudget:
    """`node_id`'s capacity v2 budget as it will be once ONE reservation of
    `old_class` — the resized VM's own — is released: vali's ledger minus
    that placement, the same trusted/untrusted terms as admission.

    `vm_running`: the guest is up, so the miner's fresh free-RAM report
    does not include its memory yet; it is credited back, or the down-only
    clamp would count the VM against itself. A stopped guest already
    shows up as free there. `stopped_at` (the guest just stopped): credited
    only in a report taken before that instant — decided on the row read
    here, which the caller may hold locked against a heartbeat replacing
    it."""
    row = MinerCapacity.objects.filter(miner_node_id=node_id).first()
    if row is None:
        return HOST_BUDGET_UNKNOWN
    whole = _committed_by_node().get(node_id, _Committed())
    old_mem, old_cpus = _committed_resources(old_class)
    # The VM's disk stays where it is and keeps its committed GiB: only the
    # difference a new size would add is asked of the disk below
    # (`resize_shortfall`) — none for a same-disk resize, which never needs
    # the free space for a second copy of its own disk.
    without = _Committed(
        vcpus=max(0, whole.vcpus - old_cpus),
        memory_mb=max(0, whole.memory_mb - old_mem),
        vms=max(0, whole.vms - 1),
        disk_gb=whole.disk_gb,
    )
    inputs = budget_inputs(row, without)
    if stopped_at is not None:
        vm_running = row.reported_at is not None and row.reported_at < stopped_at
    if vm_running and inputs.reported_free_mib is not None:
        inputs = dataclasses.replace(
            inputs,
            reported_free_mib=inputs.reported_free_mib + old_mem + inputs.per_vm_overhead_mb,
        )
    disk = disk_budget(disk_inputs(row, without.disk_gb))
    return dataclasses.replace(
        host_budget(inputs), disk=disk, disk_gate=disk_gate_state_of(disk)
    )


def resize_shortfall(
    *,
    node_id: str,
    old_class: str,
    new_class: str,
    vm_running: bool,
    stopped_at: datetime | None = None,
) -> str:
    """Why `node_id` cannot hold the VM at `new_class` once its `old_class`
    reservation is released — `""` when it can. The same `capacity.fits`
    admission applies to a launch, so a resize is never admitted where a
    fresh VM of the new size would not be."""
    b = resize_budget(
        node_id=node_id, old_class=old_class, vm_running=vm_running, stopped_at=stopped_at
    )
    mem, cpus = _committed_resources(new_class)
    # A resize never adds disk: the VM keeps the one it was launched with.
    # Nothing for the disk gate to admit (and an unknown budget under
    # `deny` must not refuse a VM its own disk).
    disk_gb = 0
    b = dataclasses.replace(b, disk_gate=DISK_GATE_OFF)
    if fits(b, cpu_count=cpus, memory_mb=mem, disk_gb=disk_gb):
        return ""
    if not b.known:
        return "host size unknown (no trusted capacity anchor)"
    short: list[str] = []
    if cpus > b.max_vm_vcpus:
        short.append(f"host threads {b.max_vm_vcpus} < {cpus} vCPU")
    if cpus > b.free_vcpus:
        short.append(f"cpu {b.free_vcpus} < {cpus}")
    if mem + b.per_vm_overhead_mb > b.free_memory_mb:
        short.append(f"memory {b.free_memory_mb} < {mem + b.per_vm_overhead_mb} MiB")
    if b.free_vms < 1:
        short.append("VM slots 0")
    if not disk_admits(b.disk, b.disk_gate, disk_gb=disk_gb):
        short.append(f"disk free {b.disk.free_gb} < {disk_gb} GiB")
    return "; ".join(short) or "does not fit"


def swap_placement_class(
    vm: Vm,
    *,
    node_id: str,
    new_class: str,
    reason: str,
    decided_by: Any,
    check_fit: bool,
    vm_running: bool = False,
    stopped_at: datetime | None = None,
) -> Placement:
    """Re-size `vm`'s reservation on `node_id` (a chain `node_id`) to
    `new_class`: close its active row `Resized` and open a fresh `Bound`
    one, in ONE transaction — never a moment with both rows counted (a
    double reservation) or neither (a free slot another launch could take).

    `check_fit` re-runs [`resize_shortfall`] UNDER the host's capacity-row
    lock and raises [`ResizeNoRoom`] instead of swapping: the admission
    and the reservation are one step, so two resizes on one host cannot
    both spend the same free room. (A concurrent LAUNCH decision does not
    take this lock — the same "count at decision time" bound every
    placement has; the miner's preflight gate stays the last word.)

    Idempotent: a row already at `new_class` is returned as is. Raises
    [`PlacementSwapConflict`] when the VM does not hold exactly one active
    placement on `node_id`. Append, not mutate — see
    `move_placement_to_node`."""
    with transaction.atomic():
        MinerCapacity.objects.select_for_update().filter(miner_node_id=node_id).first()
        active = list(
            Placement.objects.select_for_update().filter(
                vm=vm, status__in=ACTIVE_PLACEMENT_STATES
            )
        )
        if len(active) != 1 or active[0].miner_node_id != node_id:
            raise PlacementSwapConflict(
                f"vm {vm.vm_id!r} holds {len(active)} active placement(s), "
                f"not exactly one on {node_id[:12]}"
            )
        row = active[0]
        if row.resource_class == new_class:
            return row
        if check_fit:
            shortfall = resize_shortfall(
                node_id=node_id,
                old_class=row.resource_class,
                new_class=new_class,
                vm_running=vm_running,
                stopped_at=stopped_at,
            )
            if shortfall:
                raise ResizeNoRoom(shortfall)
        closed = Placement.objects.filter(
            id=row.id, version=row.version, status__in=ACTIVE_PLACEMENT_STATES
        ).update(
            status=PlacementStatus.RESIZED,
            version=row.version + 1,
            reason=reason[:256],
            failure_source=PlacementFailureSource.RESIZE,
        )
        if not closed:
            raise PlacementSwapConflict(f"vm {vm.vm_id!r}: lost the CAS on placement {row.id}")
        placement = Placement.objects.create(
            vm=vm,
            vm_family=row.vm_family,
            owner=row.owner,
            resource_class=new_class,
            # The disk does not change with the flavor: pin the one the VM
            # holds (its flavor's, until a first resize recorded it).
            data_disk_gb=(
                row.data_disk_gb
                if row.data_disk_gb is not None
                else _flavor_data_disk_gb(row.resource_class)
            ),
            miner_node_id=node_id,
            status=PlacementStatus.BOUND,
            chain_epoch=mirror_epoch(node_id),
            bound_at=timezone.now(),
            kbs_release_ref=row.kbs_release_ref,
            decided_by=decided_by,
        )
    log.info(
        "placement resize: vm=%s on %s %s → %s (placement=%s, %s)",
        vm.vm_id,
        node_id[:12],
        row.resource_class,
        new_class,
        placement.id,
        reason,
    )
    return placement


#: `Vm` states in which the VM occupies RAM/CPU on its host (`Vm.host`).
#: `migrating` included: until the §25 activation CAS moves `Vm.host` and
#: the placement together, the VM is still on — and counted against — its
#: source. A stopped VM is `active` too (`VmPowerState`), and it keeps its
#: reservation: it can start again at any moment, on the same host.
VM_STATES_ON_HOST: frozenset[str] = frozenset({VmState.ACTIVE.value, VmState.MIGRATING.value})


def placement_hold_grace_s() -> int:
    """How long the §13 drain keeps holding a live VM's placement after its
    host's last heartbeat. Default 1800 s — longer than a host reboot, so
    a reboot neither drains the placement nor feeds the circuit breaker a
    failure — and always at least twice the liveness timeout the sweep
    re-binds at: a strict margin, so the two cannot flap against each
    other on a heartbeat hovering around one threshold."""
    grace = int(getattr(settings, "VALI_PLACEMENT_HOLD_GRACE_S", 1800))
    return max(grace, 2 * miner_liveness_timeout_s())


def hosting_node_ids(
    vms: Iterable[Vm], *, heartbeat_within_s: int | None = None
) -> dict[int, str]:
    """`{vm.pk: chain node_id}` of the miner each LIVE VM runs on, from
    vali's own records only (`Vm.host`, else the latest SUCCEEDED launch —
    `orchestration.effects._bound_miner_id`) — and only while that miner
    is UP: its last heartbeat is within `heartbeat_within_s` (default
    `miner_liveness_timeout_s`; the drain passes the longer
    `placement_hold_grace_s`).

    A VM that is not live, has no known host, whose host has no
    registered chain `node_id`, or whose host has gone dark maps to `""`.

    Why the heartbeat: this is the evidence the VM still occupies the
    host. A dark host's placement is released by the §13 drain as before
    (nothing can be placed on a dark host anyway, and the VM may never come
    back there); when the host heartbeats again, the tick's sweep re-binds
    it. Without this gate a VM on a host that died for good would hold a
    placement there forever — blocking its re-placement.
    """
    from apps.miners.models import MinerIdentity
    from apps.orchestration.effects import _bound_miner_id

    miner_ids = {vm.pk: _bound_miner_id(vm) for vm in vms if vm.state in VM_STATES_ON_HOST}
    if heartbeat_within_s is None:
        heartbeat_within_s = miner_liveness_timeout_s()
    cutoff = timezone.now() - timedelta(seconds=heartbeat_within_s)
    chain_by_miner = dict(
        MinerIdentity.objects.filter(
            miner_id__in={m for m in miner_ids.values() if m}, last_seen_at__gte=cutoff
        )
        .exclude(chain_node_id__isnull=True)
        .values_list("miner_id", "chain_node_id")
    )
    return {pk: chain_by_miner.get(miner_id) or "" for pk, miner_id in miner_ids.items()}


@dataclass(frozen=True)
class PlacementDrift:
    """A live VM whose active placement does not name the host it runs on.

    `active_node_ids` empty ⇒ the VM holds NO active placement at all: it
    is invisible to the §13 admission bound and the #668 fit gate, so its
    host can be over-booked by exactly this VM's flavor. Otherwise it holds
    a BOUND placement on another miner — its host is under-counted the
    same way (and another over-counted).
    """

    vm: Vm
    host_node_id: str
    active_node_ids: tuple[str, ...]


def live_vm_placement_drift() -> list[PlacementDrift]:
    """Every live VM on an UP host (`hosting_node_ids`) whose active
    placement is missing, or is BOUND on another miner. READ-ONLY — the
    orchestration tick repairs the missing case, the synthetic monitor
    reports both.

    A PENDING row on another miner is not drift: it is a re-placement
    decision in flight (`/fail` → `_replace`, then `/bind`), and the VM
    has not moved yet.

    The invariant: a VM running on a host holds exactly one active
    placement, on that host. Admission (`decision_inputs`,
    `host_resources_by_node`, feasibility) counts ONLY active placements,
    so a VM that breaks it consumes real RAM/CPU the scheduler cannot see.
    """
    from apps.lifecycle.models import Vm

    vms = list(Vm.objects.filter(state__in=VM_STATES_ON_HOST))
    hosts = hosting_node_ids(vms)
    active: dict[int, list[tuple[str, str]]] = {}
    for vm_pk, node, status in Placement.objects.filter(
        vm__in=vms, status__in=ACTIVE_PLACEMENT_STATES
    ).values_list("vm_id", "miner_node_id", "status"):
        active.setdefault(vm_pk, []).append((node, status))
    drift: list[PlacementDrift] = []
    for vm in vms:
        host = hosts.get(vm.pk, "")
        if not host:
            continue
        rows = active.get(vm.pk, [])
        wrong_host_bound = any(
            node != host and status == PlacementStatus.BOUND.value for node, status in rows
        )
        if not rows or wrong_host_bound:
            drift.append(
                PlacementDrift(
                    vm=vm,
                    host_node_id=host,
                    active_node_ids=tuple(node for node, _status in rows),
                )
            )
    return drift


def stale_pending_after_s() -> int:
    """Age past which a `Pending` placement is no longer a launch in flight.

    A launch creates its `Pending` row just before it dispatches and binds
    it the moment the miner accepts; the slowest step in between is the
    miner preflight (up to 30 min). Default 2 h — four times that — so a
    young `Pending` row is never touched."""
    return int(getattr(settings, "VALI_PENDING_PLACEMENT_STALE_S", 7200))


#: Verdicts for a stale `Pending` placement (`stale_pending_verdicts`).
PENDING_PROMOTE = "promote"
PENDING_CANCEL = "cancel"


@dataclass(frozen=True)
class StalePending:
    """What to do with one `Pending` placement older than
    `stale_pending_after_s`: `promote` it to `Bound` (the VM runs on that
    very host) or `cancel` it (the VM is not there — `why` says where it
    is instead)."""

    placement: Placement
    verdict: str
    why: str


def stale_pending_verdicts(placements: Iterable[Placement] | None = None) -> list[StalePending]:
    """READ-ONLY verdicts for every `Pending` placement older than
    `stale_pending_after_s` (or for `placements`, re-judged by a caller
    that has just locked them). A launch that crashed between stamping
    `Vm.host` and binding its placement leaves exactly such a row: still
    counted by admission, but invisible to everything that reads `Bound`
    (graceful-exit enrolment, price-watch, the snapshot reward source).

    - the VM is live, its host (`Vm.host`, stamped only on an ACCEPTED
      dispatch — else its SUCCEEDED launch) IS this placement's miner, and
      that miner is up ⇒ `promote`. Safe even while a launch job still
      runs: that job's own bind would reach the same row;
    - the VM is `destroyed` ⇒ `cancel` (`vm-destroyed`);
    - the VM runs on ANOTHER miner, that miner is up, and no launch job
      for it is still open ⇒ `cancel` (`vm-on-other-host`) — the live-VM
      sweep then re-binds it where it runs;
    - everything else waits, because vali cannot tell: no host at all (a
      dispatch may have timed out while the miner still booted it — the
      abandoned-launch sweep owns that VM), a dark or unregistered host,
      a `decommissioning` VM (its guest may still run until the §24 stop;
      the destroy releases the row), or an open launch job.

    `why` on a promote is the empty string.
    """
    from apps.orchestration.models import TERMINAL_LAUNCH_STATES, LaunchJob

    if placements is None:
        cutoff = timezone.now() - timedelta(seconds=stale_pending_after_s())
        placements = Placement.objects.filter(
            status=PlacementStatus.PENDING, decided_at__lt=cutoff
        ).select_related("vm")
    rows = list(placements)
    if not rows:
        return []
    live_hosts = hosting_node_ids([row.vm for row in rows])
    launching = set(
        LaunchJob.objects.filter(vm_id__in={row.vm.vm_id for row in rows})
        .exclude(state__in=TERMINAL_LAUNCH_STATES)
        .values_list("vm_id", flat=True)
    )

    out: list[StalePending] = []
    for row in rows:
        vm = row.vm
        if vm.state == VmState.DESTROYED:
            out.append(StalePending(row, PENDING_CANCEL, "vm-destroyed"))
            continue
        if vm.state not in VM_STATES_ON_HOST:
            continue
        # Every remaining verdict needs the VM's host UP: a dark host
        # cannot vouch for where the VM is, and after a cancel the live-VM
        # sweep could not re-bind the VM on it.
        host_chain = live_hosts.get(vm.pk, "")
        if not host_chain:
            continue
        if host_chain == row.miner_node_id:
            out.append(StalePending(row, PENDING_PROMOTE, ""))
        elif vm.vm_id not in launching:
            out.append(StalePending(row, PENDING_CANCEL, "vm-on-other-host"))
    return out


def open_placement_on_node(
    vm: Vm, *, node_id: str, decided_by: Any, reason: str
) -> Placement | None:
    """Open a `Bound` placement for `vm` on `node_id` — ONLY if it holds no
    active placement. Never closes or moves a row: an active row anywhere
    (a re-placement decided concurrently, say) wins, and this returns
    `None`. The race boundary is the one-active-placement-per-VM index,
    not a prior read, so a row inserted after the caller looked still wins.

    The VM's family, owner and flavor come from its most recent placement
    of any status (a drained one, typically). A VM with no ledger at all
    is left alone: its flavor is unknown, and inventing one would put
    fabricated figures into the admission maths.
    """
    template = Placement.objects.filter(vm=vm).order_by("-decided_at").first()
    if template is None:
        log.error(
            "placement: vm=%s has NO placement ledger — cannot open one on %s "
            "(unknown resource_class/family/owner)",
            vm.vm_id,
            node_id[:12],
        )
        return None
    try:
        with transaction.atomic():
            return Placement.objects.create(
                vm=vm,
                vm_family=template.vm_family,
                owner=template.owner,
                resource_class=template.resource_class,
                data_disk_gb=template.data_disk_gb,
                miner_node_id=node_id,
                status=PlacementStatus.BOUND,
                chain_epoch=mirror_epoch(node_id),
                bound_at=timezone.now(),
                kbs_release_ref=reason[:256],
                decided_by=decided_by,
            )
    except IntegrityError:
        return None


@dataclass(frozen=True)
class ReevalReport:
    """Outcome of one [`reeval_once`] cycle — for logging + tests."""

    current_epoch: int
    miners_seen: int
    bound_checked: int
    drained: int
    # Placements a miner-health cause would have drained but whose VM is
    # still live on that miner — kept `Bound` (see `reeval_once`).
    held: int = 0


def reeval_once() -> ReevalReport:
    """Run one re-evaluation cycle.

    Reads a fresh chain snapshot, refreshes the mirror, then checks
    every `Bound` placement: if its miner is no longer on-chain
    `Active` (quarantined / decommissioned / gone) or its score has
    gone stale, the placement is §13-drained — CAS-transitioned
    `Bound → Failed` with a `drain:<cause>` reason. A drained VM is
    re-placed by a fresh `POST /v1/scheduler/place` (idempotent: a
    Failed placement does not block a new one).

    HOLD, NOT DRAIN, while the VM is still on an UP miner (a heartbeat
    within `placement_hold_grace_s` — `hosting_node_ids`). A placement is a reservation of that
    host's RAM/CPU, and a miner whose chain score went stale, or that was
    quarantined, does not free them: the VM keeps running there until a
    §25 migration moves it — and that move re-points the placement itself
    (`move_placement_to_node`). Draining it anyway left a running VM with
    NO active placement: the host looked emptier than it was to admission
    and the #668 fit gate for the rest of the VM's life (three VMs on
    two miners after a 2026-09-21 reboot), and a quarantined miner's VMs
    dropped out of the graceful-exit enrolment, which selects BOUND
    placements. A sick miner is kept out of NEW placements by the
    dispatchability gate, not by this ledger. A miner dark for longer than
    the grace still drains (the VM may never come back there); the
    orchestration tick re-binds if the host heartbeats again with the VM
    on it. A reboot, shorter than the grace, drains nothing.
    `vm-terminal` is never held: that VM is not live.

    Raises [`chain.ChainReadUnavailable`] if the snapshot read fails
    — the caller (the management command) logs + skips the cycle;
    it never drains on a failed read (that would be a self-inflicted
    mass-quarantine on an RPC blip).
    """
    snapshot = chain.read_miner_status()
    refresh_miner_capacity(snapshot)

    lag = max_epoch_lag()
    by_node = {miner.node_id: miner for miner in snapshot.miners}
    bound = list(Placement.objects.filter(status=PlacementStatus.BOUND).select_related("vm"))

    judged = [
        (placement, cause)
        for placement in bound
        if (cause := _drain_cause(placement, by_node, snapshot.current_epoch, lag)) is not None
    ]
    hosts = hosting_node_ids(
        [placement.vm for placement, _cause in judged],
        heartbeat_within_s=placement_hold_grace_s(),
    )

    drained = 0
    held = 0
    for placement, cause in judged:
        # A terminal VM (`vm-terminal`) maps to no host, so it never holds.
        if hosts.get(placement.vm.pk) == placement.miner_node_id:
            held += 1
            log.info(
                "§13 hold: placement=%s vm=%s miner=%s cause=%s — the VM is "
                "still live on this miner, its reservation stands",
                placement.id,
                placement.vm.vm_id,
                placement.miner_node_id,
                cause,
            )
            continue
        # CAS Bound→Failed: a concurrent /fail or a stale view of
        # `version` simply loses the race (0 rows updated).
        updated = Placement.objects.filter(
            id=placement.id,
            version=placement.version,
            status=PlacementStatus.BOUND,
        ).update(
            status=PlacementStatus.FAILED,
            version=placement.version + 1,
            failed_at=timezone.now(),
            reason=f"drain:{cause}",
            # Provenance: the scheduler's OWN judgement — the operator
            # readout selects refusals on this, not on the `drain:` text.
            failure_source=PlacementFailureSource.SCHEDULER_DRAIN,
        )
        if updated:
            drained += 1
            log.warning(
                "§13 drain: placement=%s vm=%s miner=%s cause=%s",
                placement.id,
                placement.vm.vm_id,
                placement.miner_node_id,
                cause,
            )

    return ReevalReport(
        current_epoch=snapshot.current_epoch,
        miners_seen=len(snapshot.miners),
        bound_checked=len(bound),
        drained=drained,
        held=held,
    )


def _drain_cause(
    placement: Placement,
    by_node: dict[str, chain.MinerView],
    current_epoch: int,
    lag: int,
) -> str | None:
    """Return a `drain:<cause>` reason for a Bound placement, or
    `None` if the miner is still healthy + Active + fresh.
    """
    # VM-terminal net (checked BEFORE miner health): a placement whose VM
    # has reached — or is on its way to — a terminal state must free its
    # capacity slot even when the miner is perfectly healthy. `reeval_once`
    # already `.select_related("vm")`, so `placement.vm.state` costs no
    # extra query. This retroactively drains any placement leaked by a
    # destroy path that skipped `release_placements_for_vm`, and covers the
    # migration / failed-launch paths that destroy a VM out-of-band.
    if placement.vm.state in (VmState.DESTROYED, VmState.DECOMMISSIONING):
        return "vm-terminal"
    miner = by_node.get(placement.miner_node_id)
    if miner is None:
        # The miner dropped off-chain entirely — §13 worst case.
        return "miner-missing"
    if miner.status == "quarantined":
        return "miner-quarantined"
    if miner.status == "decommissioned":
        return "miner-decommissioned"
    if miner.status != MINER_ACTIVE:
        return "miner-inactive"
    if current_epoch - miner.data_epoch > lag:
        return "miner-stale"
    return None
