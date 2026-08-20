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
  miner has left `Active` state (or gone stale).
- [`move_placement_to_node`] hands a VM's placement custody to a §25
  destination — the one write that makes `Placement` follow the VM
  instead of being stamped once at launch.

Nothing here reaches HTTP — the views translate exceptions to status
codes; the management command drives [`reeval_once`] in a loop.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import timedelta
from typing import TYPE_CHECKING, Any

from django.conf import settings
from django.db import IntegrityError
from django.db.models import Count
from django.utils import timezone

from apps.lifecycle.models import VmState

from . import chain
from .capacity import CapacityInputs, effective_capacity
from .models import (
    ACTIVE_PLACEMENT_STATES,
    MinerCapacity,
    Placement,
    PlacementStatus,
)
from .placement import MINER_ACTIVE

if TYPE_CHECKING:
    from apps.lifecycle.models import Vm

log = logging.getLogger("apps.scheduler.service")


def _default_capacity_slots() -> int:
    return int(getattr(settings, "VALI_SCHEDULER_DEFAULT_CAPACITY_SLOTS", 8))


def _host_reserve_memory_mb() -> int:
    """RAM (MiB) kept for the host OS / hypervisor and never handed to
    tenant VMs when sizing dynamic capacity from the trusted anchor."""
    return int(getattr(settings, "VALI_SCHEDULER_HOST_RESERVE_MEMORY_MB", 4096))


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
    return int(
        getattr(settings, "VALI_SCHEDULER_MAX_OWNER_PLACEMENTS_PER_MINER", 4)
    )


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
        Placement.objects.filter(
            status=PlacementStatus.FAILED.value, failed_at__gte=cutoff
        )
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
# placeholder label ("epyc-9255-miner3", "onchain") is rejected —
# those are not valid hex, and a launch ticket pinned to a label cannot
# bind the miner's SNP/VCEK identity (it would fail attestation). The
# exact length is not load-bearing here: the KBS attestation is the real
# check; this gate only keeps the scheduler off un-attestable miners.
_CHIP_ID_MIN_HEX = 16


def _is_real_chip_id(platform_id: str) -> bool:
    pid = (platform_id or "").strip()
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
    """
    from apps.miners.models import MinerIdentity, MinerStatus

    cutoff = timezone.now() - timedelta(seconds=miner_liveness_timeout_s())
    ok: set[str] = set()
    rows = MinerIdentity.objects.filter(
        status=MinerStatus.ACTIVE,
        chain_node_id__isnull=False,
        netbird_ip__isnull=False,
        last_seen_at__gte=cutoff,
    ).only("chain_node_id", "platform_id")
    for m in rows:
        if m.chain_node_id and _is_real_chip_id(m.platform_id):
            ok.add(m.chain_node_id.lower())

    # ADDITIVE host-attestor requirement (default-off ⇒ no-op). Fail-closed:
    # under an ON gate a node with no attested/live host-attestor is dropped.
    if bool(getattr(settings, "VALI_HOST_ATTESTOR_GATE_ENFORCE", False)):
        from apps.telemetry.release_service import attestor_covered_node_ids

        ok &= attestor_covered_node_ids()
    return frozenset(ok)


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
                MinerCapacity.objects.filter(
                    miner_node_id=miner.node_id
                ).update(**chain_fields)
        else:
            MinerCapacity.objects.filter(pk=existing.pk).update(**chain_fields)


def price_by_node(snapshot: chain.ChainSnapshot) -> dict[str, int]:
    """`{node_id: announced_price}` for the §23 marketplace price term —
    only miners that have actually announced a `MinerPrice` on-chain. A
    miner with no price is omitted (the scheduler treats it as
    price-neutral; the tenant ceiling never trips on it)."""
    return {m.node_id: m.price for m in snapshot.miners if m.price is not None}


def max_family_per_node() -> int | None:
    """Hard ceiling on same-family VMs per host, or `None` for no cap.

    `None` is the deliberate default: the RANKING already spreads (see
    `SelectionWeights.spread`), and a numeric cap here is a capacity
    policy, not a safety property. Set `VALI_MAX_FAMILY_PER_NODE` to a
    positive integer to enforce one.
    """
    from django.conf import settings

    raw = getattr(settings, "VALI_MAX_FAMILY_PER_NODE", None)
    try:
        n = int(raw)
    except (TypeError, ValueError):
        return None
    return n if n > 0 else None


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

    capacity = _effective_capacity_by_node(load, committed_mb, committed_cpus)
    return capacity, load, family_load


def _effective_capacity_by_node(
    load: dict[str, int],
    committed_mb: dict[str, int],
    committed_cpus: dict[str, int],
) -> dict[str, int]:
    """`{node_id: effective admission slots}` — the dynamic bound for
    every mirror row, from the TRUSTED anchor + vali's committed load,
    throttled DOWN-only by the miner's fresh self-report.

    See `capacity.effective_capacity` for the invariant proof. This is
    the only place the self-report (`reported_memory_available_mib`)
    enters the admission path, and it can only reduce the result.
    """
    now = timezone.now()
    stale_cutoff = now - timedelta(seconds=miner_liveness_timeout_s())
    reserve_mb = _host_reserve_memory_mb()
    reserve_cpus = _host_reserve_cpus()
    ref_mb = _slot_ref_memory_mb()
    ref_cpus = _slot_ref_cpus()

    out: dict[str, int] = {}
    for row in MinerCapacity.objects.all():
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
        out[nid] = result.slots
    return out


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
    active = Placement.objects.filter(
        vm=vm, status__in=ACTIVE_PLACEMENT_STATES
    ).only("id", "version")
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
) -> Placement | None:
    """Move a VM's PLACEMENT CUSTODY to `node_id` (a chain `node_id`) —
    close the active row `Migrated` and open a fresh `Bound` one.

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
                Placement.objects.filter(
                    vm=vm, status__in=ACTIVE_PLACEMENT_STATES
                ).values_list("miner_node_id", flat=True)
            )
            or "<none>",
        )
        return None

    active = list(
        Placement.objects.filter(vm=vm, status__in=ACTIVE_PLACEMENT_STATES)
    )
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
    template = active[0] if active else (
        Placement.objects.filter(vm=vm).order_by("-decided_at").first()
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
        resource_class=template.resource_class,
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


@dataclass(frozen=True)
class ReevalReport:
    """Outcome of one [`reeval_once`] cycle — for logging + tests."""

    current_epoch: int
    miners_seen: int
    bound_checked: int
    drained: int


def reeval_once() -> ReevalReport:
    """Run one re-evaluation cycle.

    Reads a fresh chain snapshot, refreshes the mirror, then checks
    every `Bound` placement: if its miner is no longer on-chain
    `Active` (quarantined / decommissioned / gone) or its score has
    gone stale, the placement is §13-drained — CAS-transitioned
    `Bound → Failed` with a `drain:<cause>` reason. A drained VM is
    re-placed by a fresh `POST /v1/scheduler/place` (idempotent: a
    Failed placement does not block a new one).

    Raises [`chain.ChainReadUnavailable`] if the snapshot read fails
    — the caller (the management command) logs + skips the cycle;
    it never drains on a failed read (that would be a self-inflicted
    mass-quarantine on an RPC blip).
    """
    snapshot = chain.read_miner_status()
    refresh_miner_capacity(snapshot)

    lag = max_epoch_lag()
    by_node = {miner.node_id: miner for miner in snapshot.miners}
    bound = list(
        Placement.objects.filter(status=PlacementStatus.BOUND).select_related("vm")
    )

    drained = 0
    for placement in bound:
        cause = _drain_cause(placement, by_node, snapshot.current_epoch, lag)
        if cause is None:
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
