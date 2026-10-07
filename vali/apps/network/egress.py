"""The egress half of an ingress edge's feed (egress design §5.2, §8.3).

In an `edge`-mode region the guests leave through the region's edge, which
SNATs them to its shared `egress_ip`, counts them per VM and caps them. vali
tells the edge WHICH overlay address is WHICH VM, and under which `epoch`,
so a usage sample can only ever be billed to the binding it was counted
under.

- `VmEgressLease` is a VM's place in that list: its edge, overlay address,
  region, epoch and tc `class_id`. The reconcile pass (`reconcile`) keeps
  the leases right; `feed` renders them.
- `PublicIP.vm_region` / `epoch` do the same for the address table.
- `VALI_FEED_ADDRESS_REGION` adds `vm_region` / `epoch` (and nothing
  else) to the address table of every other bound edge too, so the
  backend can price any address's bandwidth by region.
- `VALI_FEED_BLOCK_SMTP` adds a top-level `block_smtp: true` to every
  bound edge's feed, and `smtp_allowed: true` to the address entries that
  have it (the only exemption the edge then honours).
- Any change to what an edge is served bumps its `desired_revision`
  (`sync_revisions`, a content digest), whatever caused it: a lease, a
  setting, a flag. That is the revision a later join waits on.

Nothing of this is served unless `VALI_EGRESS_FEED_ENABLED` is on, the
edge's region is in `edge` mode and the edge has an `egress_ip`: the feed of
every other edge stays exactly what it was.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import logging
from collections import Counter
from dataclasses import dataclass
from typing import Any

from django.conf import settings
from django.db import IntegrityError, transaction
from django.db.models import F
from django.db.models.functions import Upper

from apps.lifecycle.models import Vm, VmNetbirdStatus, VmState

from .models import (
    EGRESS_CLASS_ID_MAX,
    EGRESS_CLASS_ID_MIN,
    EdgeStatus,
    EgressMode,
    EgressRegion,
    IngressEdge,
    PublicIP,
    PublicIpState,
    VmEgressLease,
)
from .net_policy import MAX_VM_CAP_MBPS, _recorded_flavors, effective_cap_mbps

log = logging.getLogger("apps.network.egress")

#: The backend's bounds on a served `epoch` (a signed 64-bit counter).
MAX_EPOCH = 2**63 - 1


def _feed_epoch(epoch: int) -> int:
    """An epoch the backend accepts, or a loud failure: a `BigIntegerField`
    cannot hold anything else, so this only trips on corrupted data."""
    if not 0 <= epoch <= MAX_EPOCH:
        raise ValueError(f"egress: epoch {epoch} outside 0..2^63-1")
    return epoch


def _feed_cap(cap: int) -> int:
    """A cap the backend accepts (`0..=100000`), clamped like the miner
    clamps its own (`net_policy.MAX_VM_CAP_MBPS`)."""
    return max(0, min(cap, MAX_VM_CAP_MBPS))

_OVERLAY_NET = ipaddress.ip_network("100.64.0.0/10")


def feed_enabled() -> bool:
    return bool(getattr(settings, "VALI_EGRESS_FEED_ENABLED", False))


def address_region_enabled() -> bool:
    """`VALI_FEED_ADDRESS_REGION`: every bound edge's address table carries
    `vm_region` and `epoch`, local-mode edges included."""
    return bool(getattr(settings, "VALI_FEED_ADDRESS_REGION", False))


def block_smtp_enabled() -> bool:
    """`VALI_FEED_BLOCK_SMTP`: every bound edge drops TCP 25 from its
    public-IP VMs, except the addresses served `smtp_allowed: true`."""
    return bool(getattr(settings, "VALI_FEED_BLOCK_SMTP", False))


def _vm_allowed(vm_id: str) -> bool:
    """`VALI_EGRESS_VMS` (`*` = all): the VMs that may be put on the exit
    route, so a canary goes first."""
    allow = [v.strip() for v in getattr(settings, "VALI_EGRESS_VMS", []) if v.strip()]
    return "*" in allow or vm_id in allow


def _region_code(raw: Any) -> str:
    """`raw` upper-cased when it is an ISO 3166-1 alpha-2 code, else `""`."""
    code = str(raw or "").upper()
    return code if len(code) == 2 and code.isascii() and code.isalpha() else ""


def host_regions(hosts: set[str]) -> dict[str, str]:
    """`{miner_id: region}`: each miner's detected country, whatever the
    verdict — the rule `net_policy.miner_region` builds the miner's policy
    on, so a VM is on the exit route exactly when its host runs the
    edge-mode policy."""
    from apps.miners.models import MinerLocation

    if not hosts:
        return {}
    rows = (
        MinerLocation.objects.filter(miner_id__in=hosts)
        .annotate(cc=Upper("country_code"))
        .values_list("miner_id", "cc")
    )
    return {miner_id: region for miner_id, cc in rows if (region := _region_code(cc))}


def _is_overlay(raw: str) -> bool:
    try:
        return ipaddress.IPv4Address(raw) in _OVERLAY_NET
    except ValueError:
        return False


# ── feed ──────────────────────────────────────────────────────────────


def edge_mode_regions() -> dict[str, EgressRegion]:
    return {r.region: r for r in EgressRegion.objects.filter(mode=EgressMode.EDGE)}


def serves_egress(edge: IngressEdge) -> bool:
    """Whether `edge` is served the egress-mode feed: the flag is on, the
    edge is bound and has an `egress_ip`, and its region is in edge mode."""
    return (
        feed_enabled()
        and edge.bound
        and bool(edge.egress_ip)
        and EgressRegion.objects.filter(region=edge.region, mode=EgressMode.EDGE).exists()
    )


@dataclass(frozen=True)
class Feed:
    addresses: list[dict[str, Any]]
    egress: dict[str, Any]


def _address_entries(edge: IngressEdge) -> list[dict[str, Any]]:
    """The attached addresses with a target, minus a target outside the
    overlay or claimed by two addresses (one VM's peer re-enrolled onto an
    address another VM's row still holds, until the retarget catches up):
    the backend refuses a whole feed that breaks the one-to-one rule."""
    rows = list(
        PublicIP.objects.filter(edge=edge, state=PublicIpState.ATTACHED, target_ip__isnull=False)
        .order_by("address")
        .values_list(
            "address",
            "vm__vm_id",
            "target_ip",
            "vm_region",
            "epoch",
            "smtp_allowed",
            "pool",
            "cap_mbps",
        )
    )
    claims = Counter(
        target
        for target in PublicIP.objects.filter(
            state=PublicIpState.ATTACHED, target_ip__isnull=False
        ).values_list("target_ip", flat=True)
    )
    for address, _, target, *_ in rows:
        if claims[target] > 1 or not _is_overlay(target):
            log.warning("egress: edge %s — %s targets %s; not served", edge.name, address, target)
    rows = [row for row in rows if claims[row[2]] == 1 and _is_overlay(row[2])]
    flavors = _recorded_flavors([row[1] for row in rows])
    from .service import cdn_feed_fields

    out: list[dict[str, Any]] = []
    for address, vm_id, target, vm_region, epoch, smtp_allowed, pool, cap in rows:
        entry: dict[str, Any] = {"address": address, "vm_id": vm_id, "target_ip": target}
        if vm_region:
            entry["vm_region"] = vm_region
        entry["epoch"] = _feed_epoch(epoch)
        entry["cap_mbps"] = _feed_cap(
            effective_cap_mbps(flavors.get(vm_id, ""), has_public_ip=True)
        )
        if smtp_allowed:
            entry["smtp_allowed"] = True
        # A CDN address's own cap replaces the flavor's.
        entry.update(cdn_feed_fields(edge, pool, cap))
        out.append(entry)
    return out


def _egress_entries(edge: IngressEdge) -> list[dict[str, Any]]:
    """The edge's active leases, minus anything that would break the
    edge's one-to-one rules: a VM holding a public IP (it is on the
    address table), an overlay address an attached address targets, and an
    overlay address two leases claim (stale NetBird data — neither is
    trusted until it settles)."""
    attached = PublicIP.objects.filter(state=PublicIpState.ATTACHED)
    holders = set(attached.values_list("vm_id", flat=True))
    attached_targets = set(
        attached.filter(target_ip__isnull=False).values_list("target_ip", flat=True)
    )
    # `active` alone, not the VM's live state: what is served changes only
    # with the leases, which the pass that bumps the revision moves. The
    # filters below are the safety net for the moments between two passes.
    leases = [
        lease
        for lease in VmEgressLease.objects.filter(edge=edge, active=True).select_related("vm")
        if lease.vm_id not in holders
        and lease.target_ip not in attached_targets
        and _is_overlay(lease.target_ip)
        and EGRESS_CLASS_ID_MIN <= lease.class_id <= EGRESS_CLASS_ID_MAX
    ]
    claims = Counter(lease.target_ip for lease in leases)
    for target, n in claims.items():
        if n > 1:
            log.warning("egress: edge %s — %d leases claim %s; none served", edge.name, n, target)
    leases = [lease for lease in leases if claims[lease.target_ip] == 1]
    flavors = _recorded_flavors([lease.vm.vm_id for lease in leases])
    return sorted(
        (
            {
                "vm_id": lease.vm.vm_id,
                "target_ip": lease.target_ip,
                "vm_region": lease.region,
                "epoch": _feed_epoch(lease.epoch),
                "class_id": lease.class_id,
                "cap_mbps": _feed_cap(
                    effective_cap_mbps(flavors.get(lease.vm.vm_id, ""), has_public_ip=False)
                ),
            }
            for lease in leases
        ),
        key=lambda e: e["vm_id"],
    )


def feed(edge: IngressEdge) -> Feed | None:
    """The address table with its egress-mode fields and the `egress`
    block, or `None` when the edge is not served egress ([`serves_egress`])."""
    if not serves_egress(edge):
        return None
    return Feed(
        addresses=_address_entries(edge),
        egress={
            "address": edge.egress_ip,
            "block_smtp": True,
            "vms": _egress_entries(edge),
        },
    )


def _digest(edge: IngressEdge) -> str:
    """The digest of the fields this module adds to `edge`'s feed: the
    egress-mode feed, else the plain table while `VALI_FEED_ADDRESS_REGION`
    or `VALI_FEED_BLOCK_SMTP` is on, else `""` (the feed is exactly what it
    was). The top-level `block_smtp` counts too, so its flip is a change."""
    rendered = feed(edge)
    if rendered is not None:
        body: dict[str, Any] = {"addresses": rendered.addresses, "egress": rendered.egress}
    elif (address_region_enabled() or block_smtp_enabled()) and edge.bound:
        from .service import plain_address_entries

        body = {"addresses": plain_address_entries(edge)}
    else:
        return ""
    if block_smtp_enabled():
        body["block_smtp"] = True
    return hashlib.sha256(
        json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def sync_revisions() -> int:
    """Bump the revision of every edge whose egress-mode feed (or, with
    `VALI_FEED_ADDRESS_REGION` or `VALI_FEED_BLOCK_SMTP`, address table)
    changed since the last pass, including one that stopped (or started)
    being served it. Returns the number of edges bumped. One query while
    every flag is off and no edge was ever served either."""
    edges = (
        IngressEdge.objects.all()
        if feed_enabled() or address_region_enabled() or block_smtp_enabled()
        else IngressEdge.objects.exclude(egress_digest="")
    )
    bumped = 0
    for edge in edges:
        digest = _digest(edge)
        if digest == edge.egress_digest:
            continue
        IngressEdge.objects.filter(pk=edge.pk).update(
            egress_digest=digest, desired_revision=F("desired_revision") + 1
        )
        bumped += 1
        log.info("egress: edge %s feed changed — revision bumped", edge.name)
    return bumped


# ── leases ────────────────────────────────────────────────────────────


def _egress_edges(regions: set[str]) -> dict[str, list[IngressEdge]]:
    """`{region: [edge, ...]}`, best first: the bound edges with an
    `egress_ip`, active ones before draining or disabled ones."""
    out: dict[str, list[IngressEdge]] = {}
    edges = (
        IngressEdge.objects.filter(region__in=regions, egress_ip__isnull=False)
        .exclude(netbird_peer_id="")
        .order_by("name")
    )
    for edge in sorted(edges, key=lambda e: (e.status != EdgeStatus.ACTIVE, e.name)):
        out.setdefault(edge.region, []).append(edge)
    return out


@dataclass(frozen=True)
class _Want:
    vm_id: str
    edges: list[IngressEdge]
    region: str
    target: str


def _wanted() -> dict[Any, _Want]:
    """`{vm pk: what its lease must say}` for every VM that belongs in an
    egress feed: active, placed in an edge-mode region with routing on and
    an egress edge, on the overlay, holding no public IP, and allowed by
    `VALI_EGRESS_VMS`."""
    regions = {r for r, row in edge_mode_regions().items() if row.routing_enabled}
    edges = _egress_edges(regions)
    if not edges:
        return {}
    vms = list(
        Vm.objects.filter(state=VmState.ACTIVE)
        .exclude(host="")
        .exclude(netbird_ip="")
        .exclude(netbird_status=VmNetbirdStatus.LOST)
        .exclude(public_ips__state=PublicIpState.ATTACHED)
        .values_list("pk", "vm_id", "host", "netbird_ip")
    )
    placed = host_regions({host for _, _, host, _ in vms})
    out: dict[Any, _Want] = {}
    for pk, vm_id, host, netbird_ip in vms:
        region = placed.get(host, "")
        if region not in edges or not _vm_allowed(vm_id) or not _is_overlay(netbird_ip):
            continue
        out[pk] = _Want(vm_id=vm_id, edges=edges[region], region=region, target=netbird_ip)
    return out


class _ClassIds:
    """The tc class ids in use per edge, every lease counted — an inactive
    one keeps its id for as long as its VM lives."""

    def __init__(self, leases: list[VmEgressLease]) -> None:
        self._used: dict[int, set[int]] = {}
        for lease in leases:
            self._used.setdefault(lease.edge_id, set()).add(lease.class_id)

    def take(self, edge_id: int) -> int:
        used = self._used.setdefault(edge_id, set())
        for class_id in range(EGRESS_CLASS_ID_MIN, EGRESS_CLASS_ID_MAX + 1):
            if class_id not in used:
                used.add(class_id)
                return class_id
        raise IntegrityError(f"egress: edge {edge_id} has no free tc class id")

    def release(self, edge_id: int, class_id: int) -> None:
        self._used.get(edge_id, set()).discard(class_id)


def sync_leases() -> int:
    """Make every lease say what [`_wanted`] says. Returns the number of
    leases created, changed, deactivated or deleted.

    - A VM that is gone loses its lease (its class id is then free).
    - A VM that left the feed keeps its lease, inactive, with its class id.
    - The epoch moves when the overlay address, the region or the edge
      does, and when the lease comes back into the feed; a move to another
      edge also takes a class id there.
    """
    from .service import LIVE_VM_STATES

    deleted, _ = VmEgressLease.objects.exclude(vm__state__in=LIVE_VM_STATES).delete()
    if not feed_enabled():
        return deleted
    want = _wanted()
    changes = deleted
    with transaction.atomic():
        leases = {lease.vm_id: lease for lease in VmEgressLease.objects.select_for_update()}
        class_ids = _ClassIds(list(leases.values()))
        for vm_pk, lease in leases.items():
            if vm_pk not in want and lease.active:
                lease.active = False
                lease.save(update_fields=["active", "updated_at"])
                changes += 1
        # By vm_id: a new lease's class id does not depend on row order.
        for vm_pk, w in sorted(want.items(), key=lambda item: item[1].vm_id):
            lease = leases.get(vm_pk)
            if lease is None:
                edge = w.edges[0]
                VmEgressLease.objects.create(
                    vm_id=vm_pk,
                    edge=edge,
                    region=w.region,
                    target_ip=w.target,
                    epoch=1,
                    class_id=class_ids.take(edge.pk),
                )
                changes += 1
                continue
            fields: list[str] = []
            if lease.edge_id not in {e.pk for e in w.edges}:
                class_ids.release(lease.edge_id, lease.class_id)
                lease.edge = w.edges[0]
                lease.class_id = class_ids.take(lease.edge.pk)
                fields += ["edge", "class_id"]
            if lease.target_ip != w.target:
                lease.target_ip = w.target
                fields.append("target_ip")
            if lease.region != w.region:
                lease.region = w.region
                fields.append("region")
            if not lease.active:
                # Back in the feed: a new epoch, so the edge's counters for
                # it restart under a binding the backend has not seen yet.
                lease.active = True
                fields.append("active")
            if fields:
                lease.epoch += 1
                fields.append("epoch")
            if fields:
                lease.save(update_fields=[*fields, "updated_at"])
                changes += 1
    return changes


def refresh_public_ip_regions() -> int:
    """Follow each attached address's holder to the region it runs in;
    a change bumps the address's epoch. A host whose country is unknown
    for now keeps the last known region: a probe gap is not a move.

    A blank region (an address attached before regions were recorded, or
    while its host's country was unknown) is filled under the SAME epoch:
    no feed ever carried a region for that epoch, so no sample was counted
    under another one, and the backend can still price the samples it
    held for that binding. A new epoch there would restart the edge's
    counters for a VM that never moved. Returns the number of addresses
    changed."""
    rows = list(
        PublicIP.objects.filter(state=PublicIpState.ATTACHED)
        .exclude(vm__host="")
        .values_list("pk", "vm_id", "vm__host", "vm_region")
    )
    placed = host_regions({host for _, _, host, _ in rows})
    changed = 0
    for pk, vm_pk, host, current in rows:
        region = placed.get(host, "")
        if not region or region == current:
            continue
        # Conditional on the holder: a detach and re-attach since the read
        # must not inherit the previous holder's region.
        changed += PublicIP.objects.filter(
            pk=pk, state=PublicIpState.ATTACHED, vm_id=vm_pk, vm_region=current
        ).update(vm_region=region, epoch=F("epoch") + 1 if current else F("epoch"))
    return changed


@dataclass(frozen=True)
class ReconcileReport:
    leases: int = 0
    regions: int = 0
    revisions: int = 0


def reconcile() -> ReconcileReport:
    """One pass, run by the orchestration tick after the public-IP pass
    (which refreshes the overlay addresses it reads). Leases only move
    while the flag is on. The addresses' regions are always kept: nothing
    serves them unless a feed flag is on, and an edge must not wait a pass
    for them once one is. The revision pass always runs, so turning the
    flag off re-serves every edge its plain table under a new revision."""
    leases = 0
    try:
        leases = sync_leases()
    except IntegrityError:
        log.exception("egress: lease sync failed; retried next pass")
    regions = refresh_public_ip_regions()
    return ReconcileReport(leases=leases, regions=regions, revisions=sync_revisions())


def bump_lease_edge(vm: Vm) -> None:
    """The VM's place in an egress feed changed outside the reconcile (a
    public IP attached or released takes it off or back on): its edge must
    re-fetch now, not on the next pass."""
    from .service import bump_revision

    for edge_id in VmEgressLease.objects.filter(vm=vm, active=True).values_list(
        "edge_id", flat=True
    ):
        bump_revision(edge_id)
