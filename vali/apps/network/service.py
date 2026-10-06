"""Public-IP allocation, lifecycle and reconciliation.

Everything that decides WHO holds WHICH address lives here; the views
only parse and render. NetBird effects are called through
`apps.orchestration.effects` so the test suite can stub one module.

The loop that keeps the edges honest is [`reconcile`], run by the
orchestration tick: it is what follows a VM through a migration, a
reboot-recovery relaunch or its first enrolment (its NetBird address is
only known once the guest has joined), without a hook in any of those
paths.
"""

from __future__ import annotations

import ipaddress
import logging
from dataclasses import dataclass
from datetime import timedelta
from typing import Any

from django.conf import settings
from django.core.cache import cache
from django.db import IntegrityError, OperationalError, transaction
from django.db.models import Count, F, Q
from django.utils import timezone

from apps.lifecycle.models import Vm, VmState

from . import zones
from .models import EdgeStatus, IngressEdge, PublicIP, PublicIpState

log = logging.getLogger("apps.network")

#: The VM states an address may be attached in. A VM being decommissioned
#: or already destroyed will never carry traffic again.
LIVE_VM_STATES = frozenset({VmState.ACTIVE.value, VmState.MIGRATING.value})

#: Cache key throttling the NetBird half of [`reconcile`]. Deleted by
#: attach/detach so the very next tick applies the change.
_NETBIRD_SYNC_KEY = "network:netbird-sync"

_OVERLAY_NET = ipaddress.ip_network("100.64.0.0/10")
_NOT_PUBLIC = (
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    _OVERLAY_NET,
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("240.0.0.0/4"),
)


#: Edges that may take a new attachment: active AND bound to a NetBird peer.
ATTACHABLE_EDGES = Q(status=EdgeStatus.ACTIVE) & ~Q(netbird_peer_id="")


class NetworkError(Exception):
    """A refusal with a stable wire code (`error`) and a human `detail`."""

    def __init__(self, code: str, detail: str) -> None:
        super().__init__(detail)
        self.code = code
        self.detail = detail


# ── validation ────────────────────────────────────────────────────────


def parse_public_address(raw: Any) -> str:
    """A routable IPv4 address an edge may own, normalised. Refuses the
    private, overlay, loopback, link-local, multicast and reserved ranges:
    an edge DNATs these addresses, so one of ours in that list would
    capture traffic that was never meant for a VM."""
    try:
        addr = ipaddress.IPv4Address(str(raw).strip())
    except ValueError as exc:
        raise NetworkError("bad-address", f"not an IPv4 address: {raw!r}") from exc
    if any(addr in net for net in _NOT_PUBLIC):
        raise NetworkError("bad-address", f"{addr} is not a public address")
    return str(addr)


def parse_overlay_address(raw: Any) -> str:
    """A NetBird overlay address (`100.64.0.0/10`), normalised."""
    try:
        addr = ipaddress.IPv4Address(str(raw).strip())
    except ValueError as exc:
        raise NetworkError("bad-netbird-ip", f"not an IPv4 address: {raw!r}") from exc
    if addr not in _OVERLAY_NET:
        raise NetworkError("bad-netbird-ip", f"{addr} is not a NetBird overlay address")
    return str(addr)


# ── wire views ────────────────────────────────────────────────────────


def _iso(value: Any) -> str | None:
    return value.isoformat() if value else None


def public_ip_view(ip: PublicIP) -> dict[str, Any]:
    """`PublicIpView` — the per-VM answer of `/v1/vm/<id>/public-ip`."""
    return {
        "vm_id": ip.vm.vm_id,
        "address": ip.address,
        "edge": ip.edge.name,
        "region": ip.edge.region,
        "state": ip.state,
        "attached_at": _iso(ip.attached_at),
    }


def public_ip_by_vm(vm_pks: list[Any]) -> dict[Any, dict[str, str]]:
    """`{vm pk: {address, edge, region}}` for the given VMs' attached
    addresses — one query for a whole page of VMs."""
    if not vm_pks:
        return {}
    return {
        vm_pk: {"address": address, "edge": edge, "region": region}
        for vm_pk, address, edge, region in PublicIP.objects.filter(
            vm_id__in=vm_pks, state=PublicIpState.ATTACHED
        ).values_list("vm_id", "address", "edge__name", "edge__region")
    }


def edge_view(edge: IngressEdge) -> dict[str, Any]:
    addresses = list(edge.addresses.select_related("vm").order_by("address"))
    counts = {s.value: 0 for s in PublicIpState}
    for ip in addresses:
        counts[ip.state] += 1
    return {
        "name": edge.name,
        "provider": edge.provider,
        "region": edge.region,
        "status": edge.status,
        "netbird_ip": edge.netbird_ip,
        "netbird_peer_id": edge.netbird_peer_id,
        "bound": edge.bound,
        "per_ip_mbps": edge.per_ip_mbps,
        "desired_revision": edge.desired_revision,
        "applied_revision": edge.applied_revision,
        "last_seen_at": _iso(edge.last_seen_at),
        "last_report": edge.last_report,
        "counts": counts,
        "addresses": [
            {
                "address": ip.address,
                "state": ip.state,
                "vm_id": ip.vm.vm_id if ip.vm else None,
                "attached_at": _iso(ip.attached_at),
                "released_at": _iso(ip.released_at),
                "last_tenant_id": ip.last_tenant_id,
                "target_ip": ip.target_ip,
            }
            for ip in addresses
        ],
    }


# ── revisions ─────────────────────────────────────────────────────────


def bump_revision(edge_id: int) -> None:
    """The edge must re-render. An `F()` update, so concurrent bumps add
    up instead of overwriting each other."""
    IngressEdge.objects.filter(pk=edge_id).update(desired_revision=F("desired_revision") + 1)


def request_netbird_sync() -> None:
    """Make the next tick run the NetBird half of [`reconcile`]."""
    cache.delete(_NETBIRD_SYNC_KEY)


# ── attach / detach ───────────────────────────────────────────────────


def get_attached(vm: Vm) -> PublicIP | None:
    return (
        PublicIP.objects.select_related("edge", "vm")
        .filter(vm=vm, state=PublicIpState.ATTACHED)
        .first()
    )


def _placed_region(vm: Vm) -> str:
    """The country the VM runs in: its host's detected, verified location
    (the same rule as `region` on the VM wire shape)."""
    if not vm.host:
        return ""
    from apps.miners import geo

    country = (
        geo.placeable_locations()
        .filter(miner__miner_id=vm.host)
        .values_list("country_code", flat=True)
        .first()
    )
    return (country or "").upper()


def candidate_regions(vm: Vm, region_hint: str = "") -> list[str]:
    """Regions to try, best first: where the VM RUNS (lowest latency to
    its edge), the caller's hint, then the region its launch asked for —
    each kept only if it lies in the zone of the first one known (see
    [`route_scope`])."""
    return route_scope(vm, region_hint)[0]


def route_scope(vm: Vm, region_hint: str = "") -> tuple[list[str], str]:
    """`(regions, zone)`: the exact regions an attach for `vm` tries, best
    first, and the zone it may fall back to once they are full.

    The zone is that of where the VM runs, else of the region its launch
    asked for — a recorded fact — and only last of the hint, which is the
    caller's word. A candidate in another zone is dropped: a VM in AU is
    not served from FR because a hint said FR. An anchor with no zone (see
    `zones`) leaves that one region and no fallback; no region at all
    leaves nothing. Fails closed: an address is never routed across
    zones."""
    from apps.scheduler.service import launch_region_for_vm

    placed, hint, launched = _placed_region(vm), region_hint.upper(), launch_region_for_vm(vm.vm_id)
    out: list[str] = []
    for region in (placed, hint, launched):
        if region and region not in out:
            out.append(region)
    anchor = placed or launched or hint
    if not anchor:
        return [], ""
    zone = zones.zone_of(anchor)
    if not zone:
        return [anchor], ""
    return [r for r in out if zones.zone_of(r) == zone], zone


def _routable_edge_tiers(vm: Vm, region_hint: str) -> list[Any]:
    """Attachable edges per [`route_scope`], one queryset per tier: each
    exact region, then any edge of the zone."""
    active = IngressEdge.objects.filter(ATTACHABLE_EDGES)
    regions, zone = route_scope(vm, region_hint)
    tiers = [active.filter(region=r) for r in regions]
    if zone:
        tiers.append(active.filter(region__in=zones.countries_in(zone)))
    return tiers


def _lock_attachable_edge(edge_pk: int) -> IngressEdge | None:
    """Lock an edge before any of its addresses — the order `delete_edge`
    and the PATCH view use — and re-check under the lock that it still
    takes attachments: a concurrent drain must not let an attach land on
    it."""
    return IngressEdge.objects.select_for_update().filter(ATTACHABLE_EDGES, pk=edge_pk).first()


def _free_ip_on_best_edge(edges: Any) -> PublicIP | None:
    """Lock and return one free address on the edge with the most free
    addresses among `edges`, or `None`."""
    ranked = (
        edges.annotate(free=Count("addresses", filter=Q(addresses__state=PublicIpState.FREE)))
        .filter(free__gt=0)
        .order_by("-free", "name")
    )
    for candidate in ranked:
        edge = _lock_attachable_edge(candidate.pk)
        if edge is None:
            continue
        ip = (
            PublicIP.objects.select_for_update(skip_locked=True)
            .filter(edge=edge, state=PublicIpState.FREE)
            .order_by(F("released_at").asc(nulls_first=True), "address")
            .first()
        )
        if ip is not None:
            return ip
    return None


def _quarantined_from(tenant_id: str) -> Q:
    """Addresses in quarantine after `tenant_id` released them. Both the
    recorded tenant AND the previous holder's own tenant must match: a row
    touched by a process that predates `last_tenant_id` (a rolling deploy)
    can carry a stale value, never a stale holder."""
    return Q(state=PublicIpState.QUARANTINED, last_tenant_id=tenant_id, vm__tenant_id=tenant_id)


def _own_quarantined_ip(edges: Any, tenant_id: str) -> PublicIP | None:
    """Lock and return the address `tenant_id` released most recently and
    that is still in quarantine on one of `edges`, or `None`.

    The quarantine protects the NEXT tenant from traffic still aimed at
    the previous one; handing an address back to the tenant that released
    it exposes nobody. A blank tenant reuses nothing — two VMs without a
    tenant are not known to belong to the same one."""
    if not tenant_id:
        return None
    candidates = (
        PublicIP.objects.filter(_quarantined_from(tenant_id), edge__in=edges)
        .order_by(F("released_at").desc(nulls_last=True), "address")
        .values_list("pk", "edge_id")
    )
    for ip_pk, edge_pk in candidates:
        edge = _lock_attachable_edge(edge_pk)
        if edge is None:
            continue
        # Re-checked under the lock: an expiry or another attach of the
        # same tenant may have taken it since the candidates were read.
        # Skips, never waits, on a locked address: `detach` locks an address
        # THEN its edge, so waiting here with the edge held could close a
        # cycle (through `remove_addresses`, which locks several). A row
        # skipped because an expiry is freeing it loses only this attach.
        ip = (
            PublicIP.objects.select_for_update(skip_locked=True, of=("self",))
            .filter(_quarantined_from(tenant_id), pk=ip_pk, edge=edge)
            .first()
        )
        if ip is not None:
            return ip
    return None


def _requested_ip(edges: Any, tenant_id: str, address: str) -> PublicIP:
    """Lock and return `address` when this tenant may take it now: free, or
    in quarantine after this tenant released it. Anything else — another
    tenant's quarantined address, an attached one, one on an edge that
    takes no attachment or is not among `edges`, one we do not own — is
    `address-unavailable`."""
    found = (
        PublicIP.objects.filter(edge__in=edges, address=address)
        .values_list("pk", "edge_id")
        .first()
    )
    if found is not None and _lock_attachable_edge(found[1]) is not None:
        reusable = Q(state=PublicIpState.FREE)
        if tenant_id:
            reusable |= _quarantined_from(tenant_id)
        # Skips a locked row, as `_own_quarantined_ip` does and for the same
        # reason; a caller refused while an expiry was in flight may retry.
        ip = (
            PublicIP.objects.select_for_update(skip_locked=True, of=("self",))
            .filter(reusable, pk=found[0])
            .first()
        )
        if ip is not None:
            return ip
    raise NetworkError(
        "address-unavailable",
        f"{address} is neither free nor in quarantine from this tenant",
    )


def _pick_ip(vm: Vm, region_hint: str) -> PublicIP | None:
    """Per [`_routable_edge_tiers`]: in each tier, the tenant's own
    quarantined address first, then a free one. Region beats reuse — a
    free address near the VM wins over an own address far from it. `None`
    when nothing in the VM's zone is free: never an edge in another one."""
    for edges in _routable_edge_tiers(vm, region_hint):
        ip = _own_quarantined_ip(edges, vm.tenant_id) or _free_ip_on_best_edge(edges)
        if ip is not None:
            return ip
    return None


#: Attempts of one attach when the database picks it as a deadlock victim.
_ATTACH_ATTEMPTS = 3


def _is_deadlock(exc: OperationalError) -> bool:
    return getattr(exc.__cause__, "sqlstate", None) == "40P01"


def attach(vm: Vm, region_hint: str = "", address: str = "") -> tuple[PublicIP, bool]:
    """Attach a public address to `vm`; `(ip, created)`.

    Idempotent: a VM that already holds one gets it back with
    `created=False` (whatever `address` asks). The address is `address`
    when given, else per [`_pick_ip`]: an address the VM's tenant released
    and is still quarantined comes back to it before a free one, and a
    quarantined address never goes to another tenant.
    Raises `NetworkError` `vm-not-live` / `no-free-public-ip` /
    `address-unavailable`. An address on an edge outside the VM's zone
    (see [`route_scope`]) is never attached, asked for or not.

    Two attaches walking edges in different orders (their regions differ)
    can each hold an edge the other waits for; the database aborts one,
    and that one runs again from the start.
    """
    for attempt in range(1, _ATTACH_ATTEMPTS + 1):
        try:
            return _attach_once(vm, region_hint, address)
        except OperationalError as exc:
            if not _is_deadlock(exc) or attempt == _ATTACH_ATTEMPTS:
                raise
            log.warning("public-ip: attach for vm=%s deadlocked; retrying", vm.vm_id)
    raise AssertionError("unreachable")


def _attach_once(vm: Vm, region_hint: str, address: str) -> tuple[PublicIP, bool]:
    try:
        with transaction.atomic():
            locked = Vm.objects.select_for_update().get(pk=vm.pk)
            existing = get_attached(locked)
            if existing is not None:
                return existing, False
            if locked.state not in LIVE_VM_STATES:
                raise NetworkError("vm-not-live", f"vm is {locked.state}")
            if address:
                regions, zone = route_scope(locked, region_hint)
                edges = IngressEdge.objects.filter(
                    ATTACHABLE_EDGES, region__in=set(regions) | zones.countries_in(zone)
                )
                ip = _requested_ip(edges, locked.tenant_id, address)
            else:
                ip = _pick_ip(locked, region_hint)
            if ip is None:
                raise NetworkError("no-free-public-ip", "no ingress edge has a free address")
            reused = ip.state == PublicIpState.QUARANTINED
            ip.vm = locked
            ip.state = PublicIpState.ATTACHED
            ip.attached_at = timezone.now()
            ip.released_at = None
            ip.target_ip = None
            ip.last_tenant_id = ""
            ip.save(
                update_fields=[
                    "vm",
                    "state",
                    "attached_at",
                    "released_at",
                    "target_ip",
                    "last_tenant_id",
                ]
            )
            bump_revision(ip.edge_id)
    except IntegrityError:
        # A concurrent attach for the same VM won the one-per-VM constraint.
        existing = get_attached(vm)
        if existing is None:
            raise
        return existing, False
    request_netbird_sync()
    log.info(
        "public-ip: attached %s to vm=%s on edge=%s%s",
        ip.address,
        vm.vm_id,
        ip.edge.name,
        " (reused from quarantine, same tenant)" if reused else "",
    )
    return get_attached(vm) or ip, True


def detach(vm: Vm, *, reason: str = "detached") -> PublicIP | None:
    """Release the VM's address into quarantine; `None` when it held none.
    Idempotent. The edge drops the address on its next render."""
    with transaction.atomic():
        # The VM row first, as `attach` does: attach and detach of one VM
        # are serialised, so an attach can never hand back an address a
        # concurrent detach is about to quarantine.
        locked = Vm.objects.select_for_update().filter(pk=vm.pk).first()
        ip = (
            PublicIP.objects.select_for_update(of=("self",))
            .select_related("edge")
            .filter(vm=vm, state=PublicIpState.ATTACHED)
            .first()
        )
        if ip is None:
            return None
        ip.state = PublicIpState.QUARANTINED
        ip.released_at = timezone.now()
        ip.last_tenant_id = (locked or vm).tenant_id
        ip.save(update_fields=["state", "released_at", "last_tenant_id"])
        bump_revision(ip.edge_id)
    request_netbird_sync()
    log.info(
        "public-ip: released %s from vm=%s on edge=%s (%s)",
        ip.address,
        vm.vm_id,
        ip.edge.name,
        reason,
    )
    return ip


def release_for_destroyed_vm(vm: Vm) -> None:
    """Destroy hook: a destroyed VM never keeps an address. Never raises —
    a failure here must not fail the destroy; [`reconcile`] retries."""
    try:
        detach(vm, reason="vm-destroyed")
    except Exception:  # noqa: BLE001 — the destroy already happened.
        log.exception("public-ip: release on destroy failed for vm=%s", vm.vm_id)


# ── edge feed ─────────────────────────────────────────────────────────


def desired_state(edge: IngressEdge) -> dict[str, Any]:
    """What the edge must render: attached addresses whose NetBird target
    is known. An address without a target is left out on purpose — the
    edge cannot forward it anywhere, and a guess would be someone else's
    VM. An unbound edge is served no address at all: it has no NetBird
    peer, so nothing could reach it over the overlay."""
    edge.refresh_from_db(fields=["desired_revision", "per_ip_mbps", "netbird_peer_id"])
    if not edge.bound:
        return {
            "edge": edge.name,
            "revision": edge.desired_revision,
            "per_ip_mbps": edge.per_ip_mbps,
            "addresses": [],
        }
    rows = (
        PublicIP.objects.filter(edge=edge, state=PublicIpState.ATTACHED, target_ip__isnull=False)
        .order_by("address")
        .values_list("address", "vm__vm_id", "target_ip")
    )
    return {
        "edge": edge.name,
        "revision": edge.desired_revision,
        "per_ip_mbps": edge.per_ip_mbps,
        "addresses": [
            {"address": address, "vm_id": vm_id, "target_ip": target}
            for address, vm_id, target in rows
        ],
    }


def record_applied(edge: IngressEdge, revision: int, report: dict[str, Any]) -> None:
    """The agent applied `revision`. A revision from the future is refused:
    it would hide a real lag behind a number the edge made up. A report
    older than the one already recorded (a delayed retry) is ignored, so
    the applied revision never moves backwards."""
    with transaction.atomic():
        locked = IngressEdge.objects.select_for_update().filter(pk=edge.pk).first()
        if locked is None:
            raise NetworkError("edge-not-found", "edge not found")
        if revision > locked.desired_revision:
            raise NetworkError("revision-ahead", "revision is ahead of the desired revision")
        if revision < locked.applied_revision:
            log.info(
                "public-ip: edge %s reported revision %d after %d — stale, ignored",
                locked.name,
                revision,
                locked.applied_revision,
            )
            return
        locked.applied_revision = revision
        locked.last_seen_at = timezone.now()
        locked.last_report = report
        locked.save(update_fields=["applied_revision", "last_seen_at", "last_report"])


# ── edges and their pool ──────────────────────────────────────────────


def add_addresses(edge: IngressEdge, addresses: list[str]) -> None:
    """Add addresses to an edge's pool. Already there ⇒ no-op; owned by
    another edge ⇒ `address-taken`."""
    with transaction.atomic():
        taken = (
            PublicIP.objects.filter(address__in=addresses)
            .exclude(edge=edge)
            .values_list("address", flat=True)
        )
        if taken:
            raise NetworkError("address-taken", f"owned by another edge: {sorted(taken)}")
        have = set(PublicIP.objects.filter(edge=edge).values_list("address", flat=True))
        PublicIP.objects.bulk_create(
            [PublicIP(edge=edge, address=a) for a in sorted(set(addresses) - have)]
        )


def remove_addresses(edge: IngressEdge, addresses: list[str]) -> None:
    """Remove FREE addresses from an edge. All or nothing."""
    with transaction.atomic():
        rows = list(
            PublicIP.objects.select_for_update().filter(edge=edge, address__in=addresses)
        )
        missing = set(addresses) - {r.address for r in rows}
        if missing:
            raise NetworkError("address-not-found", f"not on this edge: {sorted(missing)}")
        busy = sorted(r.address for r in rows if r.state != PublicIpState.FREE)
        if busy:
            raise NetworkError("address-not-free", f"not free: {busy}")
        PublicIP.objects.filter(pk__in=[r.pk for r in rows]).delete()


def check_edge_deletable(edge: IngressEdge) -> None:
    """An edge goes only once every address is free: an attached one would
    cut a tenant, and deleting a quarantined one would let it be re-added
    elsewhere and handed out before its quarantine ends."""
    if edge.addresses.filter(state=PublicIpState.ATTACHED).exists():
        raise NetworkError("edge-has-attached-ips", "detach every address first")
    if edge.addresses.filter(state=PublicIpState.QUARANTINED).exists():
        raise NetworkError(
            "edge-has-quarantined-ips", "wait for every address to leave quarantine"
        )


def delete_edge(edge: IngressEdge) -> None:
    with transaction.atomic():
        locked = IngressEdge.objects.select_for_update().filter(pk=edge.pk).first()
        if locked is None:
            raise NetworkError("edge-not-found", "edge not found")
        check_edge_deletable(locked)
        locked.delete()
    # The caller removed the routing already; a reconcile pass that
    # snapshotted this edge and re-created it is swept by the next pass.
    request_netbird_sync()


def check_edge_peer(peers: list[dict[str, Any]], peer: Any) -> None:
    """Refuse to make `peer` an exit router: it would receive the egress
    of every VM on the edge. A tenant VM's peer never qualifies, and when
    `VALI_PUBLIC_IP_EDGE_PEER_GROUP` is set the peer must be in it."""
    from apps.orchestration import effects

    name = effects.peer_name_from_listing(peers, peer.id)
    if name.startswith("hippius-tenant-"):
        raise NetworkError("netbird-peer-not-an-edge", f"peer {name!r} is a tenant VM")
    group = str(getattr(settings, "VALI_PUBLIC_IP_EDGE_PEER_GROUP", "") or "")
    if group and group not in peer.groups:
        raise NetworkError(
            "netbird-peer-not-an-edge", f"peer {name!r} is not in NetBird group {group!r}"
        )


def resolve_edge_peer(netbird_ip: str) -> Any:
    """The NetBird peer an operator names by overlay address, checked by
    [`check_edge_peer`]. This is the ONLY place an edge's identity is
    bound; reconcile never re-binds it."""
    from apps.orchestration import effects

    try:
        peers = effects.list_netbird_peers()
    except effects.EffectError as exc:
        raise NetworkError("netbird-unavailable", str(exc)) from exc
    peer = effects.peer_by_ip_from_listing(peers, netbird_ip)
    if peer is None or not peer.id:
        raise NetworkError("netbird-peer-not-found", f"no NetBird peer holds {netbird_ip}")
    check_edge_peer(peers, peer)
    return peer


def availability(region: str = "") -> dict[str, Any]:
    """Free addresses on edges that can take an attachment (active and
    bound), per region. Without `region`, `total_free` counts every
    region. With one, it counts what an attach for a VM in `region` can
    reach — that region and the rest of its zone, or that region alone
    when it has no zone — and `regions` is filtered to `region`."""
    rows = (
        PublicIP.objects.filter(edge__status=EdgeStatus.ACTIVE)
        .exclude(edge__netbird_peer_id="")
        .values("edge__region")
        .annotate(
            free=Count("id", filter=Q(state=PublicIpState.FREE)),
            total=Count("id"),
            edges=Count("edge", distinct=True),
        )
        .order_by("edge__region")
    )
    regions = [
        {"region": r["edge__region"], "free": r["free"], "total": r["total"], "edges": r["edges"]}
        for r in rows
    ]
    if not region:
        return {"total_free": sum(r["free"] for r in regions), "regions": regions}
    region = region.upper()
    reachable = zones.countries_in(zones.zone_of(region)) | {region}
    return {
        "total_free": sum(r["free"] for r in regions if r["region"] in reachable),
        "regions": [r for r in regions if r["region"] == region],
    }


# ── reconcile ─────────────────────────────────────────────────────────


@dataclass(frozen=True)
class ReconcileReport:
    released: int = 0
    unquarantined: int = 0
    retargeted: int = 0
    membership_changes: int = 0


def _quarantine_s() -> float:
    return float(getattr(settings, "VALI_PUBLIC_IP_QUARANTINE_S", 3600))


def _release_destroyed() -> int:
    """Backstop for the destroy hooks: any address still attached to a
    VM that is no longer live."""
    dead = (
        PublicIP.objects.filter(state=PublicIpState.ATTACHED)
        .exclude(vm__state__in=LIVE_VM_STATES)
        .select_related("vm")
    )
    released = 0
    for ip in dead:
        if detach(ip.vm, reason=f"vm-{ip.vm.state}") is not None:
            released += 1
    return released


def _expire_quarantine(now: Any) -> int:
    cutoff = now - timedelta(seconds=_quarantine_s())
    return PublicIP.objects.filter(
        state=PublicIpState.QUARANTINED, released_at__lte=cutoff
    ).update(
        state=PublicIpState.FREE, vm=None, target_ip=None, attached_at=None, last_tenant_id=""
    )


@dataclass(frozen=True)
class _Entitlement:
    """Why a peer belongs in an edge's group: this attachment, with this
    target. Re-checked against the database right before the join."""

    ip_pk: int
    vm_pk: Any
    target: str


#: `{edge pk: {peer id: entitlement}}` — who belongs in each edge's group.
_Members = dict[int, dict[str, _Entitlement]]


def _retarget(peers: list[dict[str, Any]]) -> tuple[int, _Members]:
    """Follow every attached VM's NetBird address; returns the number of
    changes and who belongs in each edge's group."""
    from apps.orchestration import effects, netbird_binding

    changed = 0
    members: _Members = {}
    attached = list(PublicIP.objects.filter(state=PublicIpState.ATTACHED).select_related("vm"))
    vm_ids = [ip.vm.vm_id for ip in attached]
    # A re-enrolled guest's new peer is only found by id once its setup key
    # is bound; bind first (a no-op without an open key) so the address does
    # not wait for the janitor's next pass.
    try:
        netbird_binding.bind_netbird_keys(vm_ids=vm_ids)
    except effects.EffectError as exc:
        log.warning("public-ip: binding NetBird setup keys failed: %s", exc)
    bindings = netbird_binding.bindings_for(vm_ids)
    index = effects.PeerIndex.of(peers)
    for ip in attached:
        binding = bindings[ip.vm.vm_id]
        peer = effects.tenant_peer_from_listing(
            index, ip.vm.vm_id, peer_ids=binding.ranked, bound_owners=binding.owners
        )
        new_target = peer.ip if peer is not None and peer.ip else None
        if new_target is None and ip.target_ip is None:
            log.info("public-ip: %s waits for vm=%s to join NetBird", ip.address, ip.vm.vm_id)
            continue
        if new_target is None:
            # The VM's peer RECORD is gone (a disconnected peer keeps its
            # record; only the ephemeral GC or a revoke removes it). Its old
            # overlay address may be handed to another peer — possibly
            # another tenant's VM — so the edge must stop forwarding to it
            # NOW, not when the VM re-enrols.
            log.warning(
                "public-ip: %s — vm=%s has no NetBird peer any more; dropping target %s",
                ip.address,
                ip.vm.vm_id,
                ip.target_ip,
            )
        if peer is not None and peer.id and new_target:
            members.setdefault(ip.edge_id, {})[peer.id] = _Entitlement(
                ip_pk=ip.pk, vm_pk=ip.vm_id, target=new_target
            )
        if new_target == ip.target_ip:
            continue
        with transaction.atomic():
            # Conditional on the row still being this VM's attachment: a
            # detach that raced this pass must not be re-targeted.
            n = PublicIP.objects.filter(
                pk=ip.pk, state=PublicIpState.ATTACHED, vm_id=ip.vm_id
            ).update(target_ip=new_target)
            if n:
                bump_revision(ip.edge_id)
        if n:
            changed += 1
            log.info(
                "public-ip: %s target %s → %s (vm=%s)",
                ip.address,
                ip.target_ip,
                new_target,
                ip.vm.vm_id,
            )
    return changed, members


def _may_join(edge: IngressEdge, why: _Entitlement) -> bool:
    """Re-read right before each join. The attachment must still be there
    with the same target — a detach or re-target that landed after the pass
    took its snapshot stops the join — and the edge must have applied every
    revision vali asked for: until then it may still DNAT some address to
    an overlay IP NetBird has since handed to this peer (a recycled
    address), and group membership is what lets the edge reach it. Joining
    earlier is pointless anyway: without the edge's SNAT rule the VM's
    egress would be dropped there."""
    edge.refresh_from_db(fields=["desired_revision", "applied_revision"])
    if edge.applied_revision < edge.desired_revision:
        return False
    return PublicIP.objects.filter(
        pk=why.ip_pk,
        edge=edge,
        vm_id=why.vm_pk,
        state=PublicIpState.ATTACHED,
        target_ip=why.target,
    ).exists()


def _prepare_edge_routing(
    edge: IngressEdge, peers: list[dict[str, Any]], want: dict[str, _Entitlement]
) -> tuple[Any, int]:
    """Make one edge's routing objects right and remove every peer that no
    longer belongs in its group. Returns `(routing, removals)`; `routing`
    is `None` when the edge must take no joins this pass.

    The edge is its registered peer ID — re-read here, so a re-bind that
    landed during the pass is honoured — never "whoever holds its overlay
    address now": an address NetBird re-assigned must not turn another
    peer into the exit router for every VM on the edge. A re-enrolled edge
    is re-bound explicitly (PATCH `netbird_ip`). When the edge's peer is
    gone or disqualified its routing is left alone, but departures from
    its group still happen."""
    from apps.orchestration import effects

    edge.refresh_from_db(fields=["netbird_peer_id", "netbird_ip"])
    edge_peer = effects.peer_by_id_from_listing(peers, edge.netbird_peer_id)
    usable = edge_peer is not None
    if edge_peer is None:
        log.error(
            "public-ip: edge %s — its NetBird peer %s is gone; its VMs have no exit "
            "route until it is re-bound (PATCH netbird_ip)",
            edge.name,
            edge.netbird_peer_id,
        )
    else:
        try:
            check_edge_peer(peers, edge_peer)
        except NetworkError as exc:
            log.error("public-ip: edge %s — %s; routing left alone", edge.name, exc.detail)
            usable = False
    if not usable:
        group = effects.edge_pip_group(edge.name)
        removals = 0
        for peer_id in sorted(group.pip_peer_ids - set(want)) if group else []:
            effects.group_remove_peer(group.pip_group_id, peer_id)
            removals += 1
        return None, removals
    if edge_peer.ip != edge.netbird_ip:
        log.warning(
            "public-ip: edge %s — peer %s now holds %s, not %s",
            edge.name,
            edge_peer.id,
            edge_peer.ip,
            edge.netbird_ip,
        )
    routing = effects.ensure_edge_routing(edge.name, edge_peer.id)
    removals = 0
    for peer_id in sorted(routing.pip_peer_ids - set(want)):
        effects.group_remove_peer(routing.pip_group_id, peer_id)
        removals += 1
    return routing, removals


def _join_edge_group(edge: IngressEdge, routing: Any, want: dict[str, _Entitlement]) -> int:
    """Admit the peers that belong in the edge's group and are not in it,
    each re-checked by [`_may_join`]. Returns the number of joins."""
    from apps.orchestration import effects

    joins = 0
    for peer_id in sorted(set(want) - routing.pip_peer_ids):
        if not _may_join(edge, want[peer_id]):
            log.info(
                "public-ip: edge %s (revision %d of %d) — peer %s does not join yet",
                edge.name,
                edge.applied_revision,
                edge.desired_revision,
                peer_id,
            )
            continue
        effects.group_add_peer(routing.pip_group_id, peer_id)
        joins += 1
    return joins


def _sync_routing(edges: list[IngressEdge], peers: list[dict[str, Any]], members: _Members) -> int:
    """Two phases across ALL edges: every departure first, then every join —
    and no join at all unless every departure succeeded. A VM moving from
    one edge to another therefore never sits in both groups, and a failing
    join never keeps a peer that has to go. Returns the number of
    membership changes."""
    from apps.orchestration import effects

    changes = 0
    departed = True
    prepared: list[tuple[IngressEdge, Any]] = []
    for edge in edges:
        try:
            done = _prepare_edge_routing(edge, peers, members.get(edge.pk, {}))
        except IngressEdge.DoesNotExist:
            continue  # deleted during this pass; the GC below sweeps it
        except effects.EffectError:
            log.exception("public-ip: NetBird routing for edge %s failed", edge.name)
            departed = False
            continue
        routing, removals = done
        changes += removals
        if routing is not None:
            prepared.append((edge, routing))
    if not departed:
        log.error("public-ip: a departure may not have happened — no peer joins this pass")
        return changes
    # A join is re-checked right before it happens (`_may_join`), but the
    # check and the NetBird write are not atomic: a detach landing between
    # them leaves the peer in the group until the next tick, which that
    # detach has requested.
    for edge, routing in prepared:
        try:
            changes += _join_edge_group(edge, routing, members.get(edge.pk, {}))
        except effects.EffectError:
            log.exception("public-ip: NetBird group joins for edge %s failed", edge.name)
    return changes


def _netbird_configured() -> bool:
    return bool(str(getattr(settings, "VALI_NETBIRD_API_TOKEN", "") or "").strip())


def _netbird_sync_due() -> bool:
    interval = int(getattr(settings, "VALI_PUBLIC_IP_NETBIRD_SYNC_S", 30))
    return bool(cache.add(_NETBIRD_SYNC_KEY, 1, timeout=interval))


def reconcile(*, now: Any = None) -> ReconcileReport:
    """One idempotent pass, run by the orchestration tick.

    Database half, every tick: release addresses of VMs that are no longer
    live, and return quarantined addresses to the pool once past
    `VALI_PUBLIC_IP_QUARANTINE_S`.

    NetBird half, every `VALI_PUBLIC_IP_NETBIRD_SYNC_S` (or on the next
    tick after an attach/detach): re-read every attached VM's overlay
    address — a migration or relaunch can change it, and a VM whose peer
    record is gone loses its target — bump the edge's revision when it
    did, make each edge's exit routing and group membership match, and
    remove the routing of edges that no longer exist. A NetBird failure is
    logged and retried next pass; it never touches the database half.
    """
    now = now or timezone.now()
    released = _release_destroyed()
    unquarantined = _expire_quarantine(now)
    retargeted = membership = 0
    # With no edge there is nothing to route, but routing a deleted edge
    # left behind (a pass that raced the delete) must still be collected —
    # so the pass runs whenever NetBird is configured. The throttle is
    # claimed BEFORE the edges are read: a `request_netbird_sync()` that
    # lands after the claim is honoured by the next tick, never lost.
    if (_netbird_configured() or IngressEdge.objects.exists()) and _netbird_sync_due():
        from apps.orchestration import effects, netbird_binding

        # Unbound edges have no peer to route through and never had routing.
        edges = list(IngressEdge.objects.exclude(netbird_peer_id=""))
        peers = None
        overlay = netbird_binding.overlay_snapshot()
        try:
            peers = effects.list_netbird_peers()
        except effects.EffectError:
            log.exception("public-ip: NetBird peer listing failed — routing not reconciled")
        if peers is not None:
            if edges:
                retargeted, members = _retarget(peers)
                membership = _sync_routing(edges, peers, members)
            # Same snapshot: every live VM's displayed overlay address
            # follows its peer, public IP or not.
            netbird_binding.refresh_overlay_ips(peers, overlay)
            # Same snapshot, bindings just closed: a relaunch key whose
            # guest is back on its own peer is deleted, not left to expire.
            try:
                netbird_binding.revoke_unneeded_relaunch_keys(peers)
            except Exception:  # noqa: BLE001 — never break the routing pass
                log.exception("netbird: revoking unneeded relaunch keys failed")
        # Re-read the edge set: one deleted during this pass must not be
        # kept alive by the snapshot above.
        try:
            # Bound edges only: an unbound edge must have no routing either.
            keep = frozenset(
                IngressEdge.objects.exclude(netbird_peer_id="").values_list("name", flat=True)
            )
            for gone in effects.gc_edge_routing(keep=keep):
                log.warning("public-ip: removed orphaned NetBird %s", gone)
        except effects.EffectError:
            log.exception("public-ip: NetBird garbage collection failed")
    return ReconcileReport(
        released=released,
        unquarantined=unquarantined,
        retargeted=retargeted,
        membership_changes=membership,
    )
