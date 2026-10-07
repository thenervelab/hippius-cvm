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

from apps.common.cdn import cdn_enabled, is_cdn_tenant
from apps.lifecycle.models import Vm, VmState

from . import zones
from .models import (
    EdgeStatus,
    EgressMode,
    EgressRegion,
    IngressEdge,
    PublicIP,
    PublicIpPool,
    PublicIpState,
)

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


def is_cdn_vm(vm: Vm) -> bool:
    """Whether `vm` is a CDN node: it runs as `VALI_CDN_TENANT_ID`."""
    return is_cdn_tenant(vm.tenant_id)


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
    by_pool = {p.value: {s.value: 0 for s in PublicIpState} for p in PublicIpPool}
    for ip in addresses:
        counts[ip.state] += 1
        by_pool[ip.pool][ip.state] += 1
    return {
        "name": edge.name,
        "provider": edge.provider,
        "region": edge.region,
        "status": edge.status,
        "netbird_ip": edge.netbird_ip,
        "netbird_peer_id": edge.netbird_peer_id,
        "bound": edge.bound,
        "per_ip_mbps": edge.per_ip_mbps,
        "egress_ip": edge.egress_ip,
        "desired_revision": edge.desired_revision,
        "applied_revision": edge.applied_revision,
        "last_seen_at": _iso(edge.last_seen_at),
        "last_report": edge.last_report,
        "counts": counts,
        "counts_by_pool": by_pool,
        "addresses": [
            {
                "address": ip.address,
                "state": ip.state,
                "vm_id": ip.vm.vm_id if ip.vm else None,
                "attached_at": _iso(ip.attached_at),
                "released_at": _iso(ip.released_at),
                "last_tenant_id": ip.last_tenant_id,
                "target_ip": ip.target_ip,
                "pool": ip.pool,
                "cap_mbps": ip.cap_mbps,
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


def _free_ip_on_best_edge(edges: Any, pool: str) -> PublicIP | None:
    """Lock and return one free address of `pool` on the edge with the most
    free addresses of `pool` among `edges`, or `None`."""
    ranked = (
        edges.annotate(
            free=Count(
                "addresses",
                filter=Q(addresses__state=PublicIpState.FREE, addresses__pool=pool),
            )
        )
        .filter(free__gt=0)
        .order_by("-free", "name")
    )
    for candidate in ranked:
        edge = _lock_attachable_edge(candidate.pk)
        if edge is None:
            continue
        ip = (
            PublicIP.objects.select_for_update(skip_locked=True)
            .filter(edge=edge, state=PublicIpState.FREE, pool=pool)
            .order_by(F("released_at").asc(nulls_first=True), "address")
            .first()
        )
        if ip is not None:
            return ip
    return None


def _quarantined_from(tenant_id: str) -> Q:
    """General addresses in quarantine after `tenant_id` released them.
    Both the recorded tenant AND the previous holder's own tenant must
    match: a row touched by a process that predates `last_tenant_id` (a
    rolling deploy) can carry a stale value, never a stale holder. A CDN
    address is never reused early: its quarantine always runs in full
    (docs/design/cdn.md §7.6)."""
    return Q(
        state=PublicIpState.QUARANTINED,
        last_tenant_id=tenant_id,
        vm__tenant_id=tenant_id,
        pool=PublicIpPool.GENERAL,
    )


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
    """Lock and return the general `address` when this tenant may take it
    now: free, or in quarantine after this tenant released it. Anything
    else — another tenant's quarantined address, an attached one, a CDN
    one, one on an edge that takes no attachment or is not among `edges`,
    one we do not own — is `address-unavailable`."""
    found = (
        PublicIP.objects.filter(edge__in=edges, address=address, pool=PublicIpPool.GENERAL)
        .values_list("pk", "edge_id")
        .first()
    )
    if found is not None and _lock_attachable_edge(found[1]) is not None:
        reusable = Q(state=PublicIpState.FREE, pool=PublicIpPool.GENERAL)
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


def _pick_ip(vm: Vm, region_hint: str, pool: str) -> PublicIP | None:
    """Per [`_routable_edge_tiers`], an address of `pool`: in each tier, the
    tenant's own quarantined address first (general pool only, see
    [`_quarantined_from`]), then a free one. Region beats reuse — a free
    address near the VM wins over an own address far from it. `None` when
    nothing in the VM's zone is free: never an edge in another one."""
    for edges in _routable_edge_tiers(vm, region_hint):
        own = _own_quarantined_ip(edges, vm.tenant_id) if pool == PublicIpPool.GENERAL else None
        ip = own or _free_ip_on_best_edge(edges, pool)
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
    `address-unavailable` / `cdn-vm-uses-cdn-pool`. An address on an edge
    outside the VM's zone (see [`route_scope`]) is never attached, asked
    for or not. Only general addresses: a CDN address is never handed to a
    tenant, and a CDN node takes its address from [`attach_cdn`].

    Two attaches walking edges in different orders (their regions differ)
    can each hold an edge the other waits for; the database aborts one,
    and that one runs again from the start.
    """
    return _attach(vm, region_hint, address, PublicIpPool.GENERAL)


def attach_cdn(vm: Vm) -> tuple[PublicIP, bool]:
    """Attach a CDN address to the CDN node `vm`; `(ip, created)`. In-process
    only (the CDN fleet), never exposed as is.

    From the CDN pool only, and only on an edge of the very region the node
    runs in — its host's verified country, `cdn_host_region` — with no zone,
    hint or launch-region fallback: no CDN node sits behind a remote edge
    (v1). A quarantined address always serves its full window. Raises
    `NetworkError` `cdn-disabled` while `VALI_CDN_ENABLED` is off,
    `not-a-cdn-vm` for a VM that does not run as `VALI_CDN_TENANT_ID`,
    `cdn-no-local-edge` when the host's country is unknown or no attachable
    edge there has a free CDN address, `cdn-vm-moving` while a migration or
    restore is in flight, and `vm-not-live`."""
    if not cdn_enabled():
        raise NetworkError("cdn-disabled", "VALI_CDN_ENABLED is off")
    return _attach(vm, "", "", PublicIpPool.CDN)


def cdn_host_region(miner_id: str) -> str:
    """The VERIFIED country of `miner_id` (fresh geo verdict `verified`,
    whatever `VALI_GEO_REQUIRE_VERIFIED` says), upper case, or `""`."""
    if not miner_id:
        return ""
    from apps.miners import geo

    country = (
        geo.placeable_locations(verified_only=True)
        .filter(miner__miner_id=miner_id)
        .values_list("country_code", flat=True)
        .first()
    )
    return (country or "").upper()


def cdn_edge_regions(vm_id: str = "") -> frozenset[str]:
    """The regions a CDN node may run in (no CDN node behind a remote edge,
    v1): the region of the edge serving the address `vm_id` holds, when it
    holds one — the address follows the node, so the node stays where its
    edge is — else every region with an attachable edge holding a free CDN
    address."""
    held = (
        PublicIP.objects.filter(state=PublicIpState.ATTACHED, vm__vm_id=vm_id)
        .values_list("edge__region", flat=True)
        .first()
        if vm_id
        else None
    )
    if held is not None:
        return frozenset({held.upper()})
    return frozenset(
        r.upper()
        for r in IngressEdge.objects.filter(
            ATTACHABLE_EDGES,
            addresses__pool=PublicIpPool.CDN,
            addresses__state=PublicIpState.FREE,
        ).values_list("region", flat=True)
    )


def _local_cdn_ip(vm: Vm) -> PublicIP:
    """Lock and return a free CDN address on an edge of `vm`'s host region,
    or refuse `cdn-no-local-edge`. A node being moved (§25 or restore in
    flight) is refused `cdn-vm-moving`: its host is still the source, and
    an address taken there would stay on the source region's edge once the
    node lands elsewhere."""
    from apps.orchestration.effects import _bound_miner_id
    from apps.orchestration.models import TERMINAL_MIGRATION_STATES, MigrationJob

    if (
        vm.state == VmState.MIGRATING
        or MigrationJob.objects.filter(vm=vm).exclude(state__in=TERMINAL_MIGRATION_STATES).exists()
    ):
        raise NetworkError("cdn-vm-moving", "the node is being moved: attach once it has landed")

    region = cdn_host_region(_bound_miner_id(vm))
    if not region:
        raise NetworkError(
            "cdn-no-local-edge", "the node's host has no verified country: no local edge"
        )
    ip = _free_ip_on_best_edge(
        IngressEdge.objects.filter(ATTACHABLE_EDGES, region=region), PublicIpPool.CDN
    )
    if ip is None:
        raise NetworkError(
            "cdn-no-local-edge", f"no attachable edge in {region} has a free CDN address"
        )
    return ip


def _attach(vm: Vm, region_hint: str, address: str, pool: str) -> tuple[PublicIP, bool]:
    for attempt in range(1, _ATTACH_ATTEMPTS + 1):
        try:
            return _attach_once(vm, region_hint, address, pool)
        except OperationalError as exc:
            if not _is_deadlock(exc) or attempt == _ATTACH_ATTEMPTS:
                raise
            log.warning("public-ip: attach for vm=%s deadlocked; retrying", vm.vm_id)
    raise AssertionError("unreachable")


def _check_pool_holder(vm: Vm, pool: str) -> None:
    """A CDN node holds a CDN address, everything else a general one."""
    if pool == PublicIpPool.CDN and not is_cdn_vm(vm):
        raise NetworkError("not-a-cdn-vm", "only a CDN node takes a CDN address")
    if pool == PublicIpPool.GENERAL and is_cdn_vm(vm):
        raise NetworkError("cdn-vm-uses-cdn-pool", "a CDN node takes a CDN address")


def _attach_once(
    vm: Vm, region_hint: str, address: str, pool: str
) -> tuple[PublicIP, bool]:
    from . import egress

    try:
        with transaction.atomic():
            locked = Vm.objects.select_for_update().get(pk=vm.pk)
            _check_pool_holder(locked, pool)
            existing = get_attached(locked)
            if existing is not None:
                if existing.pool != pool:
                    raise NetworkError(
                        "address-unavailable", f"the vm holds a {existing.pool} address"
                    )
                return existing, False
            if locked.state not in LIVE_VM_STATES:
                raise NetworkError("vm-not-live", f"vm is {locked.state}")
            if pool == PublicIpPool.CDN:
                ip = _local_cdn_ip(locked)
            elif address:
                regions, zone = route_scope(locked, region_hint)
                edges = IngressEdge.objects.filter(
                    ATTACHABLE_EDGES, region__in=set(regions) | zones.countries_in(zone)
                )
                ip = _requested_ip(edges, locked.tenant_id, address)
            else:
                ip = _pick_ip(locked, region_hint, pool)
            if ip is None:
                raise NetworkError("no-free-public-ip", "no ingress edge has a free address")
            reused = ip.state == PublicIpState.QUARANTINED
            ip.vm = locked
            ip.state = PublicIpState.ATTACHED
            ip.attached_at = timezone.now()
            ip.released_at = None
            ip.target_ip = None
            ip.last_tenant_id = ""
            # A new binding: a new epoch, the holder's region, and port 25
            # closed until it is unblocked for this holder.
            ip.epoch += 1
            ip.vm_region = egress.host_regions({locked.host}).get(locked.host, "")
            ip.smtp_allowed = False
            ip.save(
                update_fields=[
                    "vm",
                    "state",
                    "attached_at",
                    "released_at",
                    "target_ip",
                    "last_tenant_id",
                    "epoch",
                    "vm_region",
                    "smtp_allowed",
                ]
            )
            bump_revision(ip.edge_id)
            egress.bump_lease_edge(locked)
    except IntegrityError:
        # A concurrent attach for the same VM won the one-per-VM constraint.
        existing = get_attached(vm)
        if existing is None or existing.pool != pool:
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
    from . import egress

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
        egress.bump_lease_edge(locked or vm)
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


def cdn_feed_fields(edge: IngressEdge, pool: str, cap_mbps: int | None) -> dict[str, Any]:
    """What a CDN address adds to its feed entry (`pool`, and its own
    `cap_mbps` in place of the edge's `per_ip_mbps`) once the reconcile
    applied `VALI_CDN_ENABLED` to `edge` (`IngressEdge.cdn_feed`); nothing
    for a general address, or while off — so the feed stays byte-identical
    to what it was."""
    if pool != PublicIpPool.CDN or not edge.cdn_feed:
        return {}
    return {"pool": PublicIpPool.CDN.value, "cap_mbps": cap_mbps}


def desired_state(edge: IngressEdge) -> dict[str, Any]:
    """What the edge must render: attached addresses whose NetBird target
    is known. An address without a target is left out on purpose — the
    edge cannot forward it anywhere, and a guess would be someone else's
    VM. An unbound edge is served no address at all: it has no NetBird
    peer, so nothing could reach it over the overlay.

    An edge serving its region's egress (`egress.serves_egress`) also gets
    each address's `vm_region`, `epoch`, `cap_mbps` and `smtp_allowed`, and
    the `egress` block; every other edge gets [`plain_address_entries`].
    With `VALI_FEED_BLOCK_SMTP` on, every bound edge also gets a top-level
    `block_smtp: true`."""
    from . import egress

    edge.refresh_from_db(
        fields=[
            "desired_revision",
            "per_ip_mbps",
            "netbird_peer_id",
            "egress_ip",
            "region",
            "cdn_feed",
        ]
    )
    if not edge.bound:
        return {
            "edge": edge.name,
            "revision": edge.desired_revision,
            "per_ip_mbps": edge.per_ip_mbps,
            "addresses": [],
        }
    fed = egress.feed(edge)
    if fed is not None:
        state: dict[str, Any] = {
            "edge": edge.name,
            "revision": edge.desired_revision,
            "per_ip_mbps": edge.per_ip_mbps,
            "addresses": fed.addresses,
            "egress": fed.egress,
        }
    else:
        state = {
            "edge": edge.name,
            "revision": edge.desired_revision,
            "per_ip_mbps": edge.per_ip_mbps,
            "addresses": plain_address_entries(edge),
        }
    if egress.block_smtp_enabled():
        state["block_smtp"] = True
    return state


def plain_address_entries(edge: IngressEdge) -> list[dict[str, Any]]:
    """The address table of a bound edge not served egress. With
    `VALI_FEED_ADDRESS_REGION` on, each entry also carries the address's
    `vm_region` (when known) and `epoch` — never `cap_mbps`, which would
    override the edge's `per_ip_mbps`. With `VALI_FEED_BLOCK_SMTP` on, an
    address whose port 25 is unblocked carries `smtp_allowed: true` (absent
    when false), else the edge's `block_smtp` would close it too. A CDN
    address also carries [`cdn_feed_fields`]."""
    from . import egress

    with_region = egress.address_region_enabled()
    with_smtp = egress.block_smtp_enabled()
    rows = (
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
    out: list[dict[str, Any]] = []
    for address, vm_id, target, vm_region, epoch, smtp_allowed, pool, cap in rows:
        entry: dict[str, Any] = {"address": address, "vm_id": vm_id, "target_ip": target}
        if with_region:
            if vm_region:
                entry["vm_region"] = vm_region
            entry["epoch"] = egress._feed_epoch(epoch)
        if with_smtp and smtp_allowed:
            entry["smtp_allowed"] = True
        entry.update(cdn_feed_fields(edge, pool, cap))
        out.append(entry)
    return out


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


def add_addresses(
    edge: IngressEdge,
    addresses: list[str],
    pool: str = PublicIpPool.GENERAL,
    cap_mbps: int | None = None,
) -> None:
    """Add addresses of `pool` to an edge. A CDN address needs its own
    `cap_mbps`, a general one takes none (the edge's `per_ip_mbps`).
    Already there in the same pool ⇒ no-op, except that a CDN address takes
    the new `cap_mbps` (the edge re-renders when one is attached); there in
    the other pool ⇒ `address-pool-mismatch` (an address never changes pool
    in place); owned by another edge ⇒ `address-taken`."""
    if pool not in PublicIpPool.values:
        raise NetworkError("bad-request", f"pool must be one of {sorted(PublicIpPool.values)}")
    if pool == PublicIpPool.CDN and cap_mbps is None:
        raise NetworkError("bad-request", "a cdn address needs cap_mbps")
    if pool == PublicIpPool.GENERAL and cap_mbps is not None:
        raise NetworkError(
            "bad-request", "a general address takes the edge's per_ip_mbps, not cap_mbps"
        )
    with transaction.atomic():
        taken = (
            PublicIP.objects.filter(address__in=addresses)
            .exclude(edge=edge)
            .values_list("address", flat=True)
        )
        if taken:
            raise NetworkError("address-taken", f"owned by another edge: {sorted(taken)}")
        egress_ips = IngressEdge.objects.filter(egress_ip__in=addresses).values_list(
            "egress_ip", flat=True
        )
        if egress_ips:
            raise NetworkError("address-taken", f"an edge's egress address: {sorted(egress_ips)}")
        have = dict(
            PublicIP.objects.select_for_update()
            .filter(edge=edge, address__in=addresses)
            .values_list("address", "pool")
        )
        other = sorted(a for a, p in have.items() if p != pool)
        if other:
            raise NetworkError("address-pool-mismatch", f"in another pool: {other}")
        PublicIP.objects.bulk_create(
            [
                PublicIP(edge=edge, address=a, pool=pool, cap_mbps=cap_mbps)
                for a in sorted(set(addresses) - set(have))
            ]
        )
        if pool == PublicIpPool.CDN and have:
            stale = PublicIP.objects.filter(edge=edge, address__in=list(have)).exclude(
                cap_mbps=cap_mbps
            )
            served = stale.filter(state=PublicIpState.ATTACHED).exists()
            stale.update(cap_mbps=cap_mbps)
            if served:
                bump_revision(edge.pk)


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
    """Free general addresses on edges that can take an attachment (active
    and bound), per region — the CDN pool is never counted, no tenant can
    take it. Without `region`, `total_free` counts every region. With one,
    it counts what an attach for a VM in `region` can reach — that region
    and the rest of its zone, or that region alone when it has no zone —
    and `regions` is filtered to `region`."""
    rows = (
        PublicIP.objects.filter(edge__status=EdgeStatus.ACTIVE, pool=PublicIpPool.GENERAL)
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


# ── egress regions and port 25 ────────────────────────────────────────

_REGION_FIELDS = frozenset({"mode", "routing_enabled", "enforce"})


def parse_region(raw: Any) -> str:
    """An ISO 3166-1 alpha-2 code, upper-cased."""
    code = raw.strip().upper() if isinstance(raw, str) else ""
    if not (len(code) == 2 and code.isascii() and code.isalpha()):
        raise NetworkError("bad-region", "region must be an ISO 3166-1 alpha-2 code (e.g. 'AU')")
    return code


def egress_region_view(row: EgressRegion) -> dict[str, Any]:
    """One entry of `GET /v1/network/egress-regions` (the backend's
    contract). The caps are vali's settings, the same for every region."""
    return {
        "region": row.region,
        "mode": row.mode,
        "routing_enabled": row.routing_enabled,
        "enforce": row.enforce,
        "default_cap_mbps": int(settings.VALI_NET_CAP_DEFAULT_MBPS),
        "cap_mbps_by_flavor": {
            str(k): int(v) for k, v in dict(settings.VALI_NET_CAP_MBPS_BY_FLAVOR).items()
        },
    }


def _has_egress_edge(region: str, *, exclude_pk: int | None = None) -> bool:
    edges = IngressEdge.objects.filter(
        region=region, status=EdgeStatus.ACTIVE, egress_ip__isnull=False
    ).exclude(netbird_peer_id="")
    if exclude_pk is not None:
        edges = edges.exclude(pk=exclude_pk)
    return edges.exists()


def update_egress_region(region: str, body: dict[str, Any]) -> EgressRegion:
    """Create or update a region's egress policy. `mode=edge` needs a
    bound, active edge with an `egress_ip` in the region (§4). The miners'
    policies and the edges' feeds follow on the next tick."""
    unknown = set(body) - _REGION_FIELDS
    if unknown:
        raise NetworkError("bad-request", f"unknown fields: {sorted(unknown)}")
    if "mode" in body and body["mode"] not in EgressMode.values:
        raise NetworkError("bad-request", f"mode must be one of {sorted(EgressMode.values)}")
    for flag in ("routing_enabled", "enforce"):
        if flag in body and not isinstance(body[flag], bool):
            raise NetworkError("bad-request", f"{flag} must be a boolean")
    with transaction.atomic():
        row, _ = EgressRegion.objects.select_for_update().get_or_create(region=region)
        for name in sorted(_REGION_FIELDS & set(body)):
            setattr(row, name, body[name])
        if row.mode == EgressMode.EDGE and not _has_egress_edge(region):
            raise NetworkError(
                "no-egress-edge",
                f"edge mode needs a bound, active edge with an egress_ip in {region}",
            )
        row.save()
    return row


def set_egress_ip(edge: IngressEdge, raw: Any) -> None:
    """Set (or clear, with `None`) the edge's shared egress address: a
    public address that is in no edge's pool. Clearing the last egress
    edge of an edge-mode region is refused — its VMs would lose their exit.
    Locks the edge; call inside the caller's transaction."""
    if raw is None:
        mode = EgressRegion.objects.filter(region=edge.region).values_list("mode", flat=True)
        if mode.first() == EgressMode.EDGE and not _has_egress_edge(
            edge.region, exclude_pk=edge.pk
        ):
            raise NetworkError(
                "egress-in-use", f"{edge.region} is in edge mode and this is its egress edge"
            )
        edge.egress_ip = None
        return
    address = parse_public_address(raw)
    if PublicIP.objects.filter(address=address).exists():
        raise NetworkError("address-taken", f"{address} is in an edge's public IP pool")
    edge.egress_ip = address


def public_ip_smtp_view(ip: PublicIP) -> dict[str, Any]:
    return {
        "address": ip.address,
        "vm_id": ip.vm.vm_id if ip.vm else None,
        "smtp_allowed": ip.smtp_allowed,
    }


def get_smtp_allowed(address: str) -> PublicIP:
    """The attached address's port-25 state, refused like `set_smtp_allowed`:
    an unattached row's flag is stale (a re-attach closes it again)."""
    ip = PublicIP.objects.select_related("vm").filter(address=address).first()
    if ip is None:
        raise NetworkError("address-not-found", f"{address} is not one of our addresses")
    if ip.state != PublicIpState.ATTACHED:
        raise NetworkError("address-not-attached", f"{address} is {ip.state}")
    return ip


def set_smtp_allowed(
    address: str, allowed: bool, expected_vm_id: str | None = None
) -> PublicIP:
    """Unblock (or block again) outbound TCP 25 for the holder of an
    attached address. The edge and the holder's miner pick it up on their
    next pass; a re-attach closes it again. `expected_vm_id`, checked under
    the row lock, refuses the change if the address now has another holder."""
    with transaction.atomic():
        ip = (
            PublicIP.objects.select_for_update(of=("self",))
            .select_related("vm")
            .filter(address=address)
            .first()
        )
        if ip is None:
            raise NetworkError("address-not-found", f"{address} is not one of our addresses")
        if ip.state != PublicIpState.ATTACHED:
            raise NetworkError("address-not-attached", f"{address} is {ip.state}")
        holder = ip.vm.vm_id if ip.vm else None
        if expected_vm_id is not None and holder != expected_vm_id:
            raise NetworkError("vm-mismatch", f"{address} is attached to {holder}")
        if ip.smtp_allowed != allowed:
            ip.smtp_allowed = allowed
            ip.save(update_fields=["smtp_allowed"])
            bump_revision(ip.edge_id)
    log.info(
        "public-ip: %s (vm=%s) port 25 %s",
        address,
        ip.vm.vm_id if ip.vm else "-",
        "unblocked" if allowed else "blocked",
    )
    return ip


# ── reconcile ─────────────────────────────────────────────────────────


@dataclass(frozen=True)
class ReconcileReport:
    released: int = 0
    unquarantined: int = 0
    retargeted: int = 0
    membership_changes: int = 0
    egress_changes: int = 0


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
            ).update(target_ip=new_target, epoch=F("epoch") + 1)
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


def _sync_cdn_flag() -> int:
    """Apply `VALI_CDN_ENABLED` to every edge's `cdn_feed`, bumping the
    revision of each edge it changes in the same statement — whether or not
    it serves a CDN address right now, so no concurrent attach or retarget
    can change its feed between the check and the bump. A flip is rare and
    a re-render cheap. One query while every edge already matches. Returns
    the number of edges changed."""
    flag = cdn_enabled()
    changed = IngressEdge.objects.exclude(cdn_feed=flag).update(
        cdn_feed=flag, desired_revision=F("desired_revision") + 1
    )
    if changed:
        log.info("public-ip: VALI_CDN_ENABLED=%s applied — %d edge(s) re-render", flag, changed)
    return changed


def reconcile(*, now: Any = None) -> ReconcileReport:
    """One idempotent pass, run by the orchestration tick.

    Database half, every tick: release addresses of VMs that are no longer
    live, return quarantined addresses to the pool once past
    `VALI_PUBLIC_IP_QUARANTINE_S`, and re-render the edges serving a CDN
    address when `VALI_CDN_ENABLED` flipped.

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
    try:
        _sync_cdn_flag()
    except Exception:  # noqa: BLE001 — retried next pass; the routing half must still run.
        log.exception("public-ip: applying VALI_CDN_ENABLED to the edges failed")
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
    # Last: it reads the overlay addresses and attachments just refreshed.
    from . import egress

    try:
        fed = egress.reconcile()
    except Exception:  # noqa: BLE001 — the address half above must still report.
        log.exception("egress: reconcile failed")
        fed = egress.ReconcileReport()
    return ReconcileReport(
        released=released,
        unquarantined=unquarantined,
        retargeted=retargeted,
        membership_changes=membership,
        egress_changes=fed.leases + fed.regions + fed.revisions,
    )
