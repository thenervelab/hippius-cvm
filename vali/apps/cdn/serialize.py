"""The §B shapes (CONTRACT_vali_backend_node.md, adopted by the backend)."""

from __future__ import annotations

import base64
import datetime as dt
import hashlib
import hmac
from typing import Any

from django.conf import settings

from . import ca, fleet
from .models import CdnNode, CdnNodeState, CdnRegion

#: Destroyed nodes drop out of the list (§B.1).
LISTED_STATES = tuple(s for s in CdnNodeState.values if s != CdnNodeState.DESTROYED)


def _ts(value: dt.datetime | None) -> str | None:
    if value is None:
        return None
    return value.astimezone(dt.UTC).isoformat().replace("+00:00", "Z")


def host_ref(host: str) -> str | None:
    """An opaque, stable name for the miner a node runs on: anti-affinity
    audit only. Keyed, so it cannot be matched back to a miner id."""
    if not host:
        return None
    key = str(settings.SECRET_KEY).encode()
    digest = hmac.new(key, b"hippius-cdn-host-ref:" + host.encode(), hashlib.sha256).hexdigest()
    return f"h-{digest[:6]}"


def _measurement(vm_id: str) -> str | None:
    """The node's current launch measurement: the newest pin the miner
    accepted, else the newest pin."""
    from apps.orchestration.models import MeasurementLedger

    rows = MeasurementLedger.objects.filter(vm_id=vm_id)
    row = (
        rows.filter(launched_at__isnull=False).order_by("-launched_at").first()
        or rows.order_by("-pinned_at").first()
    )
    return row.launch_digest_hex.lower() if row is not None else None


def _image(node: CdnNode) -> dict[str, Any]:
    from apps.tenant_bake.models import TenantBake

    bake = TenantBake.objects.filter(bake_id=node.bake_id).first() if node.bake_id else None
    return {
        "name": node.image_name or None,
        "bake_id": node.bake_id or None,
        "verity_root_hash": bake.verity_root_hash if bake is not None else None,
    }


def node(n: CdnNode) -> dict[str, Any]:
    from apps.network.models import PublicIP, PublicIpState

    vm = n.vm
    ip = (
        PublicIP.objects.filter(vm=vm, state=PublicIpState.ATTACHED).select_related("edge").first()
        if vm is not None
        else None
    )
    cert = None
    if n.cert_pem:
        cert = {
            "pem": n.cert_pem,
            "serial": n.cert_serial,
            "not_before": _ts(n.cert_not_before),
            "not_after": _ts(n.cert_not_after),
        }
    drain = None
    if n.drain_requested_at is not None or n.dns_released_at is not None:
        drain = {
            "requested_at": _ts(n.drain_requested_at),
            "reason": n.drain_reason or None,
            "dns_released_at": _ts(n.dns_released_at),
        }
    return {
        "node_id": n.node_id,
        "vm_id": n.node_id,
        "region": n.region,
        "generation": int(vm.generation) if vm is not None else None,
        "state": n.state,
        "public_ip": ip.address if ip is not None else None,
        "edge": ip.edge.name if ip is not None else None,
        "flavor": n.flavor or None,
        "host_ref": host_ref(vm.host) if vm is not None else None,
        "image": _image(n),
        "measurement_hex": _measurement(n.node_id),
        "node_public_key_b64": (
            base64.b64encode(bytes(n.node_public_key)).decode("ascii")
            if n.node_public_key is not None
            else None
        ),
        "cert": cert,
        "created_at": _ts(n.created_at),
        "ready_at": _ts(n.ready_at),
        "drain": drain,
    }


def ca_block() -> dict[str, Any] | None:
    cas = ca.published_cas()
    active = next((c for c in cas if c.state == "active"), None)
    if active is None:
        return None
    nxt = next((c for c in cas if c.state == "pending"), None)
    return {
        "kid": active.kid,
        "cert_pem": active.cert_pem,
        "next": {"kid": nxt.kid, "cert_pem": nxt.cert_pem} if nxt is not None else None,
    }


def nodes(revision: int) -> dict[str, Any]:
    rows = CdnNode.objects.filter(state__in=LISTED_STATES).select_related("vm")
    return {
        "revision": revision,
        "ca": ca_block(),
        "fleet_keys": fleet.published(),
        "nodes": [node(n) for n in rows],
    }


def region(r: CdnRegion) -> dict[str, Any]:
    from apps.network.models import IngressEdge, PublicIP, PublicIpPool, PublicIpState

    edges = list(IngressEdge.objects.filter(region=r.region).order_by("name"))
    ips = PublicIP.objects.filter(edge__in=edges, pool=PublicIpPool.CDN)
    caps = [c for c in ips.values_list("cap_mbps", flat=True) if c]
    return {
        "region": r.region,
        "active": r.active,
        "desired_nodes": r.desired_nodes,
        "ready_nodes": CdnNode.objects.filter(region=r.region, state=CdnNodeState.READY).count(),
        "flavor": r.flavor,
        "edges": [e.name for e in edges],
        "cdn_ip_mbps": min(caps) if caps else None,
        "pool": {
            "total": ips.count(),
            "free": ips.filter(state=PublicIpState.FREE).count(),
            "attached": ips.filter(state=PublicIpState.ATTACHED).count(),
            "quarantined": ips.filter(state=PublicIpState.QUARANTINED).count(),
        },
        "failover_region": r.failover_region or None,
    }
