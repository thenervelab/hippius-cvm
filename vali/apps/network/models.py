"""Ingress edges and the public IPv4 addresses they serve.

An `IngressEdge` is a server we rent (not an SNP miner) that owns a few
public IPv4 addresses and is a NetBird peer. A `PublicIP` attached to a VM
is DNAT'ed on its edge to the VM's NetBird overlay address, and the VM's
egress is SNAT'ed back to it, so the VM uses one address both ways. vali
only records WHO holds WHICH address and where its traffic must go; the
edge agent renders that into its own netfilter state.

Not to be confused with the edge-gateway (`/v1/edge/...`), the relay that
fronts the miner plane — hence `IngressEdge` and the `/v1/network/` prefix.
"""

from __future__ import annotations

from django.db import models
from django.db.models import Q

from apps.lifecycle.models import Vm


class EdgeStatus(models.TextChoices):
    #: Takes new attachments.
    ACTIVE = "active", "Active"
    #: Keeps serving its attached addresses; takes no new ones.
    DRAINING = "draining", "Draining"
    #: Same as draining for vali; an operator marker for an edge being
    #: taken out of service.
    DISABLED = "disabled", "Disabled"


class PublicIpState(models.TextChoices):
    FREE = "free", "Free"
    ATTACHED = "attached", "Attached"
    #: Released recently. Held out of the pool for
    #: `VALI_PUBLIC_IP_QUARANTINE_S` so traffic still aimed at the previous
    #: holder never reaches ANOTHER tenant. The tenant that released it may
    #: take it back meanwhile (`last_tenant_id`).
    QUARANTINED = "quarantined", "Quarantined"


class IngressEdge(models.Model):
    #: A slug that ends up in NetBird object names (`hippius-pip-<name>` is a
    #: route `network_id`, capped at 40 characters by NetBird).
    name = models.SlugField(max_length=28, unique=True)
    provider = models.CharField(max_length=64, blank=True, default="")
    #: ISO 3166-1 alpha-2, upper case — the same key as a VM's region.
    region = models.CharField(max_length=2, db_index=True)
    #: The edge's NetBird peer. Empty until the edge is BOUND: an edge is
    #: registered before it can enrol (its setup key is minted for an edge
    #: that already exists), then bound with PATCH `netbird_ip`. An unbound
    #: edge takes no attachment, gets no routing and is served no address.
    netbird_peer_id = models.CharField(max_length=64, blank=True, default="")
    netbird_ip = models.GenericIPAddressField(protocol="IPv4", unique=True, null=True, blank=True)
    status = models.CharField(
        max_length=16, choices=EdgeStatus.choices, default=EdgeStatus.ACTIVE
    )
    #: Bumped on every change to what the edge must render; the agent
    #: reports the revision it applied, so `desired - applied` is its lag.
    desired_revision = models.BigIntegerField(default=1)
    applied_revision = models.BigIntegerField(default=0)
    last_seen_at = models.DateTimeField(null=True, blank=True)
    last_report = models.JSONField(default=dict, blank=True)
    #: Per-address rate cap the agent applies, in Mbit/s.
    per_ip_mbps = models.PositiveIntegerField(default=1000)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["name"]

    def __str__(self) -> str:
        return f"{self.name} ({self.region})"

    @property
    def bound(self) -> bool:
        return bool(self.netbird_peer_id)


class PublicIP(models.Model):
    address = models.GenericIPAddressField(protocol="IPv4", unique=True)
    edge = models.ForeignKey(IngressEdge, on_delete=models.CASCADE, related_name="addresses")
    #: The holder while attached, the previous holder while quarantined
    #: (audit), `NULL` once free.
    vm = models.ForeignKey(
        Vm, on_delete=models.PROTECT, null=True, blank=True, related_name="public_ips"
    )
    state = models.CharField(
        max_length=16, choices=PublicIpState.choices, default=PublicIpState.FREE
    )
    #: The VM's NetBird overlay address last pushed to the edge. `NULL`
    #: until the VM's peer is resolved; the edge is not told about the
    #: address before that.
    target_ip = models.GenericIPAddressField(protocol="IPv4", null=True, blank=True)
    attached_at = models.DateTimeField(null=True, blank=True)
    released_at = models.DateTimeField(null=True, blank=True)
    #: While quarantined: the tenant of the VM that released it — the only
    #: tenant an attach may hand it to before the window ends. Blank
    #: otherwise, and for a VM with no tenant (which reuses nothing: two
    #: blank tenants are not the same tenant).
    last_tenant_id = models.CharField(max_length=256, blank=True, default="")

    class Meta:
        ordering = ["address"]
        constraints = [
            models.UniqueConstraint(
                fields=["vm"],
                condition=Q(state="attached"),
                name="network_one_attached_public_ip_per_vm",
            ),
            models.CheckConstraint(
                condition=(
                    Q(state="free", vm__isnull=True)
                    | Q(state="attached", vm__isnull=False)
                    | Q(state="quarantined")
                ),
                name="network_public_ip_holder_matches_state",
            ),
        ]

    def __str__(self) -> str:
        return f"{self.address} ({self.state})"
