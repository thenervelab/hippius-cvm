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


class PublicIpPool(models.TextChoices):
    #: Handed to tenant VMs by `attach`.
    GENERAL = "general", "General"
    #: Reserved for the CDN fleet (docs/design/cdn.md §6.1), handed out by
    #: `attach_cdn` only. A tenant never holds one: it would receive CDN
    #: traffic and could answer HTTP-01 for our customers' domains.
    CDN = "cdn", "CDN"


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
    #: The shared SNAT address of the region's egress (edge mode,
    #: docs/design/egress-and-bandwidth.md §4). Never one of the edge's
    #: `PublicIP` addresses and never DNATed. `NULL` = this edge serves no
    #: egress.
    egress_ip = models.GenericIPAddressField(protocol="IPv4", unique=True, null=True, blank=True)
    #: SHA-256 of the egress-mode feed last seen by the reconcile (blank
    #: while the edge is served no egress block). A change bumps
    #: `desired_revision`, whatever caused it — a lease, a setting, a flag.
    egress_digest = models.CharField(max_length=64, blank=True, default="")
    #: The feed carries `pool` and `cap_mbps` on the edge's CDN addresses:
    #: `VALI_CDN_ENABLED` as the reconcile last applied it, in the same
    #: transaction as the revision bump. The feed reads this, never the
    #: setting, so the content and its revision move together whichever
    #: process serves the feed.
    cdn_feed = models.BooleanField(default=False, db_default=False)
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
    #: The region the holder runs in, as last fed to the edge (egress
    #: design §8.3: bandwidth is priced where the VM runs). Blank until
    #: known.
    vm_region = models.CharField(max_length=2, blank=True, default="")
    #: Bumped whenever the `(vm, target_ip)` binding or `vm_region` changes,
    #: so a usage sample names the binding it was counted under.
    epoch = models.BigIntegerField(default=0)
    #: Outbound TCP 25 unblocked for the holder (a support decision). Reset
    #: on every attach: an unblock never follows the address to its next
    #: holder.
    smtp_allowed = models.BooleanField(default=False)
    #: Which attach may hand the address out. Set when the address is added
    #: to its edge, never changed while it lives there.
    pool = models.CharField(
        max_length=16,
        choices=PublicIpPool.choices,
        default=PublicIpPool.GENERAL,
        db_default=PublicIpPool.GENERAL,
        db_index=True,
    )
    #: The address's own rate cap in Mbit/s, in place of the edge's
    #: `per_ip_mbps`: set on every CDN address (sized to the node), never on
    #: a general one.
    cap_mbps = models.PositiveIntegerField(null=True, blank=True)

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
            models.CheckConstraint(
                condition=(
                    Q(pool="general", cap_mbps__isnull=True)
                    | Q(pool="cdn", cap_mbps__isnull=False, cap_mbps__gte=1)
                ),
                name="network_public_ip_cap_only_on_cdn",
            ),
        ]

    def __str__(self) -> str:
        return f"{self.address} ({self.state})"


class EgressMode(models.TextChoices):
    #: Guests leave through their miner's own NAT.
    LOCAL = "local", "Local"
    #: Guests leave through the region's edge; the miners allow only the
    #: listed endpoints once `enforce` is on.
    EDGE = "edge", "Edge"


class EgressRegion(models.Model):
    """How one region's guests reach the internet (egress design §4).

    A region with no row is `local`. `routing_enabled` and `enforce` only
    mean something in edge mode; they let the rollout and its rollback move
    one step at a time.
    """

    #: ISO 3166-1 alpha-2, upper case — the same key as `IngressEdge.region`.
    region = models.CharField(max_length=2, primary_key=True)
    mode = models.CharField(max_length=8, choices=EgressMode.choices, default=EgressMode.LOCAL)
    #: Edge mode: put the region's VMs on the exit route.
    routing_enabled = models.BooleanField(default=False)
    #: Edge mode: the miners apply the forward allowlist.
    enforce = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["region"]
        constraints = [
            models.CheckConstraint(
                condition=Q(region__regex=r"^[A-Z]{2}$"),
                name="network_egress_region_alpha2_upper",
            ),
        ]

    def __str__(self) -> str:
        return f"{self.region} ({self.mode})"


#: The first tc class id an egress lease takes: above the per-address
#: classes (`0x10 + index`) that share the edge's `wt0` root.
EGRESS_CLASS_ID_MIN = 0x1000
#: tc minor ids are 16 bits, and the edge refuses `0xffff` (the backend
#: validates `0x1000..=0xfffe`): one lease there would fail the whole feed.
EGRESS_CLASS_ID_MAX = 0xFFFE


class VmEgressLease(models.Model):
    """A VM's place in its region edge's egress feed (egress design §5.2).

    Kept for the VM's whole life, even while it is out of the feed
    (`active=False`, e.g. it holds a public IP): its `class_id` is never
    handed to another VM while it lives. Deleted once the VM is gone.
    """

    vm = models.OneToOneField(
        Vm, on_delete=models.CASCADE, primary_key=True, related_name="egress_lease"
    )
    edge = models.ForeignKey(
        IngressEdge, on_delete=models.CASCADE, related_name="egress_leases"
    )
    region = models.CharField(max_length=2)
    target_ip = models.GenericIPAddressField(protocol="IPv4")
    #: Bumped whenever `(vm, target_ip)` or `region` changes, and on a move
    #: to another edge.
    epoch = models.BigIntegerField(default=1)
    #: The edge's tc class for this VM, unique per edge.
    class_id = models.PositiveIntegerField()
    #: In the edge's feed right now.
    active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["edge_id", "class_id"]
        constraints = [
            models.UniqueConstraint(
                fields=["edge", "class_id"], name="network_egress_class_id_per_edge"
            ),
            models.CheckConstraint(
                condition=Q(class_id__gte=EGRESS_CLASS_ID_MIN, class_id__lte=EGRESS_CLASS_ID_MAX),
                name="network_egress_class_id_range",
            ),
            models.CheckConstraint(
                condition=Q(region__regex=r"^[A-Z]{2}$"),
                name="network_egress_lease_region_alpha2_upper",
            ),
        ]

    def __str__(self) -> str:
        return f"egress {self.vm_id} on {self.edge_id} class {self.class_id:#x} e{self.epoch}"


class MinerNetPolicy(models.Model):
    """The `net-policy` order state of one miner (egress design §7).

    `revision` is per miner and monotonic, the miner's replay floor: it is
    bumped when the policy's content changes (`content_key`), never when
    only its expiry moves. `body_sha` is the content hash the miner acks
    for the current revision (`applied:<revision>:<body_sha>`), `acked_*`
    what it last acked.
    """

    miner = models.OneToOneField(
        "miners.MinerIdentity",
        on_delete=models.CASCADE,
        primary_key=True,
        related_name="net_policy",
    )
    revision = models.BigIntegerField(default=0)
    #: SHA-256 of the body without `revision` and `not_after_unix`.
    content_key = models.CharField(max_length=64, blank=True, default="")
    #: `net-policy-digest` of the current revision's body.
    body_sha = models.CharField(max_length=64, blank=True, default="")
    #: The current revision's body, without `not_after_unix` (readout).
    body = models.JSONField(default=dict, blank=True)
    region = models.CharField(max_length=2, blank=True, default="")
    mode = models.CharField(max_length=8, choices=EgressMode.choices, default=EgressMode.LOCAL)
    #: Last push attempt, whatever its outcome.
    sent_at = models.DateTimeField(null=True, blank=True)
    acked_revision = models.BigIntegerField(default=0)
    acked_sha = models.CharField(max_length=64, blank=True, default="")
    acked_at = models.DateTimeField(null=True, blank=True)
    #: Why the last attempt did not end in the expected ack; blank once it did.
    last_error = models.CharField(max_length=256, blank=True, default="")
    #: When the agent last refused an edge-mode policy as unsupported (422
    #: `net-policy-unsupported`, an agent without edge mode). No edge-mode
    #: revision is sent again for `VALI_NET_POLICY_UNSUPPORTED_RETRY_S`, or
    #: until an operator clears it after an upgrade (`vali_net_policy
    #: --retry`). Cleared by an edge-mode ack.
    edge_unsupported_at = models.DateTimeField(null=True, blank=True)
    #: Consecutive 500 `net-policy-apply` refusals of the current revision:
    #: the same revision is re-sent with an exponential backoff.
    apply_failures = models.PositiveIntegerField(default=0)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["miner_id"]
        verbose_name_plural = "miner net policies"

    def __str__(self) -> str:
        return f"MinerNetPolicy {self.miner_id} r{self.revision} (acked r{self.acked_revision})"

    @property
    def acked_current(self) -> bool:
        return (
            self.revision > 0
            and self.acked_revision == self.revision
            and self.acked_sha == self.body_sha
        )
