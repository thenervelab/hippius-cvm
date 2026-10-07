"""The CDN fleet (docs/design/cdn.md, CDN plan V1).

- `CdnRegion` — how many nodes vali runs in a region, and on which flavor.
- `CdnNode` — one CDN VM and where it is in its lifecycle (§B.1 states).
- `CdnCaKey` — the PUBLIC half of the CDN CA: one row per Vault Transit key
  version, with the self-signed CA certificate vali made over it. The
  private key never leaves Transit (`apps.cdn.ca`).
- `CdnFleetKey` — a fleet key version's PUBLIC metadata, as the KBS signed
  it (K2). vali never holds the fleet secret, not even wrapped.
- `CdnRevision` — the one counter every CDN read carries as `revision`
  and `ETag`; any change the backend can see bumps it.
"""

from __future__ import annotations

from django.db import models
from django.db.models import F, Q

from apps.lifecycle.models import Vm


class CdnNodeState(models.TextChoices):
    #: The launch job is in flight.
    LAUNCHING = "launching", "launching"
    #: The VM is active, not yet ready.
    BOOTING = "booting", "booting"
    #: Serving: the backend may publish its DNS record.
    READY = "ready", "ready"
    #: vali asked for its removal; waiting for the backend's dns-released.
    DRAINING = "draining", "draining"
    #: The backend released its DNS record, and the grace period passed.
    DRAINED = "drained", "drained"
    #: §24 in progress.
    DECOMMISSIONING = "decommissioning", "decommissioning"
    #: The launch failed, or the guest stayed wedged too long. The backend
    #: treats it like `draining`.
    FAILED = "failed", "failed"
    #: Gone. Never listed.
    DESTROYED = "destroyed", "destroyed"


#: A node in one of these states holds (or may soon hold) a VM that serves.
LIVE_NODE_STATES = frozenset(
    {
        CdnNodeState.LAUNCHING,
        CdnNodeState.BOOTING,
        CdnNodeState.READY,
        CdnNodeState.DRAINING,
    }
)

#: The states a node certificate may be issued or renewed in: the VM runs
#: and the backend still accepts the node (§B.1 registration check).
CERTIFIABLE_NODE_STATES = frozenset(
    {CdnNodeState.BOOTING, CdnNodeState.READY, CdnNodeState.DRAINING}
)


class DrainReason(models.TextChoices):
    REPLACE = "replace", "replace"
    SCALE_DOWN = "scale_down", "scale_down"
    UPGRADE = "upgrade", "upgrade"
    ROTATE = "rotate", "rotate"
    OPERATOR = "operator", "operator"


class CdnRegion(models.Model):
    #: ISO 3166-1 alpha-2, upper case — the same key as `IngressEdge.region`.
    region = models.CharField(max_length=2, primary_key=True)
    #: vali runs nodes here. The backend's own mirror decides whether it
    #: routes and sells (two keys, plan G.10).
    active = models.BooleanField(default=False)
    desired_nodes = models.PositiveIntegerField(default=0)
    flavor = models.CharField(max_length=32, default="xlarge")
    #: Where the backend fails the region's traffic over to. Blank = none.
    failover_region = models.CharField(max_length=2, blank=True, default="")
    #: The last node launch here that failed before its node was ready, and
    #: how many did in a row (reset when a node gets ready): the launch
    #: backoff, and the "no spare host" signal of a replacement.
    launch_failed_at = models.DateTimeField(null=True, blank=True)
    launch_failures = models.PositiveIntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["region"]
        constraints = [
            models.CheckConstraint(
                condition=Q(region__regex=r"^[A-Z]{2}$"),
                name="cdn_region_alpha2_upper",
            ),
        ]

    def __str__(self) -> str:
        return f"cdn {self.region} ({self.desired_nodes} nodes, active={self.active})"


class CdnNode(models.Model):
    #: The node's VM, once its launch created the row (a node is recorded
    #: before its launch, which is how the launch knows its role). A VM is
    #: a CDN node at most once, for its whole life.
    vm = models.OneToOneField(
        Vm, on_delete=models.PROTECT, null=True, blank=True, related_name="cdn_node"
    )
    #: The node's name in every CDN API — and its VM's `vm_id`, always.
    node_id = models.CharField(max_length=128, unique=True)
    region = models.CharField(max_length=2, db_index=True)
    state = models.CharField(
        max_length=16,
        choices=CdnNodeState.choices,
        default=CdnNodeState.LAUNCHING,
        db_index=True,
    )
    state_changed_at = models.DateTimeField(null=True, blank=True)
    #: Why the node is `failed`, for the operator.
    failure_reason = models.CharField(max_length=256, blank=True, default="")
    #: What the node launched: its region's flavor, the blessed image and
    #: the bake it resolved to, and the launch job.
    flavor = models.CharField(max_length=32, blank=True, default="")
    image_name = models.CharField(max_length=64, blank=True, default="")
    bake_id = models.CharField(max_length=64, blank=True, default="")
    launch_job_id = models.CharField(max_length=64, blank=True, default="")

    #: The node's Ed25519 public key, `HKDF(lifecycle seed,
    #: "HIPPIUS_CDN_NODE_KEY_V1")` (`apps.cdn.node_key`). Set at the first
    #: certificate and never changed: the lifecycle seed is fixed for the
    #: VM's life.
    node_public_key = models.BinaryField(max_length=32, null=True, blank=True)
    #: The current node certificate (public). Blank until the first issue.
    cert_pem = models.TextField(blank=True, default="")
    cert_serial = models.CharField(max_length=64, blank=True, default="")
    cert_not_before = models.DateTimeField(null=True, blank=True)
    cert_not_after = models.DateTimeField(null=True, blank=True)
    #: The VM generation the certificate's SAN names.
    cert_generation = models.BigIntegerField(null=True, blank=True)
    #: The CA (`CdnCaKey.kid`) that signed it.
    cert_ca_kid = models.CharField(max_length=32, blank=True, default="")

    ready_at = models.DateTimeField(null=True, blank=True)
    drain_requested_at = models.DateTimeField(null=True, blank=True)
    drain_reason = models.CharField(
        max_length=16, choices=DrainReason.choices, blank=True, default=""
    )
    dns_released_at = models.DateTimeField(null=True, blank=True)
    #: `dns_released_at` was set by the operator override
    #: (`vali_cdn_node force-drained`), not by the backend's ack.
    dns_release_forced = models.BooleanField(default=False)
    #: The backend's Route 53 change behind its ack (audit).
    dns_release_change_id = models.CharField(max_length=256, blank=True, default="")
    #: When vali alerted that the ack is late (once per drain).
    drain_ack_alerted_at = models.DateTimeField(null=True, blank=True)
    #: The revision the backend said it acted on (audit).
    dns_release_revision_seen = models.BigIntegerField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["region", "created_at", "node_id"]
        constraints = [
            models.CheckConstraint(
                condition=Q(region__regex=r"^[A-Z]{2}$"),
                name="cdn_node_region_alpha2_upper",
            ),
            # The decommission gate (B.2): a node that was ever `ready` —
            # so may have a DNS record — reaches `drained` or
            # `decommissioning` only once the backend released the record.
            # `destroyed` records what happened, whoever destroyed it.
            models.CheckConstraint(
                condition=(
                    ~Q(state__in=["drained", "decommissioning"])
                    | Q(dns_released_at__isnull=False)
                    | Q(ready_at__isnull=True)
                ),
                name="cdn_node_drained_only_after_dns_released",
            ),
            # ...and `ready_at` is what says it was: a ready node has one.
            models.CheckConstraint(
                condition=~Q(state="ready") | Q(ready_at__isnull=False),
                name="cdn_node_ready_has_ready_at",
            ),
        ]

    def __str__(self) -> str:
        return f"cdn node {self.node_id} ({self.region}, {self.state})"


class CdnCaState(models.TextChoices):
    #: Published in the bundle (so the backend trusts it) but not signing.
    PENDING = "pending", "pending"
    #: Signs every new node certificate.
    ACTIVE = "active", "active"
    #: No longer signs; still published until its certificates expire.
    RETIRING = "retiring", "retiring"
    #: Out of the bundle.
    RETIRED = "retired", "retired"


#: The CA states the published bundle carries.
PUBLISHED_CA_STATES = frozenset({CdnCaState.PENDING, CdnCaState.ACTIVE, CdnCaState.RETIRING})


class CdnCaKey(models.Model):
    #: `cdnca-<transit key version>`.
    kid = models.CharField(max_length=32, primary_key=True)
    transit_key = models.CharField(max_length=64)
    transit_key_version = models.PositiveIntegerField()
    #: Raw Ed25519 public key, as Transit reported it.
    public_key = models.BinaryField(max_length=32)
    #: The self-signed CA certificate, signed by Transit.
    cert_pem = models.TextField()
    not_before = models.DateTimeField()
    not_after = models.DateTimeField()
    state = models.CharField(max_length=16, choices=CdnCaState.choices, db_index=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["transit_key", "transit_key_version"]
        constraints = [
            models.UniqueConstraint(
                fields=["transit_key", "transit_key_version"],
                name="cdn_ca_one_row_per_transit_version",
            ),
            models.UniqueConstraint(
                fields=["state"],
                condition=Q(state="active"),
                name="cdn_ca_one_active",
            ),
            models.UniqueConstraint(
                fields=["state"],
                condition=Q(state="pending"),
                name="cdn_ca_one_pending",
            ),
        ]

    def __str__(self) -> str:
        return f"{self.kid} ({self.state})"


class CdnFleetKeyState(models.TextChoices):
    #: Nodes are being rebooted onto the keyring; nobody seals to it yet.
    PENDING = "pending", "pending"
    #: The backend seals to it.
    ACTIVE = "active", "active"
    #: Unseal only.
    RETIRING = "retiring", "retiring"
    #: No blob references it; out of the keyring.
    RETIRED = "retired", "retired"


class CdnFleetKey(models.Model):
    version = models.PositiveIntegerField(primary_key=True)
    #: Raw X25519 public key, as the KBS derived it from the wrapped key.
    x25519_public = models.BinaryField(max_length=32)
    #: The KBS response key that signed it, and its Ed25519 signature over
    #: `"HIPPIUS_CDN_FLEET_PUB_V1" ‖ version ‖ x25519_public`.
    kbs_kid_hex = models.CharField(max_length=128)
    kbs_signature = models.BinaryField(max_length=64)
    state = models.CharField(max_length=16, choices=CdnFleetKeyState.choices, db_index=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["version"]
        constraints = [
            # The backend and the cdn-agent refuse a feed with two active
            # versions (`fleet-version-multiple-active`).
            models.UniqueConstraint(
                fields=["state"],
                condition=Q(state="active"),
                name="cdn_fleet_one_active",
            ),
        ]

    def __str__(self) -> str:
        return f"cdn fleet key v{self.version} ({self.state})"


class CdnRevision(models.Model):
    """The single row (`pk=1`) holding the CDN revision."""

    value = models.BigIntegerField(default=0)
    #: A digest of what the CDN reads show but the network app owns (each
    #: node's address and edge, each region's pool): a change bumps the
    #: revision (`apps.cdn.reconcile.sync_network_revision`).
    network_digest = models.CharField(max_length=64, blank=True, default="")
    #: Since when the liveness breaker holds (`apps.cdn.reconcile`); NULL
    #: while it does not.
    liveness_hold_since = models.DateTimeField(null=True, blank=True)
    #: Consecutive passes without an outage since the hold started: the
    #: start clears only after two, so a ratio hovering around half cannot
    #: restart the cap on every flip.
    liveness_clear_passes = models.PositiveSmallIntegerField(default=0)

    def __str__(self) -> str:
        return f"cdn revision {self.value}"

    @classmethod
    def current(cls) -> int:
        row = cls.objects.filter(pk=1).only("value").first()
        return row.value if row is not None else 0

    @classmethod
    def bump(cls) -> int:
        """Advance the revision; call inside the transaction that made the
        change, so the change and its revision commit together."""
        cls.objects.get_or_create(pk=1)
        cls.objects.filter(pk=1).update(value=F("value") + 1)
        return cls.objects.get(pk=1).value
