"""Miner-fleet identity registry — PR-vali-miner-register.

Spec of record: ARCHITECTURE.md §13 / §23 (miners are untrusted; vali
gates every signed envelope on an out-of-band-registered identity).

`MinerIdentity` is the operator-curated registry of the compute miners
vali knows. A row is created ONLY through the admin register endpoint
(`POST /v1/admin/miner/register`, miner-admin ServiceToken) — never
self-asserted by a miner.

It is deliberately distinct from `scheduler.MinerCapacity`: that model
mirrors a miner's on-chain `MinerStatus` / quality score and is keyed
on the 64-hex compute `node_id`; THIS model is the off-chain
fleet/identity record — the Ed25519 telemetry key, the AMD platform
id, the NetBird mesh coordinates — keyed on a human-readable
`miner_id`. The scheduler trusts the chain; the telemetry broker
trusts this registry.

## Link to the §9 telemetry broker

Registering a miner also provisions a linked
`telemetry.TelemetrySource` (`source="miner"`, `source_id=miner_id`,
`verifying_key` = the miner pubkey). That is the row the pull-only
broker's fail-closed ingest path checks — so miner-signed envelopes
(heartbeats etc., a future PR-MA-6) are accepted iff the miner is a
registered, non-quarantined identity. Quarantining a miner deactivates
that source (`is_active=False`).

## Two distinct quarantine mechanisms

`MinerIdentity.status` is the **operator-controlled lifecycle**:
`quarantined` is set deliberately via the admin endpoint and is
permanent until an operator reverses it. It is mirrored onto the
linked source's `is_active`.

The §9 broker's **poison-quarantine** (`TelemetrySource.quarantined_until`,
set by `telemetry.service._record_failure` after repeated bad
signatures) is a separate, TRANSIENT state with its own TTL. It is
deliberately NOT mirrored onto `MinerIdentity.status`: the two have
different lifetimes (permanent vs auto-expiring), so collapsing them
would be wrong. Miner-signed envelope ingestion — the only path that
can trip a poison-quarantine — lands with PR-MA-6, which owns
surfacing that transient state.

Tenant-signed `served_receipt`s are a SEPARATE trust plane: they are
signed by the tenant guest key, their `TelemetrySource` is provisioned
out-of-band, and they are NOT gated by this registry.
"""

from __future__ import annotations

from django.db import models


class MinerStatus(models.TextChoices):
    """`MinerIdentity` lifecycle. Pinned strings."""

    ACTIVE = "active", "Active"
    QUARANTINED = "quarantined", "Quarantined"


class SnpGeneration(models.TextChoices):
    """AMD EPYC SEV-SNP generation of a miner host. Pinned strings — the
    launch-digest recompute maps each to its vCPU model
    (`orchestration.services.launch_digest.SNP_GENERATION_VCPU`)."""

    MILAN = "milan", "Milan (EpycMilan)"
    GENOA = "genoa", "Genoa (EpycGenoa)"
    TURIN = "turin", "Turin (EpycTurin)"


# The `telemetry.SourceType` discriminator a miner's linked
# `TelemetrySource` row carries. Defined here as the single source of
# truth the register/quarantine views and the telemetry last-seen hook
# all read; it mirrors `telemetry.SourceType.MINER`.
TELEMETRY_SOURCE_KIND = "miner"


# The `platform_id` a permissionless miner's `MinerIdentity` carries when
# vali AUTO-PROVISIONS it from its first on-chain-gated heartbeat
# (`telemetry.service.autoprovision_node_heartbeat_source`) — vali knows
# the node key there, never the AMD CHIP_ID. A placeholder, not a
# platform identity: it fails the scheduler's real-CHIP_ID gate and the
# launch-digest generation mapping, and the register endpoint upgrades
# it (only it) to the operator-supplied CHIP_ID.
#
# `platform_id` is UNIQUE, so the placeholder is PER NODE —
# `onchain:<node_id_hex>` (`autoprovision_platform_id`); a single shared
# literal would let only one unregistered permissionless miner exist at a
# time. The bare `AUTOPROVISION_PLATFORM_ID` is the legacy form (rewritten
# by migration 0006) and is still recognised. Always test with
# `is_autoprovision_placeholder`, never with `==`.
AUTOPROVISION_PLATFORM_ID = "onchain"
AUTOPROVISION_PLATFORM_ID_PREFIX = f"{AUTOPROVISION_PLATFORM_ID}:"


def autoprovision_platform_id(node_id_hex: str) -> str:
    """The per-node placeholder `platform_id` for an auto-provisioned
    miner: `onchain:<node_id_hex>` (lower-case; 8 + 64 chars, within the
    column's 128). Unique because the node id is."""
    return f"{AUTOPROVISION_PLATFORM_ID_PREFIX}{node_id_hex.lower()}"


def is_autoprovision_placeholder(platform_id: str | None) -> bool:
    """True iff `platform_id` is an auto-provision placeholder — the
    per-node `onchain:<…>` form or the legacy bare `onchain`. Exact,
    case-sensitive: vali writes these values itself."""
    pid = platform_id or ""
    return pid == AUTOPROVISION_PLATFORM_ID or pid.startswith(
        AUTOPROVISION_PLATFORM_ID_PREFIX
    )


class MinerIdentity(models.Model):
    """One registered compute miner — operator-curated identity.

    Field-by-field:

    - `miner_id`        human-readable primary key, e.g.
                        `miner-a`. Operator-assigned.
    - `pubkey_hex`      the miner's Ed25519 public key, 64 lowercase
                        hex chars (unique). Mirrored into the linked
                        `TelemetrySource.verifying_key` — the trust
                        anchor for the miner's signed envelopes.
    - `platform_id`     the AMD platform identity (CHIP_ID / VCEK
                        identifier). One physical machine ⇒ one
                        `platform_id` (unique).
    - `netbird_peer_id` / `netbird_ip` — the miner's NetBird mesh
                        coordinates, if known. Informational.
    - `registered_at`   first-registration wall-clock.
    - `last_seen_at`    refreshed by the telemetry broker each time a
                        verified envelope from this miner is ingested
                        (`None` until the first one).
    - `last_heartbeat_sequence` — the monotonic `sequence` of the last
                        ACCEPTED signed heartbeat (§K / PR-Part4-B).
                        `None` until the first heartbeat. The ingest
                        gate refuses any heartbeat whose `sequence` is
                        not strictly greater than this value — the
                        replay / regression defence — and bumps it
                        under a row lock on accept.
    - `status`          `active` | `quarantined`. A quarantined miner's
                        linked `TelemetrySource` is deactivated, so the
                        §9 broker refuses its telemetry.
    - `snp_generation`  `milan` | `genoa` | `turin` | "" (unset). Operator-set;
                        unset ⇒ inferred from the CHIP_ID length. Required
                        for Milan (64-byte CHIP_ID, same as Genoa).

    Uniqueness on `pubkey_hex` and `platform_id` is DB-enforced — two
    miners can never share a key or a physical platform.
    """

    miner_id = models.CharField(max_length=64, primary_key=True)
    pubkey_hex = models.CharField(max_length=64)
    platform_id = models.CharField(max_length=128, db_index=True)
    chain_node_id = models.CharField(
        max_length=64,
        null=True,
        blank=True,
        unique=True,
        help_text=(
            "The miner's on-chain compute node_id — 64 lowercase hex "
            "(the 32-byte ed25519 key registered in "
            "pallet-compute-scoring). This is the key the §23 scheduler "
            "ranks placements by (`scheduler.MinerCapacity.miner_node_id`), "
            "and the bridge the launch pipeline joins on to recover THIS "
            "identity (miner_id, netbird_ip, platform_id) from a "
            "scheduler-chosen placement. DISTINCT from `pubkey_hex` — that "
            "is the off-chain telemetry-signing key; this is the on-chain "
            "compute-registration key. NULL until the operator backfills "
            "it at register; unique when set, so two miners can never "
            "claim the same on-chain node."
        ),
    )
    netbird_peer_id = models.CharField(max_length=64, blank=True, default="")
    netbird_ip = models.GenericIPAddressField(null=True, blank=True)
    registered_at = models.DateTimeField(auto_now_add=True)
    last_seen_at = models.DateTimeField(null=True, blank=True)
    last_heartbeat_sequence = models.PositiveBigIntegerField(
        null=True,
        blank=True,
        default=None,
        help_text=(
            "Monotonic sequence of the last accepted heartbeat "
            "envelope (§K / PR-Part4-B replay gate). NULL = no "
            "heartbeat received yet."
        ),
    )
    status = models.CharField(
        max_length=16,
        choices=MinerStatus.choices,
        default=MinerStatus.ACTIVE,
    )
    snp_generation = models.CharField(
        max_length=8,
        choices=SnpGeneration.choices,
        blank=True,
        default="",
        # DB-side default too: a pod still on the previous image INSERTs
        # without this column during a rollout, and must not hit NOT NULL.
        db_default="",
        help_text=(
            "SEV-SNP CPU generation, operator-registered. Selects the vCPU "
            "model of the launch-digest recompute and the §25 same-generation "
            "gate. Empty = legacy, inferred from the CHIP_ID length (8 bytes "
            "⇒ Turin, 64 bytes ⇒ Genoa). REQUIRED for Milan: its CHIP_ID is "
            "64 bytes like Genoa's, so an unset Milan host is measured as "
            "Genoa and every launch is refused. Must agree with the CHIP_ID "
            "length (turin = 8 bytes, genoa/milan = 64), else vali fails "
            "closed."
        ),
    )

    class Meta:
        ordering = ["miner_id"]
        verbose_name_plural = "miner identities"
        constraints = [
            models.UniqueConstraint(fields=["pubkey_hex"], name="miners_unique_pubkey"),
            models.UniqueConstraint(fields=["platform_id"], name="miners_unique_platform"),
        ]

    def __str__(self) -> str:
        return f"MinerIdentity {self.miner_id} ({self.status})"

    def clean(self) -> None:
        """Refuse an `snp_generation` inconsistent with the CHIP_ID length
        (the Django admin's edit path; the register endpoint checks the
        same thing). The launch-digest recompute would fail closed on it
        anyway; this surfaces the mistake at edit time instead."""
        super().clean()
        if not self.snp_generation:
            return
        from django.core.exceptions import ValidationError

        from apps.orchestration.effects import EffectError
        from apps.orchestration.services.launch_digest import (
            _vcpu_type_for_platform,
        )

        try:
            _vcpu_type_for_platform(self.platform_id, self.snp_generation)
        except EffectError as exc:
            raise ValidationError({"snp_generation": str(exc)}) from exc


class LocationVerdict(models.TextChoices):
    """How much vali trusts the DETECTED location of a miner.

    Every input is measured server-side or bounded by physics — the miner
    asserts nothing:

    - `verified`   — the public IP the miner's NetBird peer connects from
                     geolocates somewhere the round-trip time measured from
                     vali permits (a tunnel can only ADD latency, never
                     remove it), the two GeoIP sources agree, and every
                     tenant CVM on the host egresses from that same IP.
    - `unverified` — a location is known but one physical check could not
                     be made or failed: no RTT sample, RTT too short for
                     the claimed distance, peer not seen recently.
    - `mismatch`   — the evidence CONTRADICTS itself: a tenant CVM on this
                     host egresses from a different public IP than the host
                     (guest traffic tunnelled elsewhere), or the two GeoIP
                     sources disagree on the country.
    - `unknown`    — no evidence yet (no NetBird peer matched, no public
                     connection IP, GeoIP lookup failed).
    """

    VERIFIED = "verified", "Verified"
    UNVERIFIED = "unverified", "Unverified"
    MISMATCH = "mismatch", "Mismatch"
    UNKNOWN = "unknown", "Unknown"


class MinerLocation(models.Model):
    """The DETECTED geographic location of one miner, with the evidence and
    the verdict `vali_geo_probe` derived from it.

    Written ONLY by the probe. `region` is the ISO 3166-1 alpha-2 country
    code (`FR`) — the scheduler's region gate and `GET /v1/operator/regions`
    key on it, and treat a miner as being in a region only when `verdict`
    is `verified` (`VALI_GEO_REQUIRE_VERIFIED`). `evidence_json` keeps the
    raw sources of the last cycle so an operator can audit a verdict.
    """

    miner = models.OneToOneField(
        MinerIdentity,
        on_delete=models.CASCADE,
        primary_key=True,
        related_name="location",
    )
    # The public IP the miner's NetBird peer connects to the management
    # server FROM — observed by that server, never reported by the miner.
    connection_ip = models.GenericIPAddressField(null=True, blank=True)
    country_code = models.CharField(max_length=2, blank=True, default="", db_index=True)
    city = models.CharField(max_length=64, blank=True, default="")
    latitude = models.FloatField(null=True, blank=True)
    longitude = models.FloatField(null=True, blank=True)
    # ASNs are unsigned 32-bit (4-byte ASNs) — a plain integer column
    # would refuse anything above 2^31.
    asn = models.PositiveBigIntegerField(null=True, blank=True)
    as_prefix = models.CharField(max_length=64, blank=True, default="")
    as_holder = models.CharField(max_length=128, blank=True, default="")
    # Minimum TCP-connect round-trip from the probe pod to the miner's
    # NetBird address — the physical distance bound.
    rtt_ms = models.FloatField(null=True, blank=True)
    rtt_vantage = models.CharField(max_length=64, blank=True, default="")
    # Public egress IPs of the tenant CVMs hosted on this miner, as seen by
    # the NetBird management server. The attested guest's own view of
    # "where do I come out" — must equal `connection_ip`.
    guest_egress_ips = models.JSONField(default=list, blank=True)
    verdict = models.CharField(
        max_length=16,
        choices=LocationVerdict.choices,
        default=LocationVerdict.UNKNOWN,
        db_index=True,
    )
    verdict_reasons = models.JSONField(default=list, blank=True)
    netbird_last_seen_at = models.DateTimeField(null=True, blank=True)
    # When the GeoIP source (RIPEstat) last ANSWERED for `connection_ip`.
    # Drives the lookup TTL — distinct from `observed_at`, which every cycle
    # refreshes, so a cached answer still expires.
    geo_refreshed_at = models.DateTimeField(null=True, blank=True)
    observed_at = models.DateTimeField()
    evidence_json = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ["miner_id"]

    def __str__(self) -> str:
        return f"MinerLocation {self.miner_id} {self.region or '??'} ({self.verdict})"

    @property
    def region(self) -> str:
        return self.country_code.upper()
