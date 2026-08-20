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


# The `telemetry.SourceType` discriminator a miner's linked
# `TelemetrySource` row carries. Defined here as the single source of
# truth the register/quarantine views and the telemetry last-seen hook
# all read; it mirrors `telemetry.SourceType.MINER`.
TELEMETRY_SOURCE_KIND = "miner"


class MinerIdentity(models.Model):
    """One registered compute miner — operator-curated identity.

    Field-by-field:

    - `miner_id`        human-readable primary key, e.g.
                        `miner-1`. Operator-assigned.
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

    class Meta:
        ordering = ["miner_id"]
        verbose_name_plural = "miner identities"
        constraints = [
            models.UniqueConstraint(
                fields=["pubkey_hex"], name="miners_unique_pubkey"
            ),
            models.UniqueConstraint(
                fields=["platform_id"], name="miners_unique_platform"
            ),
        ]

    def __str__(self) -> str:
        return f"MinerIdentity {self.miner_id} ({self.status})"
