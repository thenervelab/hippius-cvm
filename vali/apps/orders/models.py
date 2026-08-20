"""OrderTicket intake model.

vali is an **opaque transport** for the COSE_Sign1 OrderTicket
(ARCHITECTURE.md §3 / §4): it never verifies the L1 signature, never
inspects sealed user-data, never picks security inputs. This table
stores the byte-exact COSE blob plus parsed metadata for indexing.

Schema invariants:

- `ticket_id` is unique. A second intake with the same `ticket_id`
  but different bytes is a §13 anomaly (replay or L1 bug) — the view
  returns 409 in that case.
- `cose_blob` is the byte-exact L1-emitted envelope. Re-transmission
  to the KBS uses this blob verbatim — no re-encoding, no re-signing.
- Time fields are stored as unix seconds (matching the `OrderTicket`
  CBOR schema in `hippius-types`).
"""

from __future__ import annotations

import uuid

from django.db import models


class OrderTicketIntake(models.Model):
    """A single COSE_Sign1 OrderTicket that L1 handed off to vali."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    # Extracted from the parsed ticket. Unique so a replay surfaces.
    ticket_id = models.CharField(max_length=256, unique=True)
    vm_id = models.CharField(max_length=256, db_index=True)
    tenant_id = models.CharField(max_length=256, db_index=True)
    user_id = models.CharField(max_length=256)
    lease_id = models.CharField(max_length=256)
    vm_generation = models.BigIntegerField()
    # Unix seconds (matches `hippius_types::ticket::OrderTicket`).
    issue_time = models.BigIntegerField()
    expiry = models.BigIntegerField()
    node_id = models.CharField(max_length=256)
    platform_id = models.CharField(max_length=256)
    resource_class = models.CharField(max_length=128)
    # L1 ticket-signing kid (hex). Stored for KBS routing; never
    # trusted as authority — the KBS independently checks it against
    # the §22 offline allowlist.
    kid_hex = models.CharField(max_length=512)
    # Byte-exact COSE_Sign1 envelope as received from L1. vali
    # re-emits this blob to the KBS unchanged.
    cose_blob = models.BinaryField()
    received_at = models.DateTimeField(auto_now_add=True, db_index=True)
    # `ServiceClient.name` of the authenticated caller that handed
    # over this ticket. Audit trail per §15.
    received_from = models.CharField(max_length=256)

    class Meta:
        ordering = ["-received_at"]
        indexes = [
            models.Index(fields=["expiry"]),
            models.Index(fields=["vm_id", "vm_generation"]),
        ]

    def __str__(self) -> str:
        return f"OrderTicket {self.ticket_id} (vm={self.vm_id} gen={self.vm_generation})"
