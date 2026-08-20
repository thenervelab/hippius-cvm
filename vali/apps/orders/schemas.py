"""Doc-only serializers for the orders OpenAPI schema (OrderTicket
intake). Referenced from `@extend_schema` in `views.py` only — never
wired into request handling. The request is raw CBOR/COSE_Sign1 bytes
(documented as `application/octet-stream` BINARY, not a JSON body); this
serializer mirrors only the minimal JSON `_ok` success envelope.
"""

from __future__ import annotations

from rest_framework import serializers


class OrderTicketAcceptedSerializer(serializers.Serializer):
    """`POST /v1/order_ticket` success body (`_ok`).

    Minimal JSON — the COSE blob / nonce / vault paths are NEVER echoed
    back (§20 logging discipline). `201` on first intake, `200` on a
    byte-identical idempotent re-intake; the body shape is identical.
    """

    ticket_id = serializers.CharField(help_text="Parsed ticket id (unique).")
    vm_id = serializers.CharField()
    vm_generation = serializers.IntegerField()
    received_at = serializers.DateTimeField(help_text="Server intake timestamp (ISO-8601).")
    created = serializers.BooleanField(
        help_text="`true` on first intake (201), `false` on idempotent re-intake (200)."
    )
