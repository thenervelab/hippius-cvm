"""DRF parser for COSE_Sign1 octet-stream bodies.

The intake view needs `request.body` as raw bytes (the COSE blob).
DRF's default JSON parser would consume and try to decode the body
first. This parser is the canonical content-type contract for the
`POST /v1/order_ticket` endpoint.

Content-Type accepted: `application/cose-sign1` (registered for the
endpoint in `apps.orders.views`; ops tooling that uses
`application/octet-stream` works through the bytes-from-`request.body`
path without going through DRF's content negotiation).

The parser bounds the read at `VALI_TICKET_MAX_BYTES + 1` so a
permissive ingress can't OOM the worker; the view turns
`len(body) > VALI_TICKET_MAX_BYTES` into a structured 413.
"""

from __future__ import annotations

from rest_framework.parsers import BaseParser


class CoseSign1OctetStreamParser(BaseParser):
    """Return the raw request body unchanged."""

    # DRF picks the parser by Content-Type. Listing both lets ops
    # tooling that doesn't speak the RFC 9052 media-type identifier
    # still hit the endpoint.
    media_type = "application/cose-sign1"

    def parse(self, stream, media_type=None, parser_context=None) -> bytes:
        # Bound the read at `VALI_TICKET_MAX_BYTES + 1` so an attacker
        # with a permissive ingress can't OOM the Python worker by
        # streaming gigabytes here. The view checks `len(body) >
        # max_bytes` and surfaces 413 with the extra byte we read.
        from django.conf import settings  # local import: avoid Django setup at module load

        limit = int(settings.VALI_TICKET_MAX_BYTES) + 1
        data = stream.read(limit)
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError(
                f"CoseSign1OctetStreamParser expected bytes, got {type(data).__name__}"
            )
        return bytes(data)
