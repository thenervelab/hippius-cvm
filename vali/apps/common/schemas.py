"""Shared, doc-only serializers for the drf-spectacular OpenAPI schema.

These serializers exist SOLELY to shape the generated OpenAPI 3 document
(`/v1/schema`, `/v1/docs`). They are referenced from `@extend_schema`
decorators and are NEVER wired into request handling — every `/v1/`
APIView keeps its own manual `request.data` parsing and hand-built
`Response`. Changing a field here only changes the docs, not behaviour.

`ErrorSerializer` models the uniform failure envelope the validator emits
across every endpoint: `{"error": "<message>", "category": "<slug>"}`
(see `apps.orders.exceptions.vali_exception_handler` and each view's
`_error` helper).
"""

from __future__ import annotations

from rest_framework import serializers


class ErrorSerializer(serializers.Serializer):
    """The uniform `{error, category}` failure envelope.

    Every `/v1/` endpoint returns this shape on a 4xx/5xx. `category` is a
    stable machine-readable slug (e.g. `wire`, `bad-field`, `not-found`,
    `conflict`, `internal`) that lets callers branch without string-matching
    the human-readable `error`.
    """

    error = serializers.CharField(help_text="Human-readable failure message.")
    category = serializers.CharField(
        help_text=(
            "Stable machine-readable failure slug — e.g. `wire` (malformed "
            "body), `bad-field` (invalid value), `not-found`, `conflict` "
            "(state conflict / in-flight job), `internal` (server/config fault)."
        )
    )
