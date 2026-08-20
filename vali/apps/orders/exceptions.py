"""DRF exception handler for the orders app.

Django raises [`django.core.exceptions.RequestDataTooBig`] when an
incoming request's `Content-Length` exceeds
`settings.DATA_UPLOAD_MAX_MEMORY_SIZE`. By default DRF turns that
into an HTTP 500; we want a structured **413 Request Entity Too
Large** with the same `{error, category}` schema the view emits for
post-body checks, so a misbehaving caller sees a consistent contract
either way the cap fires.
"""

from __future__ import annotations

from django.core.exceptions import RequestDataTooBig
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import exception_handler as drf_default_handler


def vali_exception_handler(exc, context):
    """Convert Django's `RequestDataTooBig` into a 413 with the
    `{error, category: "wire"}` schema. Anything else falls through
    to DRF's default handling.
    """
    if isinstance(exc, RequestDataTooBig):
        return Response(
            {
                "error": "request body exceeds DATA_UPLOAD_MAX_MEMORY_SIZE",
                "category": "wire",
            },
            status=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
        )
    return drf_default_handler(exc, context)
