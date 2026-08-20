"""Transport-agnostic request-building and response-parsing helpers.

Shared by the sync (``requests``) and async (``httpx``) clients so the URL
joining, header assembly and error-envelope handling live in one place. The
two transports themselves stay separate.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from .errors import HippiusApiError

if TYPE_CHECKING:
    from .models import OnProgress, ProvisionStep

logger = logging.getLogger("hippius_validator_client")

_JSON_HEADERS = {"Accept": "application/json"}


def emit_progress(callback: OnProgress | None, step: ProvisionStep) -> None:
    """Fire a progress ``callback`` with ``step``, swallowing any exception.

    A UI callback that raises must never crash the poll loop; the failure is
    logged at ``exception`` level so it is still diagnosable.
    """
    if callback is None:
        return
    try:
        callback(step)
    except Exception:  # noqa: BLE001 — a bad UI callback must not break polling
        logger.exception("hippius_validator_client on_progress callback raised")


def build_url(base_url: str, path: str) -> str:
    """Join ``base_url`` and an absolute API ``path`` (e.g. ``/v1/vm/launch``)."""
    return f"{base_url.rstrip('/')}/{path.lstrip('/')}"


def build_headers(
    token: str,
    host_header: str | None,
    *,
    json_body: bool = False,
) -> dict[str, str]:
    """Assemble the request headers.

    ``host_header`` overrides the ``Host`` header — required when calling the
    validator by IP, because it validates ``Host`` against ``ALLOWED_HOSTS``.
    """
    headers: dict[str, str] = {
        "Authorization": f"Bearer {token}",
        **_JSON_HEADERS,
    }
    if json_body:
        headers["Content-Type"] = "application/json"
    if host_header:
        headers["Host"] = host_header
    return headers


def parse_json(status: int, text: str, json_loader: Any) -> Any:
    """Decode a response body, tolerating an empty / non-JSON payload."""
    if not text:
        return None
    try:
        return json_loader(text)
    except ValueError:
        return text


def handle_response(status: int, body: Any) -> dict[str, Any]:
    """Return the JSON body for a 2xx response, else raise ``HippiusApiError``.

    The validator returns ``{"error", "category"}`` on every 4xx/5xx.
    """
    if 200 <= status < 300:
        if isinstance(body, dict):
            return body
        # A 2xx with a non-object body is unexpected for these endpoints.
        return {"_raw": body}
    raise HippiusApiError.from_response(status, body)
