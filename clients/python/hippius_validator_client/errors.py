"""Error types for the Hippius validator client."""

from __future__ import annotations

from typing import Any


class HippiusApiError(Exception):
    """A non-2xx response from the validator API.

    The validator emits a uniform failure envelope on every 4xx/5xx:

        {"error": "<human message>", "category": "<stable slug>"}

    ``category`` is a stable machine-readable slug (e.g. ``wire``,
    ``bad-field``, ``not-found``, ``conflict``, ``already-in-flight``,
    ``version-conflict``, ``internal``) that lets callers branch without
    string-matching the human-readable ``error``.
    """

    def __init__(
        self,
        status: int,
        error: str,
        category: str | None,
        body: Any = None,
    ) -> None:
        self.status = status
        self.error = error
        self.category = category
        self.body = body
        super().__init__(f"[{status}] {category or 'error'}: {error}")

    @classmethod
    def from_response(cls, status: int, body: Any) -> HippiusApiError:
        """Build from a parsed JSON body (or an opaque non-JSON body)."""
        if isinstance(body, dict):
            error = str(body.get("error", body))
            category = body.get("category")
            return cls(status, error, category, body)
        return cls(status, str(body), None, body)


class HippiusTimeoutError(HippiusApiError):
    """A ``wait_for_*`` poll helper exceeded its ``timeout`` budget."""

    def __init__(self, message: str, body: Any = None) -> None:
        super().__init__(status=0, error=message, category="client-timeout", body=body)


class LaunchFailedError(HippiusApiError):
    """A polled launch job reached the terminal ``failed`` state."""

    def __init__(self, message: str, body: Any = None) -> None:
        super().__init__(status=0, error=message, category="launch-failed", body=body)


class BakeFailedError(HippiusApiError):
    """A polled bake reached the terminal ``failed`` state."""

    def __init__(self, message: str, body: Any = None) -> None:
        super().__init__(status=0, error=message, category="bake-failed", body=body)


class DecommissionFailedError(HippiusApiError):
    """A polled decommission job reached the terminal ``failed`` state."""

    def __init__(self, message: str, body: Any = None) -> None:
        super().__init__(
            status=0, error=message, category="decommission-failed", body=body
        )


class MigrationFailedError(HippiusApiError):
    """A polled §25 migration job reached the terminal ``failed`` state.

    The destination was NOT activated (the migration fails closed). Inspect
    ``body["reason"]`` for the failing step and ``body["quarantine_node_id"]``
    for a §13-quarantined source.
    """

    def __init__(self, message: str, body: Any = None) -> None:
        super().__init__(
            status=0, error=message, category="migration-failed", body=body
        )
