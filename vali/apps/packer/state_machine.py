"""PackerBuild state machine — legal transitions + required fields.

Single authority on what `POST /finalize` will accept. The view
delegates here so the rule set is testable without HTTP.

Legal transitions:

    Queued → Running       (Packer Job picks the build up)
    Running → Succeeded    (build completes — needs artifact + provenance)
    Running → Failed       (build errors out — needs failure_reason)

Anything else is rejected at the view boundary. In particular:
  - `Succeeded` and `Failed` are terminal — no transition out.
  - `Queued → Succeeded` / `Queued → Failed` are rejected (the
    worker must claim the row by flipping to Running first so the
    `started_at` timestamp is set).
  - `Running → Queued` is rejected — a retry is a new row, not a
    rewind.
"""

from __future__ import annotations

from dataclasses import dataclass

from .models import PackerBuildState


class FinalizeError(Exception):
    """A finalize request was rejected for a non-CAS reason — bad
    shape, illegal source state, missing required field, etc. The
    view surfaces this as HTTP 400 with `category`.
    """

    def __init__(self, message: str, category: str) -> None:
        super().__init__(message)
        self.message = message
        self.category = category


# Stable category strings — kept in sync with the view's error
# vocabulary so the Django consumer can map each to a code.
CAT_ILLEGAL = "illegal-transition"
CAT_MISSING_FIELD = "missing-field"
CAT_BAD_FIELD = "bad-field"


@dataclass(frozen=True)
class FinalizeRequest:
    """Caller-supplied payload for `POST /build/<id>/finalize`."""

    to_state: PackerBuildState
    if_version: int
    artifact_sha256: str | None = None
    provenance_signed_url: str | None = None
    failure_reason: str | None = None


_LEGAL_TRANSITIONS: frozenset[tuple[PackerBuildState, PackerBuildState]] = frozenset(
    {
        (PackerBuildState.QUEUED, PackerBuildState.RUNNING),
        (PackerBuildState.RUNNING, PackerBuildState.SUCCEEDED),
        (PackerBuildState.RUNNING, PackerBuildState.FAILED),
    }
)


def legal(from_state: PackerBuildState, to_state: PackerBuildState) -> bool:
    """Return True iff `from_state → to_state` is in the table above."""
    return (from_state, to_state) in _LEGAL_TRANSITIONS


def required_args(to_state: PackerBuildState, req: FinalizeRequest) -> None:
    """Raise `FinalizeError` if `req` is missing fields needed for
    the target state.

    - `Succeeded`: must carry `artifact_sha256` (64 hex chars) AND
      `provenance_signed_url` (non-empty).
    - `Failed`: must carry `failure_reason` (non-empty). The reason
      is bounded by the model's `max_length=256` — the view rejects
      longer strings at parse time.
    """
    if to_state == PackerBuildState.SUCCEEDED:
        if not req.artifact_sha256:
            raise FinalizeError(
                "artifact_sha256 required for Succeeded target", CAT_MISSING_FIELD
            )
        if not _is_sha256_hex(req.artifact_sha256):
            raise FinalizeError(
                "artifact_sha256 must be 64 lowercase hex chars",
                CAT_BAD_FIELD,
            )
        if not req.provenance_signed_url:
            raise FinalizeError(
                "provenance_signed_url required for Succeeded target",
                CAT_MISSING_FIELD,
            )
    if to_state == PackerBuildState.FAILED:
        if not req.failure_reason:
            raise FinalizeError(
                "failure_reason required for Failed target", CAT_MISSING_FIELD
            )


def _is_sha256_hex(s: str) -> bool:
    """64 lowercase hex chars. Rejecting upper-case keeps the wire
    representation canonical (no two builds with the "same" digest
    differing only in case)."""
    if len(s) != 64:
        return False
    return all(c in "0123456789abcdef" for c in s)
