"""Per-miner launch-error ledger — what a miner's operator sees of the
launches that failed on their host (`GET /v1/operator/nodes`).

Observability ONLY: nothing here feeds placement, capacity or the §23
capability ledger (`apps.scheduler.cvm_capability` keeps its own closed
vocabulary and its own writer). Recording a failure changes no behaviour.

What is recorded, and from where:

- the miner's ANSWER to a `tenant-preflight` or `launch` order vali sent it
  — the static class it put in the body (`dispatch-failed`,
  `insufficient-resources`, …) and, from an agent that sends one, the finer
  reason code in the `x-hippius-reason` response header that the Edge
  relays (`libvirt-driver/define`, `tenant-preflight/ovmf-missing`, …);
- an Edge 502/504 with no body: the Edge could not reach the miner, or gave
  up waiting on it — code `preflight-timeout` for a `tenant-preflight`
  order, `miner-unreachable` for a `launch` order.

A `preflight-timeout` is usually the Edge's 30 s forward giving up on a
preflight that is still staging a cold artefact set — the miner did nothing
wrong, and vali re-places. It stays in the ledger, but the operator only
sees it, and it only counts in the streak, once `PREFLIGHT_TIMEOUT_RUN`
of them follow each other with no accepted launch in between.

A vali-side fault (Vault, minting, the KBS, vali → Edge transport) is not
the miner's and is never recorded here.

Both strings are MINER-CONTROLLED. Each passes `sanitize_code` — lower-case
`[a-z0-9._:/-]`, at most `MAX_CODE_LEN` — and anything else is replaced by
`invalid`, never trimmed into shape: an honest agent only ever sends static
codes (`MinerAgentError`'s `Display`), so a value outside the charset is not
a code at all. The row is keyed by the miner vali DISPATCHED to, so a miner
can only write to its own row, which only its own operator reads.

Fail-open: bookkeeping must never turn a launch outcome into another one.
"""

from __future__ import annotations

import logging
import re
from datetime import datetime
from typing import Any

from django.db import transaction
from django.utils import timezone

log = logging.getLogger(__name__)

#: Newest errors the operator sees per miner.
MAX_RECENT = 5
#: Newest errors stored per miner — more than `MAX_RECENT`, so hidden
#: `preflight-timeout`s never push a visible error out.
MAX_STORED = 20
#: Consecutive `preflight-timeout`s from which they are shown and counted.
PREFLIGHT_TIMEOUT_RUN = 3
#: Longest code kept. `MinerAgentError` codes are under 64 bytes; the rest
#: is headroom, not an invitation.
MAX_CODE_LEN = 128
#: Longest `order_id` kept (the miner-agent refuses longer ones).
MAX_ORDER_ID_LEN = 128

STAGE_PREFLIGHT = "preflight"
STAGE_LAUNCH = "launch"

#: vali's own codes, for answers that carry no miner code.
CODE_INVALID = "invalid"
CODE_UNREACHABLE = "miner-unreachable"
CODE_PREFLIGHT_TIMEOUT = "preflight-timeout"
CODE_UNCLASSIFIED = "unclassified"

_CODE_RE = re.compile(r"[a-z0-9][a-z0-9._:/-]*")
_ORDER_ID_RE = re.compile(r"[A-Za-z0-9._:-]+")
#: Edge statuses with no miner answer behind them.
_EDGE_STATUSES = frozenset({502, 504})


def sanitize_code(raw: str | None) -> str:
    """`raw` if it is a well-formed code, `""` if empty, else `invalid`."""
    value = (raw or "").strip()
    if not value:
        return ""
    if len(value) > MAX_CODE_LEN or not _CODE_RE.fullmatch(value):
        return CODE_INVALID
    return value


def printable(raw: str, limit: int = MAX_CODE_LEN) -> str:
    """`raw` as printable ASCII (anything else becomes `?`), at most `limit`
    characters — for miner bytes kept verbatim-ish (a launch emit), where
    a static class must survive unchanged."""
    return "".join(c if " " <= c <= "~" else "?" for c in raw[:limit])


def failure_entry(
    *,
    stage: str,
    http_status: int,
    classifier: str,
    reason: str = "",
    order_id: str = "",
) -> dict[str, Any]:
    """The sanitized record of one failed attempt (without `at`).

    `code` is the finest thing known: the miner's reason code, else its
    class, else, for a bodiless Edge 502/504, `preflight-timeout` at the
    preflight stage and `miner-unreachable` at the launch stage, else
    `unclassified`. `class` is the body class as vali branched on it."""
    cls = sanitize_code(classifier)
    code = sanitize_code(reason) or cls
    if not code and http_status in _EDGE_STATUSES:
        code = CODE_PREFLIGHT_TIMEOUT if stage == STAGE_PREFLIGHT else CODE_UNREACHABLE
    elif not code:
        code = CODE_UNCLASSIFIED
    oid = order_id if len(order_id) <= MAX_ORDER_ID_LEN and _ORDER_ID_RE.fullmatch(order_id) else ""
    return {
        "code": code,
        "class": cls or None,
        "http_status": int(http_status),
        "stage": stage,
        "order_id": oid or None,
    }


def record_failure(miner: Any, entry: dict[str, Any]) -> None:
    """Prepend `entry` (from `failure_entry`) to `miner`'s errors and bump
    its streak — except for a `preflight-timeout`, which `readout` counts
    only as part of a run. `miner` is the `MinerIdentity` vali dispatched
    to."""
    _write(miner, entry)


def record_ok(miner: Any) -> None:
    """`miner` accepted a launch: its streak restarts at 0. The error list
    is kept — it is history, not state."""
    _write(miner, None)


def _write(miner: Any, entry: dict[str, Any] | None) -> None:
    from .models import MinerLaunchErrors

    miner_id = getattr(miner, "miner_id", "") or ""
    if not miner_id:
        return
    try:
        with transaction.atomic():
            row, _ = MinerLaunchErrors.objects.select_for_update().get_or_create(miner_id=miner_id)
            # Read under the lock: outcomes apply in the order they are
            # stamped, so `errors` stays newest-first and a success is
            # never undone by an older failure that waited on the lock.
            now = timezone.now()
            if entry is None:
                row.fail_streak = 0
                row.last_ok_at = now
            else:
                if not _is_preflight_timeout(entry):
                    row.fail_streak += 1
                recent = row.errors if isinstance(row.errors, list) else []
                row.errors = [{**entry, "at": now.isoformat()}, *recent][:MAX_STORED]
            row.save()
    except Exception as exc:  # noqa: BLE001 — bookkeeping is never load-bearing
        log.warning("launch-errors: not recorded for miner=%s: %s", miner_id, exc)


def _is_preflight_timeout(entry: Any) -> bool:
    return isinstance(entry, dict) and entry.get("code") == CODE_PREFLIGHT_TIMEOUT


def _at(entry: dict[str, Any]) -> datetime | None:
    try:
        return datetime.fromisoformat(str(entry.get("at", "")))
    except ValueError:
        return None


def _visible(errors: list[Any], last_ok_at: datetime | None) -> tuple[list[Any], int]:
    """`errors` without the `preflight-timeout`s that are not part of a run
    of `PREFLIGHT_TIMEOUT_RUN` consecutive ones (an accepted launch breaks a
    run), and how many shown ones came after `last_ok_at` — the ones the
    streak counts."""

    def after_ok(entry: dict[str, Any]) -> bool:
        at = _at(entry)
        return last_ok_at is None or (at is not None and at > last_ok_at)

    visible: list[Any] = []
    since_ok = 0
    run: list[dict[str, Any]] = []

    def close_run() -> None:
        nonlocal since_ok
        if len(run) >= PREFLIGHT_TIMEOUT_RUN:
            visible.extend(run)
            since_ok += sum(1 for e in run if after_ok(e))
        run.clear()

    for entry in errors:
        if not _is_preflight_timeout(entry):
            close_run()
            visible.append(entry)
            continue
        if run and after_ok(run[-1]) != after_ok(entry):
            close_run()
        run.append(entry)
    close_run()
    return visible, since_ok


def readout(row: Any) -> dict[str, Any]:
    """The operator-API view of a `MinerLaunchErrors` row (or `None`)."""
    errors = list(row.errors) if row is not None and isinstance(row.errors, list) else []
    last_ok = getattr(row, "last_ok_at", None) if row is not None else None
    visible, timeouts = _visible(errors, last_ok)
    visible = visible[:MAX_RECENT]
    return {
        "last_launch_error": visible[0] if visible else None,
        "launch_fail_streak": (row.fail_streak if row is not None else 0) + timeouts,
        "recent_launch_errors": visible,
    }
