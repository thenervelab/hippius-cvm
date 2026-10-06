"""An M1/M2 VM waiting on its customer key guardian (design §6).

With customer-held keys the guest asks the tenant's guardian FIRST and
only then the KBS, waiting inside ONE boot — no reboot loop, no KBS state
moving — until the guardian answers. While it waits, the miner's guardian
relay reports a signed `awaiting-guardian` vm-progress milestone with a
closed-vocabulary reason (at most once a minute per VM). vali records the
latest one on the `Vm` row (`record`) and clears it once a later milestone
proves the guest got past its guardian (`clear_on_milestone`).

What it is for:

- DISPLAY: `boot=awaiting-guardian`, the reason and since when, on the
  operator VM status (`view`). The backend and console render it.
- Not reading the wait as a FAILURE: a restore's pre-commit timer
  (`timer_start`) and the reboot-recovery WEDGED trigger (`is_awaiting`)
  hold back while the guest waits — otherwise the restore auto-reverts,
  and reboot-recovery relaunches, a VM the customer is about to unblock.

What it is NOT: evidence. The miner derives the milestone from the traffic
it relays, so it can forge or suppress it. The customer's guardian audit
log is the truth. That is why the pause is bounded
(`VALI_GUARDIAN_WAIT_MAX_PAUSE_S`), is only honoured for an M1/M2 VM, and
never for a terminal reason (`refused:erased` — the key is gone, nothing
will ever unblock the boot).
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

from django.conf import settings
from django.utils import timezone

#: The vm-progress wire milestone (`VmProgressMilestone::AwaitingGuardian`).
MILESTONE = "awaiting-guardian"
#: What the operator status shows for a waiting VM.
BOOT_STATE = "awaiting-guardian"
#: Wire milestones that prove the guest is past its guardian leg: the
#: guardian leg runs BEFORE the KBS release (guardian-first ordering), so a
#: KEK release — and a fortiori a running guest — means it answered.
CLEARING_MILESTONES = frozenset({"kek-released", "running"})
#: Reasons after which nothing will unblock the boot: never a pause.
TERMINAL_REASONS = frozenset({"refused:erased"})
#: The key mode that has no guardian (M0).
_NO_GUARDIAN_MODE = "hippius"


def fresh_s() -> float:
    """How long one report keeps a VM `awaiting` (the relay re-reports at
    most every 60 s while the guest waits)."""
    return float(getattr(settings, "VALI_GUARDIAN_WAIT_FRESH_S", 600.0))


def max_pause_s() -> float:
    """The most a guardian wait can hold back a timer, past its own
    deadline. Bounds what a forged `awaiting-guardian` can stall."""
    return float(getattr(settings, "VALI_GUARDIAN_WAIT_MAX_PAUSE_S", 86400.0))


def has_guardian(vm: Any) -> bool:
    return (getattr(vm, "key_mode", "") or _NO_GUARDIAN_MODE) != _NO_GUARDIAN_MODE


def is_awaiting(vm: Any, now: datetime | None = None) -> bool:
    """The VM's latest progress is a FRESH, non-terminal `awaiting-guardian`
    of an M1/M2 VM."""
    at = getattr(vm, "guardian_wait_at", None)
    reason = getattr(vm, "guardian_wait_reason", "") or ""
    if not has_guardian(vm) or not reason or at is None or reason in TERMINAL_REASONS:
        return False
    now = now or timezone.now()
    return now - at <= timedelta(seconds=fresh_s())


def _waiting_now(vm: Any, now: datetime) -> bool:
    """Waiting, terminal reasons included — for `since` bookkeeping."""
    at = getattr(vm, "guardian_wait_at", None)
    return (
        bool(vm.guardian_wait_reason)
        and at is not None
        and (now - at <= timedelta(seconds=fresh_s()))
    )


def record(vm: Any, reason: str, signed_at: datetime, now: datetime | None = None) -> bool:
    """Record a verified `awaiting-guardian:<reason>` on `vm` and save it.

    `signed_at` is the report's SIGNED timestamp (the miner's clock, inside
    the ingest's skew window). Ordering is decided on it, because delivery
    is fire-and-forget and can reorder: a report no newer than the last
    clearing milestone (`guardian_wait_cleared_at`) describes a wait the
    guest already got past, and one older than the report already recorded
    is stale — both are dropped, so a late report can never re-arm a
    cleared wait (and the pauses it drives). Freshness (`guardian_wait_at`)
    stays on vali's clock.

    Returns False (nothing written) for such a report, and for an M0 VM,
    which has no guardian — a miner reporting one is ignored."""
    if not has_guardian(vm):
        return False
    cleared = getattr(vm, "guardian_wait_cleared_at", None)
    last = getattr(vm, "guardian_wait_signed_at", None)
    if (cleared is not None and signed_at <= cleared) or (last is not None and signed_at < last):
        return False
    now = now or timezone.now()
    if not _waiting_now(vm, now):
        vm.guardian_wait_since = now
    vm.guardian_wait_reason = reason
    vm.guardian_wait_at = now
    vm.guardian_wait_signed_at = signed_at
    vm.save(
        update_fields=[
            "guardian_wait_reason",
            "guardian_wait_since",
            "guardian_wait_at",
            "guardian_wait_signed_at",
            "updated_at",
        ]
    )
    return True


def clear_on_milestone(vm: Any, milestone_wire: str, signed_at: datetime) -> list[str]:
    """A verified `kek-released` / `running` (signed at `signed_at`) proves
    the guest got past its guardian. It advances `guardian_wait_cleared_at`
    (so a LATER-delivered but earlier-signed wait report is dropped) and
    ends the displayed wait — unless the wait on record was signed after
    this milestone (a new boot already waiting again; a late clearing
    milestone must not hide it). `guardian_wait_at` is KEPT: `timer_start`
    still credits the time already spent waiting.

    Returns the fields changed (the caller saves them), `[]` for none."""
    if milestone_wire not in CLEARING_MILESTONES or not has_guardian(vm):
        return []
    changed: list[str] = []
    cleared = getattr(vm, "guardian_wait_cleared_at", None)
    if cleared is None or signed_at > cleared:
        vm.guardian_wait_cleared_at = signed_at
        changed.append("guardian_wait_cleared_at")
    last = getattr(vm, "guardian_wait_signed_at", None)
    if vm.guardian_wait_reason and (last is None or signed_at >= last):
        vm.guardian_wait_reason = ""
        vm.guardian_wait_since = None
        changed += ["guardian_wait_reason", "guardian_wait_since"]
    return changed


def holds_back_recovery(vm: Any, now: datetime | None = None) -> bool:
    """Whether reboot-recovery must leave a WEDGED-reading VM alone because
    its guest is waiting on its guardian: a fresh non-terminal wait
    (`is_awaiting`) that began no more than `max_pause_s()` ago. The same
    cap as the restore timer, measured from the wait's `since`, so a
    forged, never-ending wait cannot switch recovery off for a VM."""
    now = now or timezone.now()
    if not is_awaiting(vm, now):
        return False
    since = getattr(vm, "guardian_wait_since", None) or vm.guardian_wait_at
    return now - since <= timedelta(seconds=max_pause_s())


def timer_start(vm: Any, phase_started_at: datetime) -> datetime:
    """Where a boot-wait timer that began at `phase_started_at` effectively
    starts, given the guest's guardian wait.

    Each guardian report inside the phase restarts the clock (the guest was
    provably not failing then, only waiting), so the timer never fires
    while the wait is fresh and runs its full length from the LAST report
    once the guardian answers or the reports stop. Capped: the effective
    start never moves more than `max_pause_s()` past the phase start, so a
    forged wait delays a timer by at most that much. No credit for an M0
    VM, for a report from before the phase, or for a terminal reason."""
    at = getattr(vm, "guardian_wait_at", None)
    if (
        not has_guardian(vm)
        or at is None
        or at <= phase_started_at
        or (vm.guardian_wait_reason or "") in TERMINAL_REASONS
    ):
        return phase_started_at
    return min(at, phase_started_at + timedelta(seconds=max_pause_s()))


def view(vm: Any, now: datetime | None = None) -> dict[str, Any] | None:
    """The operator-status readout, or `None` when the VM is not waiting.
    Terminal reasons are SHOWN (the operator must see `refused:erased`) even
    though they never pause anything."""
    now = now or timezone.now()
    if not has_guardian(vm) or not _waiting_now(vm, now):
        return None
    return {
        "boot": BOOT_STATE,
        "reason": vm.guardian_wait_reason,
        "since": vm.guardian_wait_since.isoformat() if vm.guardian_wait_since else None,
        "last_report_at": vm.guardian_wait_at.isoformat(),
        "terminal": vm.guardian_wait_reason in TERMINAL_REASONS,
    }
