"""Observed SEV-SNP **start capability** per miner — the §23 placement
input that models whether a host can actually boot a confidential guest.

Spec of record: ARCHITECTURE.md §23 (scheduler) / §25 (migration).

## The gap this closes

Every pre-existing admission input models a *quantity*: CPU, RAM, slots,
epoch freshness, stake, price. Not one of them models the *binary*
precondition underneath all of them — **can this host start a CVM at
all?** A host whose SEV-SNP state machine has wedged (the AMD-PSP
`DF_FLUSH` failing, so `sev_common_kvm_init` returns `EBUSY` for every
new guest) has all its CPU and all its RAM free, heart-beats normally,
and passes the #668 fit gate with room to spare. The scheduler happily
picks it, and the failure surfaces only after a launch — or, far worse,
after a §25 migration has already quiesced and fenced the SOURCE, at
which point the VM is down and recovery is forward-only.

This module is the missing measurement. It is deliberately an
**observation ledger**, not a health check: vali records what it WATCHED
happen when it last asked a host to start a confidential guest, and the
placement decision reads that back.

## Where the evidence comes from — and why not a self-report

The miner is untrusted, so the direction of a claim decides whether it
can be believed:

- A miner asserting **"I am capable"** must buy nothing. It would win
  placements it then fails, which is exactly the defect this module
  exists to remove. So no positive claim from a miner is ever accepted:
  `PROVEN` is written **only** from an outcome vali itself observed.
- A miner asserting **"I am NOT capable"** is safe to believe — it can
  only cost the claimant its own work. Today's evidence is exactly of
  that shape without needing a new wire field: a host that cannot start
  a guest **rejects the launch order vali sent it**, and that rejection
  is the self-declared incapacity, delivered over the existing
  Edge-signed order channel and attributable to nobody else.

The two write paths are therefore both *vali-side terminal outcomes of a
dispatch vali itself decided*:

1. `launch.launch_on_miner` — the miner returned `2xx`/non-`2xx` to the
   `/v1/miner/order/launch` order. That route awaits the dispatch task,
   so a `2xx` means `handle_launch` actually created and started the
   domain; a non-`2xx` after the KBS register means the host refused to.
2. `orchestration.service._h_mig_dest_activating` — the §25 destination's
   own `migration/{vm}/status` reached `done` / `failed`.

**Cross-miner forgery is impossible by construction:** both writers key
the row on the node id from *vali's own* decision (`decide_placement`'s
return value / `MigrationJob.dest_node_id` bridged through the
operator-curated, DB-unique `MinerIdentity.chain_node_id`). No field of
any miner's response ever names the node a record is written against, so
a miner has no channel through which to mark a RIVAL incapable. The
`reason` string is a closed vali-side vocabulary for the same reason —
no miner-controlled bytes are persisted.

## Why "a CVM is running here" is NOT evidence of capability

Tempting sources — a live `HostAttestor` beacon, a `domain-state` poll
returning `running: true`, `vm_count_running` in the heartbeat — all
answer "is a confidential guest running on this host?", which is a
DIFFERENT question from "can this host start one?". Only an observed
*start* counts here.

## What ONE failure means — the measured base rate

`sev_common_kvm_init: failed ret=-16` (EBUSY) is **intermittent and
self-recovering**, not a permanent per-host wedge. Measured on the live
fleet at the time of writing:

- host A: 105 CVM start attempts over 22 days, **one** such failure;
- host B: **three** such failures in ~5 days — and it started a CVM
  successfully between each, unaided.

(The `kvm_amd: SEV-SNP: DF_FLUSH failed` line that accompanies it is
logged a minute AFTER the QEMU EBUSY: it is a consequence of the failed
start, not its cause.)

Two design consequences follow directly, and they are the reason this
module counts rather than latches:

1. **A single failure must never hard-exclude a host.** Under that rule
   host B would have been pulled out of the fleet three times in five
   days for a condition it recovered from by itself. One failure buys a
   *decaying soft* penalty (`DEGRADED`) and nothing more.
2. **The expensive part is not the failure, it is giving up on it.** A
   §25 migration quiesces and fences the SOURCE before it ever asks the
   destination to boot, so a transient EBUSY there costs the tenant its
   VM. `_h_mig_dest_activating` therefore RETRIES the activation
   (bounded, backed off) before failing — a retry is the correct
   response to an intermittent fault, and the observation ledger is what
   tells us it was not intermittent.

## Which observed failures are evidence about the HOST

A dispatch rejection is not automatically a statement about SEV. The
miner-agent answers the launch order with an HTTP status plus a static
class (`orders/handler.rs::reject_dispatch`), and those classes split
cleanly:

- `dispatch-failed` is the catch-all that carries `libvirt-driver/create`
  — `virsh start` refused the domain. THAT is the shape a wedged SEV-SNP
  subsystem produces, and it is what the live fleet logged next to
  `sev_common_kvm_init: ret=-16`. It counts.
- `launch-input` (422) says the ORDER was unprocessable — a bad digest or
  bad launch inputs. It is a statement about this VM, not this host.
- `insufficient-resources` (503) says the host is FULL. That is capacity,
  which #668's fit gate already models; a full host is not an incapable
  one.
- `insufficient-disk` (507) — and any class naming `insufficient-space`
  — says the host has no room for the VM's DATA disk. Capacity again,
  modelled by vali's disk gate; charged to the host's earned DISK ceiling
  (`capacity_earn.DISK_INSUFFICIENT`), never to its SEV record. Legacy
  agents answered a disk-full LAUNCH as a generic `dispatch-failed` (the
  `data-disk/insufficient-space` detail was only logged on the host), so
  those remain indistinguishable from a real start failure and still
  count — there is no honest way to excuse them.
- `vsock-cid-exhausted` (503) is CID allocation — the same-miner dispatch
  retry exists precisely for it, and it says nothing about SEV.
- `ticket-delivery-failed` (500) fires only AFTER the domain reached
  `Running`: the host demonstrably DID start a confidential guest. (It is
  not recorded as a success either — the class is a miner-supplied
  string, and no positive claim from a miner is ever accepted.)
- the order-auth family (`bad-signature`, `order-stale`, `order-wrong-
  miner`, …) never reaches the SEV subsystem at all, and is usually a
  vali-side minting fault that EVERY miner would reject identically —
  counting it could empty the whole fleet through a HARD gate.

[`is_start_capability_failure`] encodes exactly that, as a DENY-list:
anything not on it counts. The direction is deliberate. An allow-list
would mean that renaming or adding a miner-side class silently switches
the gate off — the vacuous-checker failure this repository keeps
re-learning — whereas an unforeseen class under a deny-list merely counts
once too often, which is soft, self-clearing and visible.

## The four-valued verdict, and where the unknown default sits

`classify` maps the ledger to one of:

- `PROVEN`    — vali observed a CVM start succeed here inside
                `VALI_SCHEDULER_CVM_PROOF_TTL_S`. Ranked UP (a bonus
                term in the composite score), never a hard requirement.
- `DEGRADED`  — a recent observed start failure, not yet enough of them
                to conclude anything. **Soft**: de-prioritised with a
                fallback to the full set, exactly like the existing
                launch circuit-breaker. This is where a lone transient
                EBUSY lands, and it decays on its own. It is ALSO where a
                host that was `INCAPABLE` lands once the hard window
                elapses — see the probation section below.
- `INCAPABLE` — `VALI_SCHEDULER_CVM_FAIL_THRESHOLD` (default **3**)
                CONSECUTIVE observed start failures with **no observed
                success in between**, each within
                `VALI_SCHEDULER_CVM_FAIL_WINDOW_S` (default **1 h**) of
                the one before. Only this is HARD-excluded, and only for
                as long as the last failure stays inside that window.
- `UNKNOWN`   — everything else.

Why 3-consecutive-within-an-hour: against the measured base rate above,
isolated failures are followed by a success on the very next attempt, so
a streak cannot form — host B never exceeds 1. Three back-to-back with
nothing succeeding in between is a qualitatively different signal, and
the hour bound keeps it a statement about NOW: failures from yesterday
cannot accumulate into today's verdict (the streak is restarted at write
time when the previous failure has aged out, so "3 failures over 3
months" never becomes an exclusion).

The unknown default is **eligible but unproven**: neither excluded nor
assumed capable.

- Excluding it would empty the fleet on a fresh deploy, and would be
  self-sealing besides — capability is only provable by *being placed*,
  so a never-placed miner could never earn its way out. That is the same
  cold-start trap `placement.decide_placement` documents for reward
  merit.
- Assuming it capable is the status-quo bug, and this module refuses to
  encode it *positively*: an unknown host carries no `PROVEN` bonus, so
  it always ranks below an otherwise-equal host that has demonstrably
  started a guest recently. Absence of evidence is scored as absence of
  evidence, not as evidence.

## Earning the way back — PROBATION, not a pardon on the clock

The first version of this module relaxed a hard exclusion purely on
time: once the last failure aged past `fail_window_s`, the host went
straight back to `UNKNOWN`, i.e. to FULL eligibility with no penalty and
no evidence whatsoever that it had recovered. On 2026-08-13 that cost a
second tenant launch, and the trace is unambiguous:

```
12:00:02  synmon-cs10-…  → miner-c   3 dispatches, all rejected
12:01:20  ledger: streak=3  ⇒ INCAPABLE          ← the gate worked
13:51:10  stamp-fed-1    → miner-c   ← 1 h 50 m later: streak aged out,
                                       verdict UNKNOWN, and an idle host
                                       has the FREEST capacity, so it
                                       ranked FIRST again
13:52:09  ledger: streak=3  ⇒ INCAPABLE          ← re-learned, one
                                                   burned launch later
```

Two miners were `PROVEN` at that moment. Nothing needed miner-c, and
nothing had observed it recover — the clock alone re-admitted it.

So the hard exclusion now relaxes in TWO stages instead of one:

1. inside `fail_window_s` of the last failure → `INCAPABLE` (hard, no
   fallback), unchanged;
2. after that, and until `VALI_SCHEDULER_CVM_PROBATION_S` (default
   **24 h**) has passed since that failure → `DEGRADED`, i.e. the SOFT
   last-resort de-rate. The host is chosen only when nothing better
   exists;
3. after the probation window → `UNKNOWN`, full re-admission.

An observed SUCCESS still clears everything instantly at any point, and
that is the fast path back: probation is not a sentence to serve, it is
the absence of evidence. A host on probation that IS chosen (because it
was the only capacity) and starts a guest is `PROVEN` on the spot.

Symmetric with the proof TTL on purpose: an observed success is proof
for 24 h, so an observed streak of failures is doubt for 24 h. Neither
number claims more than the observation behind it.

**One failure during probation re-arms the hard exclusion immediately**
(`_write`). The probation placement is a PROBE: the host has already
shown a streak and has not succeeded since, so a further failure needs
no second confirmation. Without this the streak would restart at 1 — the
"isolated failures spread over weeks never accumulate" rule, applied to
the one case where the failures are demonstrably not isolated.

Everything decays; nothing latches:

- `PROVEN` decays to `UNKNOWN` after the proof TTL. "The last CVM we saw
  start here booted three weeks ago" is not a claim about today.
- `DEGRADED` relaxes once the last failure ages past the window (or, for
  a host that reached the threshold, past the probation window) — a
  half-open circuit breaker, so a host that recovered (with or without a
  reboot, which vali cannot observe either way) is never stranded.
- A *newer* observed success clears BOTH immediately and zeroes the
  streak: the ledger keeps timestamps and a counter, not a sticky flag,
  so recovery needs no operator action.

`VALI_SCHEDULER_CVM_FAIL_THRESHOLD = 0` disarms the hard exclusion
fleet-wide — and with it the probation, which is defined off the same
threshold — leaving only the soft `DEGRADED` de-rate. The operator dial,
with no code change and no dev-only bypass.

## Where an operator SEES it

`GET /v1/scheduler/capacity` reports each dispatchable miner's
`cvm_capability`, and reports `free_slots: 0` for an `INCAPABLE` one, so
a host being skipped for this reason is visible BEFORE a launch instead
of surfacing as an unexplained `no-eligible-miner`. `decide_placement`'s
`no-eligible-miner` message additionally names how many candidates this
gate removed.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta
from typing import Any

from django.conf import settings
from django.utils import timezone

log = logging.getLogger("apps.scheduler.cvm_capability")

# The four verdicts. Plain strings (not an enum) so the value crosses
# into the pure `decide_placement` as ordinary data, exactly like every
# other input that function takes.
PROVEN = "proven"
UNKNOWN = "unknown"
DEGRADED = "degraded"
INCAPABLE = "incapable"

# Closed vali-side vocabulary for `cvm_last_fail_reason`. NEVER a
# miner-supplied string — see the module docstring.
REASON_LAUNCH_REJECTED = "launch-order-rejected"
REASON_DEST_ACTIVATION_FAILED = "dest-activation-failed"

# Cap matching the model field, so a future reason string can never
# raise a DataError inside a launch.
_MAX_REASON = 64

# Miner-returned rejection classes that are NOT evidence about this
# host's ability to START a confidential guest. Mirrors
# `binaries/miner-agent/src/orders/handler.rs::reject_dispatch` and the
# order-auth rejections in `orders/mod.rs`; see the module docstring for
# why each one is here, and why this is a DENY-list rather than an
# allow-list of the single class that does count (`dispatch-failed`).
#
# These strings are matched, never persisted: `cvm_last_fail_reason`
# stays this module's own closed vocabulary, so no miner-controlled bytes
# reach vali's audit trail.
CLASSES_NOT_START_CAPABILITY = frozenset(
    {
        # ── the dispatch reached the lifecycle, but not the SEV start ──
        "launch-input",  # 422 — bad order/digest: the VM's fault
        "insufficient-resources",  # 503 — the host is FULL (capacity, #668)
        # (507 `insufficient-disk` and every `*insufficient-space*` class —
        # no room for the DATA disk — are excused by `is_disk_refusal`.)
        "vsock-cid-exhausted",  # 503 — CID allocation; the retry clears it
        "ticket-delivery-failed",  # 500 — domain ALREADY reached Running
        "not-yet-wired",  # 501 — miner-agent build skew
        "relaunch-disks-missing",  # 412 — this host lacks the VM's disks
        "relaunch-disks-unreadable",  # 503 — could not stat them (retryable)
        "net-policy-not-loaded",  # 503 — edge-mode guest rules not loaded yet
        # ── the order never reached the lifecycle at all ──────────────
        # Usually a vali-side minting/clock fault every miner would
        # reject identically — counting it could empty the fleet through
        # a gate that has no fallback.
        "signed-order-decode",
        "order-body-decode",
        "order-body-bytes",
        "order-domain",
        "order-kind-mismatch",
        "order-id-invalid",
        "order-wrong-miner",
        "order-stale",
        "order-in-flight",
        "bad-signature",
        "malformed-sig",
        "bad-vm-id",
    }
)


#: Substring that marks a DISK refusal whatever the exact class a miner
#: build names it (`data-disk/insufficient-space`, `…/insufficient-space`).
DISK_REFUSAL_MARKER = "insufficient-space"


def is_disk_refusal(classifier: str) -> bool:
    """Is a miner rejection class a DATA-disk capacity refusal — the 507
    `insufficient-disk`, or any class containing `insufficient-space`?

    Miner-controlled, like every class: it can only move a failure from
    the host's SEV record to its (earned) disk ceiling — a cut to its OWN
    capacity — never mark a rival."""
    c = (classifier or "").strip().lower()[:_MAX_REASON]
    return c == "insufficient-disk" or DISK_REFUSAL_MARKER in c


def is_start_capability_failure(classifier: str) -> bool:
    """Is a non-2xx dispatch rejection evidence that this HOST cannot
    start a confidential guest?

    `True` for `dispatch-failed` — the class the miner-agent returns when
    `virsh start` refused the domain (`libvirt-driver/create`), which is
    what a wedged SEV-SNP subsystem produces — and for anything else not
    explicitly excused in [`CLASSES_NOT_START_CAPABILITY`].

    `False` for the excused classes: a bad order, a full host, a CID
    collision, a ticket push that failed AFTER the domain reached
    `Running`, or an order that never got past authentication. None of
    those is a statement about SEV, and this signal HARD-excludes a host,
    so it must only be written from evidence that is.

    `classifier` is miner-controlled. It is used for a set membership
    test and nothing else — it is never persisted, never logged as a
    reason, and it can only ever REMOVE a penalty from the host that sent
    it. It can never mark a rival, and it can never buy `PROVEN`
    (`record_start_ok` is written from a 2xx, not from a string).
    """
    if is_disk_refusal(classifier):
        return False
    return (classifier or "").strip().lower()[:_MAX_REASON] not in (
        CLASSES_NOT_START_CAPABILITY
    )


# §25 dest-activation failure classes (`migration/<class>` on the dest's
# status route) that end the attempt BEFORE any CVM start: the restore never
# reached a boot, so its failure says nothing about SEV. Same direction as
# `CLASSES_NOT_START_CAPABILITY` — a deny-list of excuses; anything else,
# including no class at all (an agent predating the field), still counts.
DEST_ACTIVATION_CLASSES_NOT_START_CAPABILITY = frozenset(
    {
        "migration/dest-settle-by-passed",  # vali's deadline left no room
        "migration/dest-artifacts-missing",  # boot artifacts absent
        "migration/state-disk-size",  # the source's state disk is malformed
        "migration/activate-on-source",  # this host is the VM's source
        # A same-host restore's staged-swap refusals — the staged overlay is
        # gone, staging was never `Staged`, a swap-in-progress marker
        # conflicts, or the staged/live artifacts don't match what was
        # recorded at stage time. All of these are decided by `swap_in`
        # BEFORE any domain start is attempted (see `service._h_mig_dest_
        # activating`'s `_TERMINAL_RESTORE_ACTIVATION_CLASSES`, which treats
        # the same classes as a terminal, no-retry refusal for the same
        # reason): the tenant's own staging state, not this host's SEV
        # capability.
        "migration/restore-staged-missing",
        "migration/restore-not-staged",
        "migration/staged-restore-conflict",
        "migration/restore-size-mismatch",
        "migration/restore-swap-conflict",
    }
)
DEST_ACTIVATION_PREFIXES_NOT_START_CAPABILITY = (
    "migration/snapshot-",  # snapshot download / verification / its budget
    "migration/download-",  # a presigned GET failed
    "migration/dest-artifact-",  # artifact staging (sha mismatch, budget, …)
    "migration/chain-",  # a backup-chain restore was refused
    "backup/",  # the backup-chain restore itself failed
)


def is_dest_activation_start_failure(failure_class: str) -> bool:
    """Is a `failed` §25 dest activation evidence that this HOST cannot
    start a confidential guest?

    `False` only for the excused classes above — a restore that failed
    before any boot. `True` for everything else, `""` included, so an agent
    that reports no class keeps today's behaviour. Like
    `is_start_capability_failure`, the class is miner-controlled and can
    only remove a penalty from the host that reported it.
    """
    c = (failure_class or "").strip().lower()[:_MAX_REASON]
    if c in DEST_ACTIVATION_CLASSES_NOT_START_CAPABILITY or is_disk_refusal(c):
        # A dest with no room for the restore (`…/insufficient-space`)
        # never reached a boot either.
        return False
    return not c.startswith(DEST_ACTIVATION_PREFIXES_NOT_START_CAPABILITY)


def fail_window_s() -> int:
    """The window that governs BOTH halves of the failure signal:

    - how long an observed failure keeps a host `DEGRADED` (soft), and
    - how close together consecutive failures must land to accumulate
      into a streak at all.

    Default 3600s. One hour is a statement about NOW — long enough to
    cover the retry cadence of a launch or a §25 activation (minutes
    apart), short enough that yesterday's transient cannot contribute to
    today's verdict.
    """
    return int(getattr(settings, "VALI_SCHEDULER_CVM_FAIL_WINDOW_S", 3600))


def fail_threshold() -> int:
    """How many CONSECUTIVE in-window observed start failures (with no
    observed success in between) it takes to HARD-exclude a host.

    Default 3. The measured fleet base rate is isolated failures each
    followed by a success on the next attempt, so a streak of 3 cannot
    form from the intermittent EBUSY this module was written for — see
    the module docstring. `0` disarms the hard exclusion entirely,
    leaving only the soft `DEGRADED` de-rate.
    """
    return int(getattr(settings, "VALI_SCHEDULER_CVM_FAIL_THRESHOLD", 3))


def proof_ttl_s() -> int:
    """How long an observed CVM-start SUCCESS counts as proof of
    capability before decaying back to `UNKNOWN`. Default 86400s."""
    return int(getattr(settings, "VALI_SCHEDULER_CVM_PROOF_TTL_S", 86400))


def probation_s() -> int:
    """How long a host that reached `fail_threshold()` stays PENALISED
    after its hard-exclusion window elapses — measured from its last
    observed failure, and SOFT for that whole tail (`DEGRADED`: chosen
    only when nothing better exists).

    Default 86400s, symmetric with [`proof_ttl_s`]: an observed success
    is proof for a day, an observed streak of failures is doubt for a
    day. Cleared instantly by any observed success.

    Values `<= fail_window_s()` make this a no-op (the hard window
    already covers it) — that, or a `fail_threshold()` of 0, is how an
    operator turns probation off without a code change.
    """
    return int(getattr(settings, "VALI_SCHEDULER_CVM_PROBATION_S", 86400))


def classify(
    *,
    last_ok_at: datetime | None,
    last_fail_at: datetime | None,
    fail_streak: int,
    now: datetime,
    fail_window_s: int,
    fail_threshold: int,
    proof_ttl_s: int,
    probation_s: int,
) -> str:
    """The four-valued capability verdict for one host. **Pure** — no
    I/O, no clock (`now` is an argument), so the whole policy is
    testable as a table.

    Precedence, in order:

    1. The MOST RECENT observation wins. A failure newer than the last
       success means the host has regressed since it last proved itself,
       whatever it managed to do before that. (A success also zeroes
       `fail_streak` at write time, so the two agree.)
    2. A failure inside `fail_window_s`: `INCAPABLE` once the streak
       reaches `fail_threshold`, else `DEGRADED`.
    3. A failure OLDER than the window, on a host whose streak DID reach
       the threshold, still inside `probation_s`: `DEGRADED`. This is
       the half-open probation — the hard exclusion relaxes to a soft
       last-resort preference rather than to a full pardon, because the
       clock is not evidence of recovery. An isolated failure (streak
       below the threshold) skips this entirely and ages out as before.
    4. Otherwise a fresh-enough success ⇒ `PROVEN`; a stale one decays
       to `UNKNOWN`.
    5. No evidence at all ⇒ `UNKNOWN`.

    `probation_s` is keyword-only and has NO default, deliberately: a
    caller that has not thought about it must fail loudly rather than
    silently get the permissive behaviour that burned a tenant launch.

    `fail_streak` is maintained at WRITE time (`record_start_failure`),
    which is what keeps it honest: a failure arriving more than
    `fail_window_s` after the previous one RESTARTS the streak at 1, so
    isolated failures spread over weeks can never accumulate into an
    exclusion — except while the host is on probation, where a failure
    EXTENDS the streak instead (see `_write`).
    """
    regressed = last_fail_at is not None and (
        last_ok_at is None or last_fail_at > last_ok_at
    )
    if regressed and now - last_fail_at < timedelta(seconds=fail_window_s):
        if fail_threshold > 0 and fail_streak >= fail_threshold:
            return INCAPABLE
        return DEGRADED
    # Half-open probation: the hard window has elapsed, but this host
    # reached the threshold and has NOT been observed to start anything
    # since. Soft — it is chosen when it is the only capacity, and one
    # observed success (which zeroes the streak) ends this immediately.
    if (
        regressed
        and fail_threshold > 0
        and fail_streak >= fail_threshold
        and now - last_fail_at < timedelta(seconds=probation_s)
    ):
        return DEGRADED
    if last_ok_at is not None and now - last_ok_at <= timedelta(seconds=proof_ttl_s):
        return PROVEN
    return UNKNOWN


def _classify_row(
    row: Any, at: datetime, window: int, thresh: int, ttl: int, prob: int
) -> str:
    return classify(
        last_ok_at=row.cvm_last_ok_at,
        last_fail_at=row.cvm_last_fail_at,
        fail_streak=row.cvm_fail_streak or 0,
        now=at,
        fail_window_s=window,
        fail_threshold=thresh,
        proof_ttl_s=ttl,
        probation_s=prob,
    )


def capability_of_row(row: Any, *, now: datetime | None = None) -> str:
    """The verdict for ONE already-loaded `MinerCapacity` row — for a
    caller that holds the mirror rows (the operator fleet readout) and
    must not re-query them. Same policy as [`capability_by_node`]."""
    return _classify_row(
        row, now or timezone.now(), fail_window_s(), fail_threshold(), proof_ttl_s(), probation_s()
    )


def capability_by_node(*, now: datetime | None = None) -> dict[str, str]:
    """`{chain_node_id: verdict}` over the whole `MinerCapacity` mirror —
    the input `decide_placement` takes as `cvm_capability_by_node`.

    A node absent from the map (no mirror row yet) is treated by
    `decide_placement` exactly like an explicit `UNKNOWN`, so the two
    "we have no evidence" cases can never diverge.
    """
    from .models import MinerCapacity

    at = now or timezone.now()
    window, thresh, ttl = fail_window_s(), fail_threshold(), proof_ttl_s()
    prob = probation_s()
    return {
        row.miner_node_id: _classify_row(row, at, window, thresh, ttl, prob)
        for row in MinerCapacity.objects.all().only(
            "miner_node_id",
            "cvm_last_ok_at",
            "cvm_last_fail_at",
            "cvm_fail_streak",
        )
    }


def capability_of(miner_node_id: str, *, now: datetime | None = None) -> str:
    """The verdict for ONE node — the single-host read the §25 intake
    gate uses. An unknown / unmirrored node is `UNKNOWN` (fail-safe:
    absence of evidence never blocks)."""
    from .models import MinerCapacity

    if not miner_node_id:
        return UNKNOWN
    row = (
        MinerCapacity.objects.filter(miner_node_id=miner_node_id)
        .only("cvm_last_ok_at", "cvm_last_fail_at", "cvm_fail_streak")
        .first()
    )
    if row is None:
        return UNKNOWN
    return _classify_row(
        row,
        now or timezone.now(),
        fail_window_s(),
        fail_threshold(),
        proof_ttl_s(),
        probation_s(),
    )


def record_start_ok(miner_node_id: str) -> None:
    """Record that vali OBSERVED a confidential guest start successfully
    on `miner_node_id` (a 64-hex chain node id). Zeroes the failure
    streak — a host that just booted a guest is not mid-streak, whatever
    happened before.

    `miner_node_id` MUST come from vali's own decision — the placement
    the scheduler chose, or the destination the operator named — never
    from anything a miner said. See the module docstring.

    Fail-open by construction: this is bookkeeping on the side of a
    successful launch/migration and must never be able to turn one into
    a failure. A missing mirror row is a no-op (a node with no
    `MinerCapacity` is already ineligible — `decide_placement` fails
    closed on `capacity is None` — so there is nothing to record
    against).
    """
    _write(miner_node_id, ok=True, reason="")


def record_start_failure(miner_node_id: str, *, reason: str) -> None:
    """Record that vali OBSERVED a confidential-guest start FAIL on
    `miner_node_id`, advancing its consecutive-failure streak.

    One call de-rates the host softly (`DEGRADED`); only
    `fail_threshold()` of them in a row, each within `fail_window_s()` of
    the last, hard-excludes it. A failure that lands after the window has
    elapsed RESTARTS the streak at 1 rather than extending a stale one.

    `reason` must be one of this module's closed constants: it is
    persisted, and persisting miner-controlled bytes would hand an
    untrusted host a write primitive into vali's own audit trail.
    """
    _write(miner_node_id, ok=False, reason=reason)


def _write(miner_node_id: str, *, ok: bool, reason: str) -> None:
    if not miner_node_id:
        return
    from django.db import transaction

    from .models import MinerCapacity

    now = timezone.now()
    fields: dict[str, Any] = {}
    try:
        with transaction.atomic():
            # Row-locked read-modify-write: the streak is a counter, so two
            # concurrent observations must not lose an increment (a lost
            # update would silently keep a genuinely stuck host eligible).
            row = (
                MinerCapacity.objects.select_for_update()
                .filter(miner_node_id=miner_node_id)
                .only(
                    "cvm_last_fail_at",
                    "cvm_fail_streak",
                    "cvm_fail_streak_started_at",
                )
                .first()
            )
            if row is None:
                log.info(
                    "cvm-capability: no MinerCapacity mirror row for node=%s — "
                    "start-%s observation not recorded",
                    miner_node_id,
                    "ok" if ok else "failure",
                )
                return
            if ok:
                fields = {
                    "cvm_last_ok_at": now,
                    "cvm_fail_streak": 0,
                    "cvm_fail_streak_started_at": None,
                }
            else:
                prev = row.cvm_last_fail_at
                prev_streak = row.cvm_fail_streak or 0
                # Extend the streak only if the PREVIOUS failure is still
                # inside the window; otherwise this is a fresh, isolated
                # fault and starts its own streak at 1. This is what stops
                # rare intermittent EBUSYs, spread over days, from ever
                # summing into a hard exclusion.
                extends = (
                    prev is not None
                    and prev_streak > 0
                    and now - prev <= timedelta(seconds=fail_window_s())
                )
                # ...with ONE exception: a host on PROBATION (it already
                # reached the threshold and has not been observed to start
                # anything since) that fails again re-arms the hard
                # exclusion immediately instead of restarting at 1. The
                # probation placement is a single-shot PROBE — these
                # failures are demonstrably not isolated, which is the
                # only thing the restart rule exists to protect.
                thresh = fail_threshold()
                if (
                    not extends
                    and prev is not None
                    and thresh > 0
                    and prev_streak >= thresh
                    and now - prev < timedelta(seconds=probation_s())
                ):
                    extends = True
                streak = (row.cvm_fail_streak or 0) + 1 if extends else 1
                fields = {
                    "cvm_last_fail_at": now,
                    "cvm_last_fail_reason": reason[:_MAX_REASON],
                    "cvm_fail_streak": streak,
                    "cvm_fail_streak_started_at": (
                        row.cvm_fail_streak_started_at if extends else now
                    ),
                }
            MinerCapacity.objects.filter(pk=row.pk).update(**fields)
    except Exception as exc:  # noqa: BLE001 — bookkeeping is never load-bearing
        log.warning(
            "cvm-capability: failed to record %s for node=%s: %s",
            "ok" if ok else "failure",
            miner_node_id,
            exc,
        )
        return
    if not ok and fields:
        log.warning(
            "cvm-capability: node=%s failed to start a confidential guest "
            "(%s) — consecutive in-window failures now %d (hard-excluded at %d)",
            miner_node_id,
            reason,
            fields["cvm_fail_streak"],
            fail_threshold(),
        )

