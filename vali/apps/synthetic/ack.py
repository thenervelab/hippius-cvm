"""Expiring, per-check acknowledgement of a KNOWN-AND-ACCEPTED light-tier failure.

WHY THIS EXISTS
───────────────
`SyntheticLightFailing` (`hippius_synthetic_light_success == 0`) fired
continuously from 2026-08-10 for a single accepted condition: the testnet
runtime dropped `pallet-compute-scoring`, so `check_epoch_close_advancing`
correctly reports a FOSSIL and correctly returns FAIL — and restoring the
pallet is upstream chain work with no date.

A tier gauge pinned at 0 for days is not a signal. A NEW light-tier failure
(ghost dispatchable node, stuck jobs, unapplied migration) becomes
indistinguishable from the standing one — which is the SAME defect, inverted,
that this monitor was built to fix: before #898 the epoch check said OK forever
and a frozen chain went unnoticed for a week; now it says FAIL forever and
everything else is drowned.

So the verdict is not the problem — its route to an operator is. This module
lets an operator declare "yes, THIS named check, for THIS stated reason, until
THIS date" and keeps that check out of the tier roll-up ONLY under those terms.

THE OBVIOUS RISK, AND HOW THIS FAILS
────────────────────────────────────
Any mute is one forgotten config line away from being a permanent blind spot.
This repo has shipped that shape more than once (a gate declared, then silently
not enforced). Every rule below is chosen so that the FAILURE MODE OF THE
ACKNOWLEDGEMENT ITSELF is "the tier goes red / an alert fires", never "the tier
stays green":

1. Expiry is MANDATORY and BOUNDED (`MAX_ACK_DAYS`). An ack cannot last
   forever; when it lapses the check re-enters the roll-up and
   `SyntheticLightFailing` fires again. Forgetting is self-correcting.
   REJECTED: a boolean `ack_epoch_close: true` — it is exactly the forgotten
   line that becomes permanent. REJECTED: clamping an over-long expiry down to
   the horizon — silent correction teaches nobody; an over-long date is
   REFUSED so the author sees it.
2. The ack names ONE check EXACTLY, and the name is validated against the
   checks that actually ran. REJECTED: globs / regex / a `severity: warning`
   downgrade class / an "ack everything currently failing" switch — all of
   those silently absorb the NEXT, different failure. An unknown name is an
   ERROR (surfaced), not a no-op.
3. A hard cap (`MAX_ACTIVE_ACKS`) on how many entries may exist at all, and
   exceeding it VOIDS THE WHOLE SPEC rather than applying a prefix. The cap is
   a module constant on purpose: a configurable cap is itself the blanket mute.
4. A reason is MANDATORY and must be substantive (`MIN_REASON_CHARS`), because
   the reason is what the next operator reads at 3 a.m.
5. An acked check is still RUN, still reported, still logged at WARNING, and
   still publishes its true `hippius_synthetic_light_check_success{check=...}
   == 0`. Nothing vanishes; only the TIER roll-up is affected.
6. An ack whose check has since PASSED is reported STALE and alerted on, so a
   resolved condition cannot sit silently acknowledged.
7. A malformed entry NEVER silently applies. It is counted into
   `hippius_synthetic_ack_invalid` (alerted) and its check keeps failing the
   tier — the safe direction.

The acknowledged condition must still be alarmed on its OWN terms: the fossil
keeps a dedicated `ChainScoringPalletFossil` alert off
`hippius_synthetic_chain_pallet_live` (see the PrometheusRule). Acknowledging
is about routing, never about deleting the signal.

SPEC FORMAT (`VALI_SYNTHETIC_ACK`, newline-separated, `#` comments allowed):

    epoch_close | 2026-09-10 | testnet runtime dropped pallet-compute-scoring;
    restore is upstream chain work with no date

Three `|`-separated fields: check name, expiry date `YYYY-MM-DD` (UTC), reason
(may itself contain `|`). The ack expires AT 00:00 UTC on that date.
"""

from __future__ import annotations

import datetime as dt
from collections.abc import Sequence
from dataclasses import dataclass, field

from apps.synthetic.checks import CheckResult

# ── Non-negotiable bounds (module constants, NOT settings) ───────────────
# Making any of these configurable would re-open the blanket-mute hole the
# design closes: an operator who can set `MAX_ACK_DAYS=3650` or
# `MAX_ACTIVE_ACKS=99` has a permanent silencer again. Changing them requires
# a code change + review, which is the point.

# Longest an acknowledgement may run before it must be re-decided.
MAX_ACK_DAYS = 30
# Most entries a spec may contain — exceeding it voids the ENTIRE spec.
MAX_ACTIVE_ACKS = 3
# A reason shorter than this is not a reason.
MIN_REASON_CHARS = 24

_DATE_FMT = "%Y-%m-%d"


@dataclass(frozen=True)
class Ack:
    """One parsed, structurally-valid acknowledgement entry."""

    check: str
    expires_at: dt.datetime  # tz-aware UTC, 00:00 of the `until` date
    reason: str

    def active_at(self, now: dt.datetime) -> bool:
        return now < self.expires_at

    def expires_ts(self) -> float:
        return self.expires_at.timestamp()


@dataclass
class AckSpec:
    """The parse result: structurally-valid entries + rejected lines."""

    entries: list[Ack] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def void(self) -> bool:
        """True ⇒ NOTHING in this spec applies (cap blown)."""
        return len(self.entries) > MAX_ACTIVE_ACKS


@dataclass
class AckOutcome:
    """The applied result for one light-tier run."""

    # 1 if every check that is NOT validly acknowledged passed.
    effective_success: bool
    # Every structurally-valid entry (applied or not). The metric emitter
    # publishes an expiry timestamp for each, so an operator is warned
    # BEFORE a lapse turns the tier red.
    entries: list[Ack] = field(default_factory=list)
    # check name → the ack that suppressed its contribution to the roll-up.
    applied: dict[str, Ack] = field(default_factory=dict)
    # Acks whose check PASSED this run — the condition is resolved and the
    # ack is dead config that must be removed (alerted, never silent).
    stale: dict[str, Ack] = field(default_factory=dict)
    # Structurally-valid acks that did NOT apply, with why (expired,
    # unknown check, voided spec). Their checks keep failing the tier.
    inert: dict[str, tuple[Ack, str]] = field(default_factory=dict)
    # Rejected lines + spec-level refusals (cap blown), human-readable.
    errors: list[str] = field(default_factory=list)


def parse(raw: str, *, now: dt.datetime | None = None) -> AckSpec:
    """Parse the `VALI_SYNTHETIC_ACK` spec. Never raises.

    A line that cannot be parsed becomes an ERROR and is dropped — it does
    not acknowledge anything. That is deliberate: a typo must leave the
    check failing (noticed), never accidentally mute a different one.

    `now` is needed at PARSE time for the `MAX_ACK_DAYS` horizon: an expiry
    further out than the horizon is refused outright, so `until=2099-01-01`
    can never become the forever-mute this design exists to prevent.
    """
    now = now or dt.datetime.now(tz=dt.UTC)
    horizon = now + dt.timedelta(days=MAX_ACK_DAYS)
    spec = AckSpec()
    seen: set[str] = set()
    for lineno, line in enumerate(str(raw or "").splitlines(), start=1):
        text = line.strip()
        if not text or text.startswith("#"):
            continue
        parts = text.split("|", 2)
        if len(parts) != 3:
            spec.errors.append(
                f"line {lineno}: expected `check | YYYY-MM-DD | reason`, got {text!r}"
            )
            continue
        name, until, reason = (parts[0].strip(), parts[1].strip(), parts[2].strip())
        if not name:
            spec.errors.append(f"line {lineno}: empty check name")
            continue
        # Wildcards can never match a real check name, but refuse them
        # explicitly so the author gets told WHY instead of a silent no-op.
        if any(ch in name for ch in "*?[]"):
            spec.errors.append(
                f"line {lineno}: wildcard check name {name!r} refused — "
                "an acknowledgement must name exactly one check"
            )
            continue
        if name in seen:
            spec.errors.append(f"line {lineno}: duplicate acknowledgement for {name!r}")
            continue
        try:
            day = dt.datetime.strptime(until, _DATE_FMT).replace(tzinfo=dt.UTC)
        except ValueError:
            spec.errors.append(
                f"line {lineno}: check {name!r} — expiry {until!r} is not a "
                "`YYYY-MM-DD` date; an acknowledgement without a valid expiry "
                "is refused (it would never be re-decided)"
            )
            continue
        if day > horizon:
            spec.errors.append(
                f"line {lineno}: check {name!r} — expiry {until} is more than "
                f"{MAX_ACK_DAYS} days out; refused. An acknowledgement is a "
                "deferral, not a decision: re-state it when it lapses."
            )
            continue
        if len(reason) < MIN_REASON_CHARS:
            spec.errors.append(
                f"line {lineno}: check {name!r} — reason must be at least "
                f"{MIN_REASON_CHARS} chars (got {len(reason)}); the reason is "
                "what the next operator reads before trusting this mute"
            )
            continue
        seen.add(name)
        spec.entries.append(Ack(check=name, expires_at=day, reason=reason))
    if spec.void:
        spec.errors.append(
            f"{len(spec.entries)} acknowledgements exceed the hard cap of "
            f"{MAX_ACTIVE_ACKS} — the ENTIRE spec is void (no check is "
            "acknowledged). A growing ack list is a blanket mute; fix the "
            "fleet or raise the cap in code review."
        )
    return spec


def resolve(
    raw: str,
    results: Sequence[CheckResult],
    *,
    now: dt.datetime,
) -> AckOutcome:
    """Apply the spec to one run's results.

    `effective_success` is the tier roll-up: True iff every check that is
    NOT validly acknowledged passed. An acknowledged FAILING check is
    excluded from the roll-up and from nothing else.
    """
    spec = parse(raw, now=now)
    outcome = AckOutcome(
        effective_success=False,
        entries=list(spec.entries),
        errors=list(spec.errors),
    )
    by_name = {r.name: r for r in results}
    voided = spec.void

    for ack in spec.entries:
        if voided:
            outcome.inert[ack.check] = (ack, "spec void (ack cap exceeded)")
            continue
        if ack.check not in by_name:
            # Drift guard: an ack for a check that no longer runs (renamed,
            # removed, or simply mistyped) is dead config. Surfaced as an
            # error so it is fixed, and it mutes nothing in the meantime.
            outcome.errors.append(
                f"acknowledgement names unknown check {ack.check!r} — "
                f"known checks: {sorted(by_name)}"
            )
            outcome.inert[ack.check] = (ack, "unknown check")
            continue
        if not ack.active_at(now):
            outcome.inert[ack.check] = (ack, f"EXPIRED at {ack.expires_at.date()}")
            continue
        if by_name[ack.check].ok:
            # The condition resolved. Do NOT keep it quietly acknowledged —
            # a stale ack is a pre-armed blind spot for the next, different
            # failure of the same check.
            outcome.stale[ack.check] = ack
            continue
        outcome.applied[ack.check] = ack

    outcome.effective_success = all(r.ok or r.name in outcome.applied for r in results)
    return outcome
