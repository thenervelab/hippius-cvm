"""Uptime usage metering — accrue billable resource-seconds from the
tenant guest's attested served-delivery receipts.

We pay a miner only for VM time that is genuinely UP. The authoritative,
miner-unforgeable "this VM was up and serving during [t0,t1]" signal is
the guest-Ed25519-signed `ServedDeliveryReceipt` (`hippius-types`), which
the tenant guest emits periodically and the untrusted miner relays
opaquely. A down VM emits no receipts ⇒ accrues nothing ⇒ isn't paid —
fail-closed by construction.

[`accrue_usage_once`] is one cycle of the `vali_usage_meter` worker: drain
verified `served_receipt` telemetry envelopes (the §9 pull broker),
re-run the DATA-BEARING `verify-served-receipt` to get the attested
fields, dedup by the per-`(vm,lease)` `monotonic_seq` watermark, and
accrue `resource_units × billable_seconds × (1 − degradation)` into the
`(epoch, miner, vm)` [`UsageAccrual`] ledger. `compute_epoch_weights`
reads that ledger (uptime-integrated); owed = `unit_seconds × MinerPrice`.

The guest's `monotonic_seq` is monotonic only WITHIN ONE BOOT, so the
dedup watermark re-baselines when the guest restarts its sequence — see
[`_is_sequence_restart`] for the restart signature and why it hands an
adversary no billable second. The `last_period_end` clamp, which is what
actually bounds the money, is never re-baselined.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from django.conf import settings
from django.db import transaction

from apps.telemetry import service as telemetry
from apps.telemetry import verifier
from apps.telemetry.models import (
    EnvelopeKind,
    ProcessingStatus,
    TelemetryEnvelope,
    TelemetrySource,
)
from apps.telemetry.verifier import (
    ServedReceiptFields,
    VerifierFailed,
    VerifierUnavailable,
)

from . import billing, scoring
from .models import ReceiptWatermark, UsageAccrual, VmBillingBinding

log = logging.getLogger("apps.scheduler.usage")

# Basis-point full scale for the honest-degradation discount.
_BPS_FULL = 10_000

# `_accrue_one` outcomes. Three, not two: the armed liveness gate can
# legitimately say "not yet judgeable" for a receipt whose covering live
# attestation is still in flight, and that must re-queue the envelope
# rather than burn the receipt's sequence on a premature verdict.
_ACCRUED = "accrued"
_SKIPPED = "skipped"
_REQUEUE = "requeue"


@dataclass(frozen=True)
class AccrualReport:
    """Outcome of one [`accrue_usage_once`] cycle — for logging + tests."""

    drained: int
    accrued: int
    skipped: int
    requeued: int


def _batch_limit() -> int:
    return int(getattr(settings, "VALI_USAGE_METER_BATCH", 500))


def _max_period_seconds() -> int:
    """Clamp a single receipt's billable window — a hostile/buggy guest
    can't inflate one receipt into a giant interval (the signer's
    `canonical()` already bounds `period_end ≥ period_start`; this bounds
    the magnitude)."""
    return int(getattr(settings, "VALI_USAGE_METER_MAX_PERIOD_S", 3600))


def _receipt_max_lag_seconds() -> int:
    """§23 — reject a receipt whose window ended more than this long ago.
    Legit receipts arrive ~real-time (live guests observed at 5-125 s lag);
    a much older `period_end` is a backfill/stale-replay attempt (claiming
    past uptime). Generous default (1 h) tolerates a verifier-outage queue
    backlog without dropping honest billing."""
    return int(getattr(settings, "VALI_BILLING_RECEIPT_MAX_LAG_S", 3600))


def _receipt_max_skew_seconds() -> int:
    """§23 — reject a receipt whose window ends further in the FUTURE than
    this (clock-skew tolerance). Bounds pre-forging (signing far-future
    receipts in one batch); a live guest is at most a few minutes ahead."""
    return int(getattr(settings, "VALI_BILLING_RECEIPT_MAX_SKEW_S", 600))


def _require_liveness_attestation() -> bool:
    """Whether a receipt window must be COVERED by an SNP-attested
    liveness proof to be creditable (§23 uptime-liveness gate).

    Compiled default `False` — the SAFE value. See the arming sequence
    beside `VALI_UPTIME_REQUIRE_LIVENESS_ATTESTATION` in
    `vali/settings.py`: a fleet whose guests do not yet answer KBS
    keepalive challenges must keep accruing exactly as before, or
    turning this on would stop ALL reward accrual fleet-wide. The chart
    renders the value EXPLICITLY (never an absent key) so which of the
    two regimes is live is readable off the ConfigMap.
    """
    return bool(getattr(settings, "VALI_UPTIME_REQUIRE_LIVENESS_ATTESTATION", False))


def _liveness_grace_seconds() -> int:
    """How recently a receipt's window may have closed for the armed
    gate to DEFER instead of judging it.

    The covering live attestation and the receipt travel independently
    (KBS-signed vs guest-signed), so a receipt can arrive a few seconds
    before the attestation that proves its window. Judging it then would
    burn the receipt's `monotonic_seq` on a "no coverage" verdict that
    is merely early — a systematic under-count of honest uptime. Inside
    the grace we re-queue the envelope instead; outside it we judge for
    real. Must stay well under `VALI_BILLING_RECEIPT_MAX_LAG_S` (which
    ultimately drops the receipt) so a deferral cannot loop forever.
    """
    return int(getattr(settings, "VALI_UPTIME_LIVENESS_GRACE_S", 300))


def _now_unix() -> int:
    """Wall-clock unix seconds — the freshness reference. A module-level
    indirection so tests can pin it."""
    import time

    return int(time.time())


def accrue_usage_once() -> AccrualReport:
    """Drain a batch of verified served-receipt envelopes and accrue
    their attested uptime. Best-effort: a per-envelope verifier outage
    re-queues that envelope (retried next cycle); a genuinely bad receipt
    is dropped. Since the pull broker claims each envelope exactly once,
    there is no cursor to keep — `since=0` returns only still-`Pending`
    rows.
    """
    result = telemetry.pull(
        kind=EnvelopeKind.SERVED_RECEIPT.value, since=0, limit=_batch_limit()
    )
    drained = len(result.envelopes)
    if not drained:
        return AccrualReport(drained=0, accrued=0, skipped=0, requeued=0)

    # §23 — accrue to the CURRENT billing epoch (read once per cycle),
    # NOT the epoch the guest baked into the receipt at launch. The guest
    # has no chain access, so its `telemetry_epoch` cmdline token is fixed
    # for the VM's whole life; trusting it would freeze a long-running VM's
    # uptime at its launch epoch (it would stop being credited once that
    # epoch closes). Stamping ingest-time keeps a live VM billed every
    # epoch. Receipts arrive ~real-time, so the current epoch matches the
    # receipt's service window. `0` (no cached chain epoch) ⇒ fall back to
    # the receipt's own epoch so a cold cache never drops billing.
    accrual_epoch = _current_epoch()
    accrued = skipped = requeued = 0
    for env in result.envelopes:
        vk = _source_vk(env)
        if vk is None:
            # Source vanished from the registry — shouldn't happen after a
            # verified ingest; drop (leave Done) rather than loop.
            log.warning("usage-meter: no source key for envelope=%s", env.envelope_id)
            skipped += 1
            continue
        try:
            fields = verifier.verify_served_receipt(
                body=bytes(env.payload_cbor),
                sig=bytes(env.signature),
                verifying_key=vk,
            )
        except VerifierFailed as exc:
            # A bad receipt (should not pass ingest) — drop it, don't retry.
            log.warning("usage-meter: bad receipt envelope=%s: %s", env.envelope_id, exc)
            skipped += 1
            continue
        except VerifierUnavailable as exc:
            # Binary/config outage — re-queue for a later cycle so the
            # receipt is not lost (billing must not silently under-count).
            log.error(
                "usage-meter: verifier unavailable envelope=%s: %s — requeue",
                env.envelope_id,
                exc,
            )
            _requeue(env)
            requeued += 1
            continue

        outcome = _accrue_one(fields, accrual_epoch, env.source_id)
        if outcome == _ACCRUED:
            accrued += 1
        elif outcome == _REQUEUE:
            # Armed liveness gate, receipt too fresh to judge — its
            # covering live attestation may still be in flight. Put the
            # envelope back rather than burn its sequence on a verdict
            # we would only reach by guessing. Bounded: once the receipt
            # ages past the grace it is judged for real (and, past
            # `_receipt_max_lag_seconds`, dropped as stale).
            _requeue(env)
            requeued += 1
        else:
            skipped += 1

    log.info(
        "usage-meter cycle: drained=%d accrued=%d skipped=%d requeued=%d",
        drained,
        accrued,
        skipped,
        requeued,
    )
    return AccrualReport(
        drained=drained, accrued=accrued, skipped=skipped, requeued=requeued
    )


def _source_vk(env: TelemetryEnvelope) -> bytes | None:
    src = TelemetrySource.objects.filter(
        source=env.source, source_id=env.source_id
    ).first()
    return bytes(src.verifying_key) if src is not None else None


def _requeue(env: TelemetryEnvelope) -> None:
    """Un-claim an envelope the pull broker marked Done so a later cycle
    retries it (only for transient verifier outages, never a bad receipt)."""
    TelemetryEnvelope.objects.filter(envelope_id=env.envelope_id).update(
        processing_status=ProcessingStatus.PENDING.value,
        pull_token="",
        processed_at=None,
    )


def _current_epoch() -> int:
    """The current billing epoch from the DB-cached on-chain
    `CurrentEpoch` (`MinerCapacity.observed_epoch`) — no network call in
    the meter loop; the scheduler refreshes it every chain read. `0` when
    the cache is empty (fresh cluster) ⇒ the caller falls back to the
    receipt's own epoch.
    """
    from django.db.models import Max

    from .models import MinerCapacity

    epoch = MinerCapacity.objects.aggregate(m=Max("observed_epoch"))["m"]
    return int(epoch or 0)


def _liveness_covered_seconds(
    fields: ServedReceiptFields,
    binding: VmBillingBinding,
    *,
    effective_start: int,
    now: int,
) -> int | None:
    """Seconds of `[effective_start, period_end]` proven ALIVE by an
    SNP-attested liveness sample — or `None` for "not yet judgeable".

    `None` (defer) is returned only when the window is NOT fully covered
    AND the receipt is younger than `_liveness_grace_seconds()`: the
    KBS-signed live attestation that covers it travels on its own path
    and can legitimately land a few seconds after the receipt. Judging
    then would burn the receipt's sequence on a verdict that is merely
    early. Past the grace, the answer is final — including `0`.

    The look-back is floored at the VM's binding-creation instant so a
    VM's very FIRST sample cannot credit coverage from before the VM
    existed.
    """
    from apps.telemetry import vm_liveness

    floor = int(binding.created_at.timestamp())
    covered = vm_liveness.covered_seconds(
        vm_id=fields.vm_id,
        start_unix=effective_start,
        end_unix=fields.period_end,
        floor_unix=floor,
    )
    if covered >= fields.period_end - effective_start:
        return covered
    if fields.period_end > now - _liveness_grace_seconds():
        return None
    return covered


def _is_sequence_restart(
    fields: ServedReceiptFields, wm: ReceiptWatermark
) -> bool:
    """Whether a receipt whose `monotonic_seq` does NOT exceed the
    watermark is a legitimate guest SEQUENCE RESTART (re-baseline the
    watermark) rather than a replay (drop it).

    ## Why a restart happens at all

    `monotonic_seq` is monotonic only within one boot. The guest holds it
    in RAM (`agent-tenant-telemetry`'s `ReceiptBuilder`; `FIRST_SEQ = 1`),
    so it restarts at 1 on a tenant `reboot`, on a reboot-recovery
    relaunch after a host reboot, and at a §25 migration's destination.
    An only-ever-advancing watermark then dropped every receipt until the
    fresh sequence climbed back past the pre-reboot value — from seq 600
    at a 60 s cadence, ~10 hours of attested-but-unpaid uptime, silently
    (receipts keep arriving, the VM looks healthy). Observed live.

    ## The restart signature, and why it is not an inflation primitive

    The restart is recognised by the receipt's WINDOW, not by its
    sequence: `period_start >= last_period_end` — the window opens at or
    after the billing frontier, so it can re-bill ZERO already-billed
    seconds. That is exactly what a restarted builder emits (its genesis
    `period_start` is the agent's start instant, which is necessarily at
    or after the last window it managed to close before it died), and it
    is exactly what a replay is NOT.

    The guest telemetry key is extractable by root inside the CVM (see
    `VmBillingBinding`), so the adversary — a miner running its own
    fake-tenant VM, or a hostile tenant — can sign any receipt body it
    likes. It gains nothing here:

    - A REPLAY of an already-billed receipt has
      `period_start < last_period_end` (it was billed, so the frontier
      moved past its start). It does not match, and is dropped exactly as
      before. Replaying a low sequence therefore cannot INDUCE a reset.
    - A receipt that DOES match bills `period_end - period_start` fresh
      seconds — precisely what the same window would have billed had it
      carried a higher sequence. The re-baseline hands out no seconds
      that the `last_period_end` clamp would not already have allowed.
    - After the re-baseline the guard is exactly as tight: the frontier
      has advanced to this receipt's `period_end` (never rewound — this
      function may not touch `last_period_end`) and the next receipt must
      still clear both gates.

    Consequently `Σ billable_seconds` over any interleaving of honest,
    replayed and restart receipts stays bounded by the wall-clock span
    the frontier moved through, restarts included.

    `last_monotonic_seq == 0` (a watermark that has never consumed a
    sequence) is never treated as a restart — there is nothing to
    re-baseline, and that keeps the fresh-row path byte-identical to its
    pre-existing behaviour.
    """
    if wm.last_monotonic_seq <= 0:
        return False
    return fields.period_start >= wm.last_period_end


def _accrue_one(
    fields: ServedReceiptFields, accrual_epoch: int, source_id: str
) -> str:
    """Accrue one attested receipt into the ledger.

    Returns [`_ACCRUED`], [`_SKIPPED`] (a forged/unbound receipt, a
    stale sequence already billed, a non-positive window, an unknown
    flavour, a window whose custody is unattributable, or — once the
    liveness gate is armed — a window with no SNP-attested coverage), or
    [`_REQUEUE`] (armed gate, receipt too
    fresh to judge; retry next cycle).

    `source_id` is the telemetry source the receipt was VERIFIED under
    (`env.source_id`) — the identity that owns the signing key.
    `accrual_epoch` is the CURRENT billing epoch stamped at ingest time
    (see [`accrue_usage_once`]); `0` falls back to the receipt's baked
    `fields.epoch` so a cold chain-epoch cache never drops billing."""
    # §23 — bind the signed receipt to the telemetry SOURCE whose key
    # verified it. The guest telemetry key is provisioned per-VM at launch
    # (`TelemetrySource.source_id == vm_id`), so a receipt whose signed
    # `vm_id` differs from the source it was verified under is a forgery:
    # a miner running its own CVM (root inside) extracts THAT VM's key and
    # signs receipts naming another — or an unbound — vm_id to credit
    # fabricated uptime to its node. The key authenticates exactly one
    # vm_id; reject any cross-VM claim.
    if fields.vm_id != source_id:
        log.warning(
            "usage-meter: receipt vm_id=%s != telemetry source_id=%s — "
            "rejecting (forged cross-VM receipt)",
            fields.vm_id,
            source_id,
        )
        return _SKIPPED
    # §23 — reject a receipt whose self-declared identity/tier does not
    # match what vali provisioned at launch. The guest telemetry key is
    # extractable by root inside the CVM (the tenant, or a miner running
    # its own fake-tenant VM), so the guest-signed payload cannot be
    # trusted for WHAT is billed — a forger could inflate `resource_class`
    # (more units) or claim a different `node_id` / `lease_id`. The launch
    # `VmBillingBinding` is authoritative for WHAT may be billed — it is
    # the DECLARED identity baked into the SNP-measured cmdline, so it is
    # stable for the VM's whole life, §25 migrations included (WHO is PAID
    # is the separate, time-ranged `VmBillingAssignment` resolved below,
    # and the two must not be conflated: re-pointing THIS row at a
    # migration destination would make every post-migration receipt fail
    # the match below and bill nothing at all).
    # We FAIL CLOSED when it is
    # absent: without a binding we cannot authenticate the self-declared
    # node/resource_class/lease, so an unbound vm_id (which a forger could
    # inflate at will) is dropped rather than trusted. Every VM launched
    # through `launch.py` gets a binding (`_persist_billing_binding`); a
    # missing one is a pre-binding legacy VM or a forged vm_id — neither
    # bills.
    binding = VmBillingBinding.objects.filter(vm_id=fields.vm_id).first()
    if binding is None:
        log.warning(
            "usage-meter: no launch billing binding for vm=%s — rejecting "
            "(cannot authenticate node/resource_class/lease)",
            fields.vm_id,
        )
        return _SKIPPED
    if (
        fields.node_id_hex != binding.node_id_hex
        or fields.resource_class != binding.resource_class
        or fields.lease_id != binding.lease_id
    ):
        log.warning(
            "usage-meter: receipt fields do not match the launch binding for "
            "vm=%s — rejecting (possible forged/inflated receipt)",
            fields.vm_id,
        )
        return _SKIPPED

    # §23 — freshness: a receipt must be reported ~real-time. Reject a
    # window ending too far in the future (pre-forged batch) or too far in
    # the past (backfill / stale replay claiming historical uptime). Live
    # guests are observed a few seconds behind wall-clock; the bounds are
    # generous (skew 10 min / lag 1 h) so honest billing is never dropped.
    now = _now_unix()
    if fields.period_end > now + _receipt_max_skew_seconds():
        log.warning(
            "usage-meter: future-dated receipt vm=%s (period_end=%d > now+skew) "
            "— rejecting (pre-forge)",
            fields.vm_id,
            fields.period_end,
        )
        return _SKIPPED
    if fields.period_end < now - _receipt_max_lag_seconds():
        log.warning(
            "usage-meter: stale receipt vm=%s (period_end=%d < now-maxlag) "
            "— rejecting (backfill/replay)",
            fields.vm_id,
            fields.period_end,
        )
        return _SKIPPED

    if fields.period_end <= fields.period_start:
        return _SKIPPED

    units = scoring.resource_units(fields.resource_class)
    if units <= 0:
        # Unknown flavour ⇒ no priced units ⇒ nothing to bill.
        return _SKIPPED

    with transaction.atomic():
        # Dedup + continuity: bill a receipt only if its per-(vm,lease)
        # monotonic_seq exceeds the watermark (or the guest RESTARTED its
        # sequence — see `_is_sequence_restart`), AND bill only the part of
        # its window ending AFTER the last already-billed `period_end`. The
        # seq gate stops same-seq replay; the period clamp stops TIME-OVERLAP
        # inflation — a forger submitting increasing-seq receipts with
        # overlapping windows to double-bill the same seconds (the seq gate
        # alone does not catch that; honest guests emit contiguous windows).
        # The period clamp is the guard that bounds the MONEY, and it only
        # ever advances; the seq watermark is ordering/dedup and is the only
        # one a restart re-baselines.
        wm, _ = ReceiptWatermark.objects.select_for_update().get_or_create(
            vm_id=fields.vm_id,
            lease_id=fields.lease_id,
            defaults={"last_monotonic_seq": 0, "last_period_end": 0},
        )
        restarted = False
        previous_seq = wm.last_monotonic_seq
        if fields.monotonic_seq <= wm.last_monotonic_seq:
            if not _is_sequence_restart(fields, wm):
                return _SKIPPED
            restarted = True
        # Consume the sequence (a higher seq strictly advances it) even if
        # the window is fully overlapping and bills nothing. On a restart
        # this RE-BASELINES to the guest's fresh, lower sequence.
        wm.last_monotonic_seq = fields.monotonic_seq
        seq_fields = ["last_monotonic_seq", "updated_at"]
        if restarted:
            # A money-path event: record it so it is never silent, and so
            # a restart count far above a VM's real reboot count is
            # visible to an operator.
            wm.seq_restarts += 1
            wm.last_restart_at_unix = now
            seq_fields += ["seq_restarts", "last_restart_at_unix"]
            log.warning(
                "usage-meter: vm=%s lease=%s guest sequence RESTARTED "
                "(seq %d -> %d, window opens at %d >= billed frontier %d) "
                "— re-baselining the receipt watermark (restart #%d)",
                fields.vm_id,
                fields.lease_id,
                previous_seq,
                fields.monotonic_seq,
                fields.period_start,
                wm.last_period_end,
                wm.seq_restarts,
            )

        effective_start = max(fields.period_start, wm.last_period_end)
        billable = fields.period_end - effective_start
        if billable <= 0:
            # Wholly inside an already-billed window — no new seconds.
            wm.save(update_fields=seq_fields)
            return _SKIPPED
        billable = min(billable, _max_period_seconds())

        # §25 — WHO gets paid for these seconds, resolved from the
        # append-only custody history by the receipt's SERVICE WINDOW.
        #
        # NOT `fields.node_id_hex`: the guest reads that off its
        # SNP-measured cmdline, and a §25 migration carries the cmdline to
        # the destination VERBATIM (rewriting it would change the
        # measurement and the dest would never unlock). A migrated guest
        # therefore declares its LAUNCH node forever — so crediting the
        # self-declared value pays the SOURCE for work the DESTINATION is
        # doing, for the rest of the VM's life.
        #
        # NOT "the miner the VM is on right now" either: a receipt for a
        # PRE-cutover window can be metered AFTER the cutover (the guest
        # drains its buffered receipts during the migration shutdown, and
        # the pull broker adds its own lag), and crediting that by
        # wall-clock would retroactively move already-served uptime to a
        # miner that did not serve it. `effective_start` — the first
        # second this receipt actually bills — is on exactly one side of
        # the cutover, and `_activate_dest_vm` places the cutover in the
        # dead zone between the source's verified stop and the dest's
        # boot, so no receipt window can straddle it.
        credited_node = billing.credited_node_id(
            vm_id=fields.vm_id,
            at_unix=effective_start,
            fallback_node_id_hex=binding.node_id_hex,
        )
        if not credited_node:
            # UNATTRIBUTABLE custody (see `VmBillingAssignment`): the
            # workload moved to a host vali cannot name. Fail closed in
            # the MONEY direction — burn the sequence, credit nobody.
            # Paying the previous miner would be paying for work it is
            # provably not doing.
            log.error(
                "usage-meter: vm=%s has no attributable miner at %d — "
                "crediting NOBODY for [%d,%d]",
                fields.vm_id,
                effective_start,
                effective_start,
                fields.period_end,
            )
            wm.save(update_fields=seq_fields)
            return _SKIPPED

        # §23 UPTIME-LIVENESS GATE (armed by
        # `VALI_UPTIME_REQUIRE_LIVENESS_ATTESTATION`; default OFF).
        #
        # Everything above authenticates WHAT is billed. Nothing above
        # proves the VM still EXISTS: the receipt is signed by the guest
        # telemetry key, which root inside the CVM can extract, so a
        # miner who launches a VM on its own node, lifts the key, and
        # then KILLS the VM can keep signing well-formed receipts
        # forever. Possession of the key IS the signature.
        #
        # Once armed we bill only the part of the window covered by an
        # SNP-attested liveness sample — a KBS-L0-signed
        # `LiveAttestation` minted from a fresh `SNP_GET_REPORT` whose
        # REPORT_DATA bound a single-use KBS nonce to this vm_id. That
        # cannot be produced by an extracted key, and a dead VM cannot
        # produce it at all. Uncovered time accrues NOTHING.
        if _require_liveness_attestation():
            covered = _liveness_covered_seconds(
                fields, binding, effective_start=effective_start, now=now
            )
            if covered is None:
                # Too fresh to judge — the covering attestation may still
                # be in flight. Defer WITHOUT consuming the sequence.
                return _REQUEUE
            if covered <= 0:
                log.warning(
                    "usage-meter: no SNP-attested liveness covers vm=%s "
                    "[%d,%d] — crediting ZERO (uptime-liveness gate armed)",
                    fields.vm_id,
                    effective_start,
                    fields.period_end,
                )
                wm.save(update_fields=seq_fields)
                return _SKIPPED
            billable = min(billable, covered)

        deg = min(max(fields.observed_degradation_bps, 0), _BPS_FULL)
        unit_seconds = units * billable * (_BPS_FULL - deg) // _BPS_FULL

        wm.last_period_end = max(wm.last_period_end, fields.period_end)
        wm.save(update_fields=[*seq_fields, "last_period_end"])

        accrual, _ = UsageAccrual.objects.select_for_update().get_or_create(
            epoch=accrual_epoch or fields.epoch,
            miner_node_id=credited_node,
            vm_id=fields.vm_id,
            defaults={
                "resource_class": fields.resource_class,
                "lease_id": fields.lease_id,
            },
        )
        accrual.unit_seconds += unit_seconds
        accrual.billable_seconds += billable
        accrual.save(update_fields=["unit_seconds", "billable_seconds", "updated_at"])
    return _ACCRUED
