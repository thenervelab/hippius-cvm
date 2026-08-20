"""Tests for the uptime usage meter (`apps.scheduler.usage`).

The Rust `verify-served-receipt` shell-out is mocked; the focus is the
accrual wiring: attested receipts → resource-seconds in the ledger,
monotonic dedup, epoch bucketing, degradation discount, and best-effort
requeue on a verifier outage.
"""

from __future__ import annotations

import pytest

from apps.scheduler import usage
from apps.scheduler.models import ReceiptWatermark, UsageAccrual
from apps.telemetry.models import (
    EnvelopeKind,
    ProcessingStatus,
    SourceType,
    TelemetryEnvelope,
    TelemetrySource,
)
from apps.telemetry.verifier import (
    ServedReceiptFields,
    VerifierFailed,
    VerifierUnavailable,
)

pytestmark = pytest.mark.django_db

NODE = "ab" * 32


@pytest.fixture(autouse=True)
def _fresh_now(monkeypatch):
    # Pin the receipt-freshness reference so the tests' small period_end
    # values (60-1060) count as "fresh" (now-max_lag is negative, now+skew
    # is 2600). Freshness-specific tests re-patch `usage._now_unix`.
    monkeypatch.setattr(usage, "_now_unix", lambda: 2000)


def _source(source_id: str = "vm-1") -> None:
    TelemetrySource.objects.get_or_create(
        source=SourceType.TENANT_VM.value,
        source_id=source_id,
        defaults={"verifying_key": bytes(32)},
    )


def _envelope(source_id: str = "vm-1", seq: int = 1) -> TelemetryEnvelope:
    _source(source_id)
    return TelemetryEnvelope.objects.create(
        source=SourceType.TENANT_VM.value,
        source_id=source_id,
        kind=EnvelopeKind.SERVED_RECEIPT.value,
        schema_version=1,
        payload_cbor=b"\x01" + bytes([seq % 256]),
        signature=b"\x02" * 64,
        processing_status=ProcessingStatus.PENDING.value,
        dedupe_digest=f"digest-{source_id}-{seq}",
    )


def _fields(
    *,
    vm_id: str = "vm-1",
    lease_id: str = "lease-1",
    epoch: int = 5,
    resource_class: str = "small",
    period_start: int = 1000,
    period_end: int = 1060,
    monotonic_seq: int = 1,
    degradation: int = 0,
) -> ServedReceiptFields:
    return ServedReceiptFields(
        vm_id=vm_id,
        lease_id=lease_id,
        node_id_hex=NODE,
        epoch=epoch,
        resource_class=resource_class,
        period_start=period_start,
        period_end=period_end,
        monotonic_seq=monotonic_seq,
        observed_degradation_bps=degradation,
    )


def _patch_verify(monkeypatch, fields_by_env=None, *, fixed=None):
    """Mock verify_served_receipt. `fixed` returns the same fields for
    every envelope; `fields_by_env` maps envelope_id → fields|exception."""

    def fake(*, body, sig, verifying_key):
        if fixed is not None:
            return fixed
        raise AssertionError("unexpected verify call")

    monkeypatch.setattr(usage.verifier, "verify_served_receipt", fake)


def _patch_units(monkeypatch, value: int = 100) -> None:
    monkeypatch.setattr(usage.scoring, "resource_units", lambda rc: value)


def test_accrues_unit_seconds_from_a_receipt(monkeypatch) -> None:
    _binding()
    _envelope()
    _patch_units(monkeypatch, 100)
    _patch_verify(monkeypatch, fixed=_fields(period_start=1000, period_end=1060))

    report = usage.accrue_usage_once()

    assert report.accrued == 1
    a = UsageAccrual.objects.get()
    assert a.epoch == 5
    assert a.miner_node_id == NODE
    assert a.vm_id == "vm-1"
    assert a.billable_seconds == 60
    assert a.unit_seconds == 100 * 60  # units × seconds, no degradation


def test_accrues_to_the_current_chain_epoch_not_the_baked_epoch(monkeypatch) -> None:
    # §23 — a long-running VM's guest bakes a FIXED `telemetry_epoch` at
    # launch (no chain access). The meter must stamp the CURRENT billing
    # epoch (DB-cached `MinerCapacity.observed_epoch`) at ingest, not the
    # stale baked one, or the VM stops being credited once its launch
    # epoch closes.
    from django.utils import timezone

    from apps.scheduler.models import MinerCapacity, MinerStatusMirror

    MinerCapacity.objects.create(
        miner_node_id=NODE,
        status=MinerStatusMirror.values[0],
        capacity_slots=1,
        observed_epoch=7,
        data_epoch=7,
        refreshed_at=timezone.now(),
    )
    _binding()
    _envelope()
    _patch_units(monkeypatch, 100)
    _patch_verify(monkeypatch, fixed=_fields(epoch=5, period_start=1000, period_end=1060))

    report = usage.accrue_usage_once()

    assert report.accrued == 1
    a = UsageAccrual.objects.get()
    # Stamped the current epoch (7), NOT the receipt's baked epoch (5).
    assert a.epoch == 7


def _binding(*, resource_class="small", node_id_hex=NODE, lease_id="lease-1") -> None:
    from apps.scheduler.models import VmBillingBinding

    VmBillingBinding.objects.create(
        vm_id="vm-1",
        node_id_hex=node_id_hex,
        resource_class=resource_class,
        lease_id=lease_id,
    )


def test_rejects_a_receipt_whose_resource_class_mismatches_the_binding(monkeypatch) -> None:
    # §23 — an in-CVM-root forger inflates resource_class in the signed
    # receipt; the launch binding (rc=small) is authoritative ⇒ reject.
    _binding(resource_class="small")
    _envelope()
    _patch_units(monkeypatch, 100)
    _patch_verify(monkeypatch, fixed=_fields(resource_class="huge"))

    report = usage.accrue_usage_once()

    assert report.accrued == 0
    assert not UsageAccrual.objects.exists()


def test_rejects_a_receipt_whose_node_id_mismatches_the_binding(monkeypatch) -> None:
    _binding(node_id_hex="cd" * 32)  # binding names a different miner
    _envelope()
    _patch_units(monkeypatch, 100)
    _patch_verify(monkeypatch, fixed=_fields())  # receipt node_id = NODE ("ab"*32)

    report = usage.accrue_usage_once()

    assert report.accrued == 0
    assert not UsageAccrual.objects.exists()


def test_accrues_when_the_receipt_matches_the_binding(monkeypatch) -> None:
    _binding(resource_class="small", node_id_hex=NODE, lease_id="lease-1")
    _envelope()
    _patch_units(monkeypatch, 100)
    _patch_verify(monkeypatch, fixed=_fields(period_start=0, period_end=60))

    report = usage.accrue_usage_once()

    assert report.accrued == 1
    assert UsageAccrual.objects.get().unit_seconds == 100 * 60


def test_rejects_a_future_dated_receipt(monkeypatch) -> None:
    # §23 — a pre-forged receipt whose window ends far in the future
    # (beyond now+skew=2600) is rejected.
    _binding()
    _envelope()
    _patch_units(monkeypatch, 100)
    _patch_verify(monkeypatch, fixed=_fields(period_start=9000, period_end=10000))

    report = usage.accrue_usage_once()

    assert report.accrued == 0
    assert not UsageAccrual.objects.exists()


def test_rejects_a_stale_receipt(monkeypatch) -> None:
    # §23 — a backfill/replay receipt whose window ended long before
    # now-max_lag is rejected. Pin now well ahead of the small periods.
    monkeypatch.setattr(usage, "_now_unix", lambda: 100_000)
    _binding()
    _envelope()
    _patch_units(monkeypatch, 100)
    _patch_verify(monkeypatch, fixed=_fields(period_start=1000, period_end=1060))

    report = usage.accrue_usage_once()

    assert report.accrued == 0
    assert not UsageAccrual.objects.exists()


def test_degradation_discounts_the_accrual(monkeypatch) -> None:
    _binding()
    _envelope()
    _patch_units(monkeypatch, 100)
    # 25% degradation ⇒ 75% credit.
    _patch_verify(
        monkeypatch,
        fixed=_fields(period_start=0, period_end=100, degradation=2500),
    )

    usage.accrue_usage_once()
    a = UsageAccrual.objects.get()
    assert a.unit_seconds == 100 * 100 * 7500 // 10000  # 75_000


def test_monotonic_seq_dedup_prevents_double_billing(monkeypatch) -> None:
    # Two envelopes for the same (vm,lease) carrying the SAME seq — only
    # the first accrues; the replay bills nothing.
    _binding()
    _envelope(seq=1)
    _patch_units(monkeypatch, 100)
    _patch_verify(monkeypatch, fixed=_fields(monotonic_seq=7))
    usage.accrue_usage_once()
    first = UsageAccrual.objects.get().unit_seconds

    _envelope(seq=2)  # a fresh envelope …
    _patch_verify(monkeypatch, fixed=_fields(monotonic_seq=7))  # … same seq
    report = usage.accrue_usage_once()
    assert report.accrued == 0
    assert UsageAccrual.objects.get().unit_seconds == first  # unchanged
    assert ReceiptWatermark.objects.get().last_monotonic_seq == 7


def test_higher_seq_accumulates_into_the_same_epoch_bucket(monkeypatch) -> None:
    _binding()
    _patch_units(monkeypatch, 10)
    _envelope(seq=1)
    _patch_verify(monkeypatch, fixed=_fields(monotonic_seq=1, period_end=1010, period_start=1000))
    usage.accrue_usage_once()
    _envelope(seq=2)
    _patch_verify(monkeypatch, fixed=_fields(monotonic_seq=2, period_end=1030, period_start=1010))
    usage.accrue_usage_once()

    a = UsageAccrual.objects.get()  # one bucket (same epoch,miner,vm)
    assert a.billable_seconds == 30  # 10 + 20
    assert a.unit_seconds == 10 * 30


def test_rejects_a_receipt_whose_vm_id_differs_from_the_source(monkeypatch) -> None:
    # RA-H1 — a miner runs its own CVM (source_id="vm-1", holds its key) and
    # signs a receipt naming ANOTHER vm_id to credit fabricated uptime. The
    # key authenticates exactly one vm_id (== the telemetry source_id), so
    # a cross-VM claim is rejected BEFORE any binding/units lookup.
    _binding()  # a valid binding exists for the OTHER vm_id …
    from apps.scheduler.models import VmBillingBinding

    # The victim's binding is a FULL match for the forged body (same
    # lease + node + flavour) on purpose: the cross-VM gate must be the
    # thing that rejects this, not an incidental binding mismatch — else
    # the test would pass with that gate deleted.
    VmBillingBinding.objects.create(
        vm_id="victim-vm", node_id_hex=NODE, resource_class="huge", lease_id="lease-1"
    )
    _envelope(source_id="vm-1")  # verified under vm-1's key
    _patch_units(monkeypatch, 100)
    # … but the signed body claims a different, richer vm_id.
    _patch_verify(monkeypatch, fixed=_fields(vm_id="victim-vm", resource_class="huge"))

    report = usage.accrue_usage_once()

    assert report.accrued == 0
    assert not UsageAccrual.objects.exists()


def test_rejects_a_receipt_for_a_vm_with_no_binding(monkeypatch) -> None:
    # RA-H1 — fail-closed: a receipt for a vm_id with no launch
    # `VmBillingBinding` cannot be authenticated (node/resource_class/lease
    # are self-declared) → dropped, never billed on the self-declared body.
    _envelope(source_id="vm-1")  # source matches, but NO binding created
    _patch_units(monkeypatch, 100)
    _patch_verify(monkeypatch, fixed=_fields(vm_id="vm-1", resource_class="huge"))

    report = usage.accrue_usage_once()

    assert report.accrued == 0
    assert not UsageAccrual.objects.exists()


def test_overlapping_window_bills_only_the_new_seconds(monkeypatch) -> None:
    # §23 — increasing-seq receipts whose windows OVERLAP must not
    # double-bill the shared seconds. seq1 [1000,1060] → 60; seq2
    # [1030,1090] overlaps [1030,1060] → only [1060,1090]=30 is new.
    _binding()
    _patch_units(monkeypatch, 10)
    _envelope(seq=1)
    _patch_verify(monkeypatch, fixed=_fields(monotonic_seq=1, period_start=1000, period_end=1060))
    usage.accrue_usage_once()
    _envelope(seq=2)
    _patch_verify(monkeypatch, fixed=_fields(monotonic_seq=2, period_start=1030, period_end=1090))
    usage.accrue_usage_once()

    a = UsageAccrual.objects.get()
    assert a.billable_seconds == 90  # 60 + 30 (not 120)
    assert a.unit_seconds == 10 * 90


def test_fully_overlapping_window_bills_nothing(monkeypatch) -> None:
    # A window wholly inside an already-billed one adds no new seconds
    # (but consumes its higher seq).
    from apps.scheduler.models import ReceiptWatermark

    _binding()
    _patch_units(monkeypatch, 10)
    _envelope(seq=1)
    _patch_verify(monkeypatch, fixed=_fields(monotonic_seq=1, period_start=1000, period_end=1060))
    usage.accrue_usage_once()
    _envelope(seq=2)
    _patch_verify(monkeypatch, fixed=_fields(monotonic_seq=2, period_start=1010, period_end=1050))
    report = usage.accrue_usage_once()

    assert report.accrued == 0
    assert UsageAccrual.objects.get().billable_seconds == 60  # unchanged
    # The higher seq was consumed (so it can't be retried).
    wm = ReceiptWatermark.objects.get(vm_id="vm-1", lease_id="lease-1")
    assert wm.last_monotonic_seq == 2
    assert wm.last_period_end == 1060


def test_different_epochs_are_separate_buckets(monkeypatch) -> None:
    _binding()
    _patch_units(monkeypatch, 10)
    _envelope(seq=1)
    # Contiguous windows (no overlap) so both accrue; different baked epochs.
    _patch_verify(
        monkeypatch,
        fixed=_fields(epoch=5, monotonic_seq=1, period_start=1000, period_end=1060),
    )
    usage.accrue_usage_once()
    _envelope(seq=2)
    _patch_verify(
        monkeypatch,
        fixed=_fields(epoch=6, monotonic_seq=2, period_start=1060, period_end=1120),
    )
    usage.accrue_usage_once()

    assert UsageAccrual.objects.count() == 2
    assert set(UsageAccrual.objects.values_list("epoch", flat=True)) == {5, 6}


def test_unknown_flavor_accrues_nothing(monkeypatch) -> None:
    _binding()
    _envelope()
    _patch_units(monkeypatch, 0)  # resource_units → 0 for an unknown flavour
    _patch_verify(monkeypatch, fixed=_fields())
    report = usage.accrue_usage_once()
    assert report.accrued == 0
    assert not UsageAccrual.objects.exists()


def test_zero_length_window_accrues_nothing(monkeypatch) -> None:
    _binding()
    _envelope()
    _patch_units(monkeypatch, 100)
    _patch_verify(monkeypatch, fixed=_fields(period_start=1000, period_end=1000))
    report = usage.accrue_usage_once()
    assert report.accrued == 0


def test_bad_receipt_is_dropped_not_requeued(monkeypatch) -> None:
    env = _envelope()
    _patch_units(monkeypatch, 100)

    def fake(*, body, sig, verifying_key):
        raise VerifierFailed(message="bad sig", category="signature")

    monkeypatch.setattr(usage.verifier, "verify_served_receipt", fake)
    report = usage.accrue_usage_once()
    assert report.skipped == 1
    env.refresh_from_db()
    assert env.processing_status == ProcessingStatus.DONE.value  # dropped, not retried


def test_verifier_outage_requeues_the_envelope(monkeypatch) -> None:
    env = _envelope()
    _patch_units(monkeypatch, 100)

    def fake(*, body, sig, verifying_key):
        raise VerifierUnavailable("binary missing")

    monkeypatch.setattr(usage.verifier, "verify_served_receipt", fake)
    report = usage.accrue_usage_once()
    assert report.requeued == 1
    env.refresh_from_db()
    # Un-claimed → Pending, so a later cycle retries (billing never lost).
    assert env.processing_status == ProcessingStatus.PENDING.value


def test_empty_queue_is_a_noop() -> None:
    report = usage.accrue_usage_once()
    assert report == usage.AccrualReport(drained=0, accrued=0, skipped=0, requeued=0)
