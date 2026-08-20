"""§25 — the miner PAID for a VM's uptime follows the VM.

The defect these pin: `VmBillingBinding` is written once, at launch, and
a §25 migration never touched it, so the meter kept crediting the SOURCE
miner for every second the DESTINATION served — forever, on a ledger that
feeds real on-chain epoch weight (`VALI_EPOCH_WEIGHT_SOURCE=usage`).

The two things that make this more than a one-line field update:

  * The receipt's own `node_id` CANNOT be the answer. The guest reads it
    from `hippius.node_id` on its SNP-measured cmdline, which §25 carries
    to the destination VERBATIM (rewriting it would change the
    measurement and the destination would never unlock). A migrated guest
    declares its LAUNCH node for the rest of its life. Equally, the
    launch binding must NOT be re-pointed at the destination: the meter
    matches receipts against it, so re-pointing it makes every
    post-migration receipt mismatch and bill nothing at all.
  * "The miner it is on right now" cannot be the answer either. A receipt
    for a PRE-cutover window can be metered AFTER the cutover (the guest
    drains its buffer during the migration shutdown; the pull broker adds
    lag). Crediting by wall-clock would retroactively move uptime the
    source genuinely served onto the destination — a new payments bug.

So custody is TIME-RANGED (`VmBillingAssignment`) and the meter resolves
it by the receipt's SERVICE WINDOW.
"""

from __future__ import annotations

import pytest

from apps.scheduler import billing, usage
from apps.scheduler.models import (
    ReceiptWatermark,
    UsageAccrual,
    VmBillingAssignment,
    VmBillingBinding,
)
from apps.telemetry.models import (
    EnvelopeKind,
    ProcessingStatus,
    SourceType,
    TelemetryEnvelope,
    TelemetrySource,
)
from apps.telemetry.verifier import ServedReceiptFields

pytestmark = pytest.mark.django_db

SOURCE = "ab" * 32
DEST = "cd" * 32

# The migration cutover, in the test's pinned unix clock.
CUTOVER = 1500
NOW = 2000


@pytest.fixture(autouse=True)
def _fresh_now(monkeypatch):
    monkeypatch.setattr(usage, "_now_unix", lambda: NOW)


@pytest.fixture(autouse=True)
def _units(monkeypatch):
    monkeypatch.setattr(usage.scoring, "resource_units", lambda rc: 100)


def _binding(node_id_hex: str = SOURCE) -> VmBillingBinding:
    """The launch binding — the identity the GUEST declares. Immutable."""
    return VmBillingBinding.objects.create(
        vm_id="vm-1",
        node_id_hex=node_id_hex,
        resource_class="small",
        lease_id="lease-1",
    )


def _history(*rows: tuple[str, int, str]) -> None:
    for node_id_hex, at_unix, reason in rows:
        VmBillingAssignment.objects.create(
            vm_id="vm-1",
            node_id_hex=node_id_hex,
            effective_from_unix=at_unix,
            reason=reason,
        )


def _fields(*, period_start: int, period_end: int, seq: int = 1) -> ServedReceiptFields:
    # `node_id_hex` is ALWAYS the launch node: that is what a migrated
    # guest keeps declaring (measured cmdline, carried verbatim).
    return ServedReceiptFields(
        vm_id="vm-1",
        lease_id="lease-1",
        node_id_hex=SOURCE,
        epoch=5,
        resource_class="small",
        period_start=period_start,
        period_end=period_end,
        monotonic_seq=seq,
        observed_degradation_bps=0,
    )


def _drain(monkeypatch, fields: ServedReceiptFields) -> usage.AccrualReport:
    TelemetrySource.objects.get_or_create(
        source=SourceType.TENANT_VM.value,
        source_id="vm-1",
        defaults={"verifying_key": bytes(32)},
    )
    TelemetryEnvelope.objects.create(
        source=SourceType.TENANT_VM.value,
        source_id="vm-1",
        kind=EnvelopeKind.SERVED_RECEIPT.value,
        schema_version=1,
        payload_cbor=b"\x01",
        signature=b"\x02" * 64,
        processing_status=ProcessingStatus.PENDING.value,
        dedupe_digest=f"digest-{fields.monotonic_seq}-{fields.period_end}",
    )
    monkeypatch.setattr(
        usage.verifier,
        "verify_served_receipt",
        lambda *, body, sig, verifying_key: fields,
    )
    return usage.accrue_usage_once()


# ─── the fix: post-cutover uptime is the DESTINATION's ───────────────


def test_post_cutover_uptime_is_credited_to_the_destination(monkeypatch) -> None:
    # THE BUG. The guest still declares the SOURCE node (measured
    # cmdline), and today's meter keyed the ledger off exactly that.
    _binding()
    _history((SOURCE, 1000, "launch"), (DEST, CUTOVER, "migration"))

    report = _drain(monkeypatch, _fields(period_start=1600, period_end=1660))

    assert report.accrued == 1
    accrual = UsageAccrual.objects.get()
    assert accrual.miner_node_id == DEST
    assert accrual.billable_seconds == 60


def test_the_receipt_still_has_to_match_the_launch_binding(monkeypatch) -> None:
    # The anti-inflation gate is NOT relaxed by any of this: a receipt
    # declaring a node vali never provisioned is still rejected outright,
    # whatever the custody history says.
    _binding()
    _history((SOURCE, 1000, "launch"), (DEST, CUTOVER, "migration"))
    forged = ServedReceiptFields(
        vm_id="vm-1",
        lease_id="lease-1",
        node_id_hex="ee" * 32,
        epoch=5,
        resource_class="small",
        period_start=1600,
        period_end=1660,
        monotonic_seq=1,
        observed_degradation_bps=0,
    )

    report = _drain(monkeypatch, forged)

    assert report.accrued == 0
    assert not UsageAccrual.objects.exists()


# ─── the accrual boundary: the past is NOT re-attributed ─────────────


def test_pre_cutover_uptime_metered_after_the_cutover_stays_with_the_source(
    monkeypatch,
) -> None:
    # The source's final drained receipts land while the migration is
    # already Done. Their WINDOW is what decides, not the wall-clock at
    # which the meter happens to see them — otherwise fixing the future
    # would silently re-credit the past.
    _binding()
    _history((SOURCE, 1000, "launch"), (DEST, CUTOVER, "migration"))

    report = _drain(monkeypatch, _fields(period_start=1400, period_end=1460))

    assert report.accrued == 1
    accrual = UsageAccrual.objects.get()
    assert accrual.miner_node_id == SOURCE


def test_already_accrued_seconds_are_never_moved(monkeypatch) -> None:
    # Source-served seconds accrued BEFORE the migration keep their own
    # ledger row; the destination gets a NEW row. Nothing is rewritten.
    _binding()
    _history((SOURCE, 1000, "launch"))
    _drain(monkeypatch, _fields(period_start=1100, period_end=1160, seq=1))
    assert UsageAccrual.objects.get(miner_node_id=SOURCE).billable_seconds == 60

    _history((DEST, CUTOVER, "migration"))
    _drain(monkeypatch, _fields(period_start=1600, period_end=1660, seq=2))

    assert UsageAccrual.objects.get(miner_node_id=SOURCE).billable_seconds == 60
    assert UsageAccrual.objects.get(miner_node_id=DEST).billable_seconds == 60


# ─── fail-closed, never fail-absent ──────────────────────────────────


def test_a_vm_with_no_custody_history_still_bills_its_launch_miner(
    monkeypatch,
) -> None:
    # A VM launched before the history existed (or a window predating its
    # first row) keeps the pre-history behaviour EXACTLY — the launch
    # binding's node. Introducing the history re-attributes nothing, and
    # there is no window in which a running VM stops accruing.
    _binding()

    report = _drain(monkeypatch, _fields(period_start=1600, period_end=1660))

    assert report.accrued == 1
    assert UsageAccrual.objects.get().miner_node_id == SOURCE


def test_unattributable_custody_credits_nobody(monkeypatch) -> None:
    # The workload moved to a host vali cannot name. Paying the previous
    # miner would be paying for work it provably is not doing.
    _binding()
    _history((SOURCE, 1000, "launch"), ("", CUTOVER, "migration"))

    report = _drain(monkeypatch, _fields(period_start=1600, period_end=1660, seq=9))

    assert report.accrued == 0
    assert not UsageAccrual.objects.exists()
    # The sequence is consumed — an unattributable window is judged, not
    # left to be re-judged forever.
    assert ReceiptWatermark.objects.get().last_monotonic_seq == 9


# ─── the history itself ──────────────────────────────────────────────


def test_record_assignment_is_a_noop_when_the_miner_has_not_changed() -> None:
    # Reboot-recovery re-runs the whole launch path on the SAME host. The
    # custody history must record moves that HAPPENED — a spurious row
    # per reboot would make it useless as evidence of who was paid.
    billing.record_assignment(
        vm_id="vm-1", node_id_hex=SOURCE, at_unix=1000, reason="launch"
    )
    again = billing.record_assignment(
        vm_id="vm-1", node_id_hex=SOURCE, at_unix=1200, reason="launch"
    )

    assert again is None
    assert VmBillingAssignment.objects.filter(vm_id="vm-1").count() == 1
    assert VmBillingAssignment.objects.get().effective_from_unix == 1000


def test_record_assignment_appends_on_a_real_move_and_can_move_back() -> None:
    billing.record_assignment(
        vm_id="vm-1", node_id_hex=SOURCE, at_unix=1000, reason="launch"
    )
    billing.record_assignment(
        vm_id="vm-1", node_id_hex=DEST, at_unix=1500, reason="migration"
    )
    billing.record_assignment(
        vm_id="vm-1", node_id_hex=SOURCE, at_unix=2500, reason="migration"
    )

    assert VmBillingAssignment.objects.filter(vm_id="vm-1").count() == 3
    assert billing.credited_node_id(
        vm_id="vm-1", at_unix=1200, fallback_node_id_hex=""
    ) == SOURCE
    assert billing.credited_node_id(
        vm_id="vm-1", at_unix=1600, fallback_node_id_hex=""
    ) == DEST
    assert billing.credited_node_id(
        vm_id="vm-1", at_unix=9999, fallback_node_id_hex=""
    ) == SOURCE


def test_credited_node_id_resolves_the_row_in_force_at_the_instant() -> None:
    _history((SOURCE, 1000, "launch"), (DEST, CUTOVER, "migration"))

    # Exactly AT the cutover the destination is already in force
    # (half-open ranges), and one second before it is not.
    assert billing.credited_node_id(
        vm_id="vm-1", at_unix=CUTOVER, fallback_node_id_hex="x"
    ) == DEST
    assert billing.credited_node_id(
        vm_id="vm-1", at_unix=CUTOVER - 1, fallback_node_id_hex="x"
    ) == SOURCE
    # Before ANY row: the caller's fallback (the launch binding).
    assert billing.credited_node_id(
        vm_id="vm-1", at_unix=999, fallback_node_id_hex="x"
    ) == "x"
    # Another VM's history never leaks in.
    assert billing.credited_node_id(
        vm_id="vm-2", at_unix=CUTOVER, fallback_node_id_hex="x"
    ) == "x"
