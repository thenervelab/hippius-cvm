"""§23 — a VM that REBOOTS must keep being billed.

The defect these pin, proven live before the fix:

    p1-liveness-1        (rebooted)      watermark frozen at seq 10354,
                                         ZERO accruals — for hours
    realtenant-ubuntu-1  (not rebooted)  watermark seq 34, billing normally

The guest's `monotonic_seq` lives in RAM inside the tenant VM
(`agent-tenant-telemetry`'s `ReceiptBuilder`, `FIRST_SEQ = 1`), so it
restarts at 1 on every boot: a tenant `reboot`, a host reboot followed by
reboot-recovery, and a §25 migration's destination boot all do it. The
meter's `ReceiptWatermark.last_monotonic_seq` only ever ADVANCED, so
every post-reboot receipt landed below the pre-reboot high-water mark and
was dropped — silently, because receipts kept arriving and the guest kept
looking healthy. From seq 600 at a 60 s cadence that is ~10 h of attested
uptime the miner served and was never paid for, and with
`VALI_EPOCH_WEIGHT_SOURCE=usage` armed it is real lost on-chain reward.

The fix re-baselines the SEQUENCE watermark on a restart. The load-bearing
question is why that is not simply a double-billing hole, and the answer
is that the sequence watermark is not what bounds the money —
`last_period_end` is. So:

  * the restart is recognised by the WINDOW (`period_start >=
    last_period_end`), never by the sequence: a receipt that can re-bill
    zero already-billed seconds;
  * `last_period_end` is NEVER re-baselined;
  * therefore a replayed old receipt — the one thing an adversary
    holding the extractable guest telemetry key can produce cheaply —
    both fails to bill AND fails to induce a re-baseline.

Each test below is written to KILL a specific mutant, named in its
docstring.
"""

from __future__ import annotations

import pytest

from apps.scheduler import usage
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

# A pinned clock. The scenarios below live in [BOOT1, NOW]; the meter's
# freshness gates (lag 1 h, skew 10 min) are satisfied throughout unless a
# test deliberately steps outside them.
NOW = 1_000_000

# Boot 1 runs [BOOT1, BOOT1 + 600] (10 receipts of 60 s, seq 1..10), the
# VM is down for 5 minutes, boot 2 starts at BOOT2 and restarts at seq 1.
BOOT1 = NOW - 1_500
DOWN_AT = BOOT1 + 600
BOOT2 = DOWN_AT + 300


@pytest.fixture(autouse=True)
def _fresh_now(monkeypatch):
    monkeypatch.setattr(usage, "_now_unix", lambda: NOW)


@pytest.fixture(autouse=True)
def _units(monkeypatch):
    monkeypatch.setattr(usage.scoring, "resource_units", lambda rc: 100)


def _binding(node_id_hex: str = SOURCE) -> VmBillingBinding:
    """The launch binding — the identity the GUEST declares. Immutable
    for the VM's life, §25 included."""
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


def _fields(
    *,
    period_start: int,
    period_end: int,
    seq: int,
    lease_id: str = "lease-1",
) -> ServedReceiptFields:
    # `node_id_hex` is ALWAYS the launch node — that is what the guest
    # reads off its SNP-measured cmdline, migration or not.
    return ServedReceiptFields(
        vm_id="vm-1",
        lease_id=lease_id,
        node_id_hex=SOURCE,
        epoch=5,
        resource_class="small",
        period_start=period_start,
        period_end=period_end,
        monotonic_seq=seq,
        observed_degradation_bps=0,
    )


_envelope_n = 0


def _drain(monkeypatch, fields: ServedReceiptFields) -> usage.AccrualReport:
    """Push one verified receipt through a full meter cycle."""
    global _envelope_n
    _envelope_n += 1
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
        dedupe_digest=f"digest-{_envelope_n}",
    )
    monkeypatch.setattr(
        usage.verifier,
        "verify_served_receipt",
        lambda *, body, sig, verifying_key: fields,
    )
    return usage.accrue_usage_once()


def _run_boot(
    monkeypatch, *, start: int, receipts: int, first_seq: int = 1, cadence: int = 60
) -> None:
    """One boot's worth of honest, contiguous receipts — exactly what
    `ReceiptBuilder` emits (chained windows, sequence from `first_seq`)."""
    t = start
    for i in range(receipts):
        _drain(
            monkeypatch,
            _fields(period_start=t, period_end=t + cadence, seq=first_seq + i),
        )
        t += cadence


def _wm() -> ReceiptWatermark:
    return ReceiptWatermark.objects.get(vm_id="vm-1", lease_id="lease-1")


def _billed() -> int:
    return sum(UsageAccrual.objects.values_list("billable_seconds", flat=True))


# ─── THE BUG: a rebooted VM stops being billed ───────────────────────


def test_a_rebooted_vm_keeps_accruing(monkeypatch) -> None:
    """MUTANT: `if fields.monotonic_seq <= wm.last_monotonic_seq: return
    _SKIPPED` with no restart branch — i.e. today's production code. A
    rebooted VM then accrues NOTHING until its sequence climbs back past
    the pre-reboot watermark.
    """
    _binding()
    _run_boot(monkeypatch, start=BOOT1, receipts=10)  # seq 1..10
    assert _wm().last_monotonic_seq == 10
    assert _billed() == 600

    # The guest reboots. Its sequence restarts at 1 and its first window
    # opens at the new agent's start instant.
    report = _drain(monkeypatch, _fields(period_start=BOOT2, period_end=BOOT2 + 60, seq=1))

    assert report.accrued == 1
    assert _billed() == 660  # 600 (boot 1) + 60 (boot 2)
    assert _wm().last_monotonic_seq == 1  # re-baselined to the guest's


def test_the_whole_second_boot_bills_not_just_the_first_receipt(monkeypatch) -> None:
    """MUTANT: re-baseline only the receipt that triggered it (e.g. do
    not persist the lowered `last_monotonic_seq`), so seq 2 of the new
    boot is dropped again and billing stays frozen after one receipt.
    """
    _binding()
    _run_boot(monkeypatch, start=BOOT1, receipts=10)
    _run_boot(monkeypatch, start=BOOT2, receipts=5)  # seq 1..5 again

    assert _billed() == 600 + 300
    assert _wm().last_monotonic_seq == 5


def test_the_downtime_is_never_billed(monkeypatch) -> None:
    """MUTANT: re-baseline by resetting `last_period_end` too (or by
    crediting `period_end - 0`), which would credit the 300 s the VM was
    DOWN. A down VM must accrue nothing — that is the whole fail-closed
    premise of uptime billing.
    """
    _binding()
    _run_boot(monkeypatch, start=BOOT1, receipts=10)
    _run_boot(monkeypatch, start=BOOT2, receipts=5)

    # 15 receipts × 60 s of ATTESTED uptime. The 300 s gap is not in it.
    assert _billed() == 900
    assert UsageAccrual.objects.get().unit_seconds == 100 * 900


def test_a_lease_spanning_two_boots_keeps_the_first_boots_usage(monkeypatch) -> None:
    """MUTANT: implement the re-baseline by DELETING / zeroing the
    watermark row (or the accrual) on restart. The first boot's already
    settled seconds must survive the second boot untouched.
    """
    _binding()
    _run_boot(monkeypatch, start=BOOT1, receipts=10)
    first_boot = UsageAccrual.objects.get().billable_seconds
    assert first_boot == 600

    _run_boot(monkeypatch, start=BOOT2, receipts=3)

    # One (epoch, miner, vm) bucket, ACCUMULATED across the two boots.
    assert UsageAccrual.objects.count() == 1
    assert UsageAccrual.objects.get().billable_seconds == first_boot + 180
    # And the watermark row itself was updated, not recreated.
    assert ReceiptWatermark.objects.count() == 1
    assert _wm().last_period_end == BOOT2 + 180


# ─── the replay guard the watermark exists for ───────────────────────


def test_a_replayed_receipt_is_never_re_accrued(monkeypatch) -> None:
    """MUTANT: 'a lower seq is always accepted' — the naive fix. Replay
    boot 1's receipts after the reboot and they bill a second time.
    """
    _binding()
    _run_boot(monkeypatch, start=BOOT1, receipts=10)
    _run_boot(monkeypatch, start=BOOT2, receipts=5)
    settled = _billed()

    # The miner relays boot 1's receipts again, verbatim.
    t = BOOT1
    for i in range(10):
        report = _drain(
            monkeypatch, _fields(period_start=t, period_end=t + 60, seq=1 + i)
        )
        assert report.accrued == 0
        t += 60

    assert _billed() == settled  # not one extra second


def test_replaying_a_low_seq_cannot_induce_a_re_baseline(monkeypatch) -> None:
    """MUTANT: trigger the re-baseline on ANY observed sequence
    regression. Then an adversary holding the (extractable, in-CVM-root
    readable) guest telemetry key can reset the watermark at will just by
    replaying an old receipt — a billing-inflation primitive strictly
    worse than the bug being fixed.

    The reset is keyed to the WINDOW, not the sequence: a replayed
    receipt overlaps the billed frontier, so it does not qualify.
    """
    _binding()
    _run_boot(monkeypatch, start=BOOT1, receipts=10)
    before = _wm()

    # Every replayed window opens BEFORE the billing frontier.
    for seq, start in ((1, BOOT1), (5, BOOT1 + 240), (10, BOOT1 + 540)):
        report = _drain(
            monkeypatch, _fields(period_start=start, period_end=start + 60, seq=seq)
        )
        assert report.accrued == 0

    after = _wm()
    assert after.last_monotonic_seq == before.last_monotonic_seq == 10
    assert after.last_period_end == before.last_period_end
    assert after.seq_restarts == 0  # no reset was induced


def test_a_forged_window_straddling_the_frontier_does_not_re_baseline(
    monkeypatch,
) -> None:
    """MUTANT: gate the re-baseline on `period_END > last_period_end`
    instead of `period_START >= last_period_end`. A forger could then
    re-open an already-billed window (claiming an hour that overlaps
    settled time), reset the sequence, and lean on the clamp alone.
    """
    _binding()
    _run_boot(monkeypatch, start=BOOT1, receipts=10)
    frontier = _wm().last_period_end

    # seq 1 (a regression) with a window that STARTS inside settled time
    # and ends past the frontier.
    report = _drain(
        monkeypatch,
        _fields(period_start=frontier - 300, period_end=frontier + 300, seq=1),
    )

    assert report.accrued == 0
    assert _wm().seq_restarts == 0
    assert _wm().last_period_end == frontier  # frontier never rewound
    assert _billed() == 600


def test_an_induced_re_baseline_buys_the_adversary_no_seconds(monkeypatch) -> None:
    """MUTANT: any re-baseline design under which a reset yields billable
    seconds the un-reset path would not have yielded.

    The adversary is given exactly what it can do: sign any body it likes
    (it holds the key), and choose to reset by presenting a fresh-window
    low-seq receipt. It is compared against the honest run over the same
    wall-clock. Both must bill the same seconds, and the total must stay
    bounded by the frontier's own span.
    """
    _binding()
    _run_boot(monkeypatch, start=BOOT1, receipts=10)

    # Adversary: 5 further minutes of real time, but each receipt carries
    # a deliberately reset sequence (1,1,1,…) to force a re-baseline per
    # receipt, plus a replay of an old window between each.
    t = DOWN_AT
    for _ in range(5):
        _drain(monkeypatch, _fields(period_start=t, period_end=t + 60, seq=1))
        _drain(monkeypatch, _fields(period_start=BOOT1, period_end=BOOT1 + 60, seq=1))
        t += 60

    wm = _wm()
    assert wm.last_period_end == DOWN_AT + 300
    # Exactly the wall-clock the frontier moved through — the 5 forced
    # resets and the 5 replays added nothing.
    assert _billed() == wm.last_period_end - BOOT1
    assert _billed() == 900


def test_a_restart_that_bills_nothing_still_does_not_rewind_the_frontier(
    monkeypatch,
) -> None:
    """MUTANT: rewind `last_period_end` as part of the re-baseline (the
    naive "start the VM's billing over" reading of the fix).

    On the happy path that mutant hides — a restart receipt's window is
    beyond the frontier anyway, so zeroing and re-advancing looks
    identical. It only bites on a restart receipt that is JUDGED but
    bills nothing (here: unattributable custody, but a zero-liveness or
    fully-overlapping verdict is the same shape). That path persists the
    watermark, so the zeroed frontier is committed and EVERY already-paid
    second becomes billable again.
    """
    _binding()
    _history((SOURCE, BOOT1 - 60, "launch"), ("", DOWN_AT + 60, "migration"))
    _run_boot(monkeypatch, start=BOOT1, receipts=10)
    frontier = _wm().last_period_end
    assert _billed() == 600

    # A restart receipt whose custody is unattributable: re-baselined,
    # judged, credited to nobody.
    assert _drain(
        monkeypatch, _fields(period_start=BOOT2, period_end=BOOT2 + 60, seq=1)
    ).accrued == 0
    assert _wm().last_period_end == frontier

    # The frontier survived, so boot 1's receipts still bill nothing.
    report = _drain(
        monkeypatch, _fields(period_start=BOOT1, period_end=BOOT1 + 60, seq=2)
    )
    assert report.accrued == 0
    assert _billed() == 600


def test_the_frontier_is_never_rewound(monkeypatch) -> None:
    """MUTANT: `wm.last_period_end = fields.period_end` (drop the `max`)
    on the restart path, or reset it to 0. Rewinding the frontier makes
    every already-billed second billable again — the double-billing hole
    the watermark exists to close.
    """
    _binding()
    _run_boot(monkeypatch, start=BOOT1, receipts=10)
    _run_boot(monkeypatch, start=BOOT2, receipts=3)
    peak = _wm().last_period_end

    # A late-arriving, lower-window receipt with a restarted sequence.
    _drain(monkeypatch, _fields(period_start=DOWN_AT, period_end=DOWN_AT + 60, seq=1))

    assert _wm().last_period_end == peak
    assert _billed() == 600 + 180


# ─── the other gates are NOT relaxed by the re-baseline ──────────────


def test_a_stale_restart_receipt_is_still_dropped(monkeypatch) -> None:
    """MUTANT: let the restart path bypass the §23 freshness gates. A
    backfill claiming hours of past uptime with a reset sequence must
    still be refused.
    """
    _binding()
    _run_boot(monkeypatch, start=BOOT1, receipts=10)
    monkeypatch.setattr(usage, "_now_unix", lambda: NOW + 100_000)

    report = _drain(monkeypatch, _fields(period_start=BOOT2, period_end=BOOT2 + 60, seq=1))

    assert report.accrued == 0
    assert _wm().seq_restarts == 0


def test_a_future_dated_restart_receipt_is_still_dropped(monkeypatch) -> None:
    """MUTANT: as above, for the pre-forge (skew) bound."""
    _binding()
    _run_boot(monkeypatch, start=BOOT1, receipts=10)

    report = _drain(
        monkeypatch, _fields(period_start=NOW + 5_000, period_end=NOW + 5_060, seq=1)
    )

    assert report.accrued == 0
    assert _wm().seq_restarts == 0


def test_a_restart_receipt_still_has_to_match_the_launch_binding(monkeypatch) -> None:
    """MUTANT: check the restart before the §23 identity gate, so a
    forged/inflated receipt gets in on the restart path."""
    _binding(node_id_hex=SOURCE)
    _run_boot(monkeypatch, start=BOOT1, receipts=10)

    forged = ServedReceiptFields(
        vm_id="vm-1",
        lease_id="lease-1",
        node_id_hex="ee" * 32,  # a node vali never provisioned
        epoch=5,
        resource_class="huge",  # … and a richer flavour
        period_start=BOOT2,
        period_end=BOOT2 + 60,
        monotonic_seq=1,
        observed_degradation_bps=0,
    )
    report = _drain(monkeypatch, forged)

    assert report.accrued == 0
    assert _billed() == 600


def test_a_fresh_watermark_is_not_a_restart(monkeypatch) -> None:
    """MUTANT: treat a never-used watermark (`last_monotonic_seq == 0`)
    as a restart, which would let a `seq=0` receipt bill on a row that
    has consumed nothing. The fresh-row path must be untouched.
    """
    _binding()

    report = _drain(monkeypatch, _fields(period_start=BOOT1, period_end=BOOT1 + 60, seq=0))

    assert report.accrued == 0
    assert not UsageAccrual.objects.exists()


# ─── §25: a restart must not re-credit the previous custodian ────────


def test_a_post_migration_restart_credits_the_destination(monkeypatch) -> None:
    """MUTANT: resolve the credited miner on the restart path from the
    launch binding (or from `fields.node_id_hex`) instead of the
    time-ranged `VmBillingAssignment`. The destination guest's sequence
    ALSO restarts at 1, so the restart path is exactly where a §25 VM
    re-enters the meter — crediting the source there would pay the wrong
    miner for the rest of the VM's life.
    """
    cutover = DOWN_AT + 60
    _binding()  # the guest keeps declaring SOURCE (measured cmdline)
    _history((SOURCE, BOOT1 - 60, "launch"), (DEST, cutover, "migration"))
    _run_boot(monkeypatch, start=BOOT1, receipts=10)
    assert UsageAccrual.objects.get(miner_node_id=SOURCE).billable_seconds == 600

    # The destination boots and starts its own sequence at 1.
    report = _drain(monkeypatch, _fields(period_start=BOOT2, period_end=BOOT2 + 60, seq=1))

    assert report.accrued == 1
    assert UsageAccrual.objects.get(miner_node_id=DEST).billable_seconds == 60
    # The source's settled seconds are untouched — not re-credited, not moved.
    assert UsageAccrual.objects.get(miner_node_id=SOURCE).billable_seconds == 600


def test_a_restart_cannot_re_credit_a_previous_custodian(monkeypatch) -> None:
    """MUTANT: a restart that re-opens pre-cutover time would pay the
    SOURCE again after the VM has moved. Replaying the source's own
    receipts post-migration must credit nobody.
    """
    cutover = DOWN_AT + 60
    _binding()
    _history((SOURCE, BOOT1 - 60, "launch"), (DEST, cutover, "migration"))
    _run_boot(monkeypatch, start=BOOT1, receipts=10)
    _drain(monkeypatch, _fields(period_start=BOOT2, period_end=BOOT2 + 60, seq=1))

    # Replay a pre-cutover window with a restarted sequence.
    report = _drain(monkeypatch, _fields(period_start=BOOT1, period_end=BOOT1 + 60, seq=1))

    assert report.accrued == 0
    assert UsageAccrual.objects.get(miner_node_id=SOURCE).billable_seconds == 600
    assert UsageAccrual.objects.get(miner_node_id=DEST).billable_seconds == 60


def test_an_unattributable_restart_credits_nobody(monkeypatch) -> None:
    """MUTANT: fail OPEN on the restart path (fall back to the launch
    miner when custody is unattributable). Paying a miner that provably
    no longer runs the VM is the §25 defect, restart or not."""
    _binding()
    _history((SOURCE, BOOT1 - 60, "launch"), ("", DOWN_AT + 60, "migration"))
    _run_boot(monkeypatch, start=BOOT1, receipts=10)

    report = _drain(monkeypatch, _fields(period_start=BOOT2, period_end=BOOT2 + 60, seq=1))

    assert report.accrued == 0
    assert UsageAccrual.objects.count() == 1  # only the SOURCE's pre-move row
    assert UsageAccrual.objects.get().miner_node_id == SOURCE
    # The restart was still consumed — the window is judged, not retried
    # forever.
    assert _wm().last_monotonic_seq == 1


# ─── ordering: a late pre-reboot receipt must not re-wedge billing ───


def test_a_late_pre_reboot_receipt_does_not_re_wedge_billing(monkeypatch) -> None:
    """MUTANT: gate the re-baseline on `period_start > last_period_end`
    (strict). The guest drains its buffer on shutdown and the pull broker
    adds lag, so a HIGH-seq pre-reboot receipt can arrive AFTER the new
    boot's first receipt and push the sequence watermark back up. The
    next post-reboot receipt then opens exactly AT the frontier — and
    with a strict `>` it would be dropped, wedging the VM again.
    """
    _binding()
    _run_boot(monkeypatch, start=BOOT1, receipts=10)

    # New boot, seq 1 — re-baselines and moves the frontier to BOOT2+60.
    _drain(monkeypatch, _fields(period_start=BOOT2, period_end=BOOT2 + 60, seq=1))
    # Now the pre-reboot buffer lands: high seq, old (already-billed)
    # window. It bills nothing but consumes its sequence.
    _drain(monkeypatch, _fields(period_start=BOOT1 + 540, period_end=DOWN_AT, seq=10))
    assert _wm().last_monotonic_seq == 10

    # The new boot's seq 2 chains off its own seq 1 — start == frontier.
    report = _drain(
        monkeypatch, _fields(period_start=BOOT2 + 60, period_end=BOOT2 + 120, seq=2)
    )

    assert report.accrued == 1
    assert _billed() == 600 + 120


# ─── the re-baseline is recorded, never silent ───────────────────────


def test_the_re_baseline_is_recorded(monkeypatch) -> None:
    """MUTANT: re-baseline silently. A money-path reset that leaves no
    trace cannot be audited, and an anomalous restart RATE (far above a
    VM's real reboot count) would be invisible.
    """
    _binding()
    _run_boot(monkeypatch, start=BOOT1, receipts=10)
    assert _wm().seq_restarts == 0
    assert _wm().last_restart_at_unix == 0

    _run_boot(monkeypatch, start=BOOT2, receipts=3)
    assert _wm().seq_restarts == 1
    assert _wm().last_restart_at_unix == NOW

    # A third boot bumps the counter again.
    _run_boot(monkeypatch, start=BOOT2 + 600, receipts=2)
    assert _wm().seq_restarts == 2


def test_the_restart_is_scoped_to_the_vm_lease(monkeypatch) -> None:
    """MUTANT: re-baseline across leases (or across VMs) — a restart on
    one (vm,lease) must not touch another's frontier.
    """
    _binding()
    VmBillingBinding.objects.filter(vm_id="vm-1").update(lease_id="lease-1")
    _run_boot(monkeypatch, start=BOOT1, receipts=10)

    # A second lease is a separate watermark row entirely; the first
    # lease's row must be untouched by anything happening on it.
    _drain(
        monkeypatch,
        _fields(period_start=BOOT2, period_end=BOOT2 + 60, seq=1, lease_id="lease-2"),
    )

    first = _wm()
    assert first.last_monotonic_seq == 10
    assert first.seq_restarts == 0
