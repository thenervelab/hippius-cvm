"""The §23 uptime-LIVENESS gate — credit only SNP-proven-alive time.

THE ATTACK this closes, reproduced live by a red team: a
`ServedDeliveryReceipt` is signed ONLY by the guest telemetry key, which
is HKDF-derived from the §7 lifecycle key and readable by ROOT INSIDE
THE CVM. So a miner can

  1. launch a tenant VM on its own node — entirely legitimate;
  2. read the lifecycle key and derive the telemetry key;
  3. KILL the VM;
  4. keep signing well-formed uptime receipts forever, from anywhere.

Every other gate in `_accrue_one` still passes for those receipts: the
`vm_id` matches its telemetry source, the `node_id` / `resource_class` /
`lease_id` match the launch `VmBillingBinding` vali wrote itself, the
window is fresh, the sequence is new. Possession of the key IS the
signature. Nothing there requires the VM to still exist.

The gate tested here does. Once armed, only the part of a receipt window
covered by a KBS-L0-signed `LiveAttestation` — minted only after the KBS
verified a fresh `SNP_GET_REPORT` bound to a single-use KBS nonce — is
creditable, and uncovered time credits ZERO.

The receipts here are modelled at the POST-VERIFICATION boundary
(`ServedReceiptFields`), which is exactly what the attacker's stolen key
buys: a receipt whose signature checks out. Several tests assert the
same receipt DOES credit fully with the gate disabled, so what is being
measured is the gate and nothing else.
"""

from __future__ import annotations

import pytest

from apps.scheduler import usage
from apps.scheduler.models import ReceiptWatermark, UsageAccrual, VmBillingBinding
from apps.telemetry.models import (
    EnvelopeKind,
    ProcessingStatus,
    SourceType,
    TelemetryEnvelope,
    TelemetrySource,
    VmLiveAttestation,
)
from apps.telemetry.verifier import ServedReceiptFields

pytestmark = pytest.mark.django_db

NODE = "ab" * 32
MEASUREMENT = "44" * 48
VM = "vm-1"

# Pinned wall clock. Receipt windows sit just below it so they are fresh.
NOW = 2_000_000


@pytest.fixture(autouse=True)
def _pin_now(monkeypatch):
    monkeypatch.setattr(usage, "_now_unix", lambda: NOW)


@pytest.fixture(autouse=True)
def _units(monkeypatch):
    monkeypatch.setattr(usage.scoring, "resource_units", lambda rc: 100)


@pytest.fixture(autouse=True)
def _spans(settings):
    settings.VALI_UPTIME_LIVENESS_COVERAGE_S = 900
    settings.VALI_UPTIME_LIVENESS_GRACE_S = 300


def _binding(*, created_unix: int | None = None) -> VmBillingBinding:
    """The launch binding. Its `created_at` is the FLOOR the coverage
    look-back is clipped to, so it is pinned relative to the test clock
    (default: long before any window under test)."""
    from datetime import UTC, datetime

    row = VmBillingBinding.objects.create(
        vm_id=VM,
        node_id_hex=NODE,
        resource_class="small",
        lease_id="lease-1",
    )
    created = NOW - 1_000_000 if created_unix is None else created_unix
    VmBillingBinding.objects.filter(pk=row.pk).update(
        created_at=datetime.fromtimestamp(created, tz=UTC)
    )
    row.refresh_from_db()
    return row


def _source() -> None:
    TelemetrySource.objects.get_or_create(
        source=SourceType.TENANT_VM.value,
        source_id=VM,
        defaults={"verifying_key": bytes(32)},
    )


def _envelope(seq: int = 1) -> TelemetryEnvelope:
    _source()
    return TelemetryEnvelope.objects.create(
        source=SourceType.TENANT_VM.value,
        source_id=VM,
        kind=EnvelopeKind.SERVED_RECEIPT.value,
        schema_version=1,
        payload_cbor=b"\x01",
        signature=b"\x02" * 64,
        processing_status=ProcessingStatus.PENDING.value,
        dedupe_digest=f"digest-{seq}",
    )


def _fields(
    *,
    period_start: int,
    period_end: int,
    monotonic_seq: int = 1,
) -> ServedReceiptFields:
    """A receipt that passes EVERY pre-existing gate — this is what an
    extracted telemetry key produces."""
    return ServedReceiptFields(
        vm_id=VM,
        lease_id="lease-1",
        node_id_hex=NODE,
        epoch=5,
        resource_class="small",
        period_start=period_start,
        period_end=period_end,
        monotonic_seq=monotonic_seq,
        observed_degradation_bps=0,
    )


def _patch_verify(monkeypatch, fields) -> None:
    monkeypatch.setattr(
        usage.verifier,
        "verify_served_receipt",
        lambda *, body, sig, verifying_key: fields,
    )


def _live_sample(t: int, *, seq: int = 1) -> None:
    """One recorded SNP-attested liveness sample at instant `t`."""
    VmLiveAttestation.objects.create(
        vm_id=VM,
        node_id_hex=NODE,
        attestation_seq=seq,
        epoch=5,
        observed_at_unix=t - 1,
        verified_at_unix=t,
        expiry_unix=t + 900,
        measurement=MEASUREMENT,
        snp_report_digest="11" * 32,
        body_digest=f"{seq:064d}",
    )


def _credited() -> int:
    row = UsageAccrual.objects.filter(vm_id=VM).first()
    return 0 if row is None else row.unit_seconds


# ─── THE ATTACK ──────────────────────────────────────────────────────


def test_the_attack_a_killed_vm_with_a_stolen_key_credits_zero(
    monkeypatch, settings
) -> None:
    """THE test this whole change exists for.

    Hold a valid telemetry key. Emit a well-formed receipt for a VM that
    is NOT running — no liveness attestation covers its window, because
    a dead VM cannot produce one. Assert the credited `unit_seconds` is
    ZERO once the gate is armed.

    The receipt claims a huge window, the way the red team's did (one
    fabricated receipt credited 5,716,050 unit_seconds). It is aged past
    the grace so the gate judges it rather than deferring.
    """
    _binding()
    _envelope()
    # A window that closed 400 s ago — fresh enough to pass the receipt
    # freshness gates, old enough that the liveness gate judges it.
    end = NOW - 400
    start = end - 3600
    _patch_verify(monkeypatch, _fields(period_start=start, period_end=end))
    assert VmLiveAttestation.objects.count() == 0  # the VM is dead

    settings.VALI_UPTIME_REQUIRE_LIVENESS_ATTESTATION = True
    report = usage.accrue_usage_once()

    assert report.accrued == 0
    assert report.requeued == 0
    assert _credited() == 0
    assert not UsageAccrual.objects.exists()


def test_the_same_forged_receipt_is_fully_billable_with_the_gate_off(
    monkeypatch, settings
) -> None:
    """Control for the test above: the forged receipt is otherwise
    PERFECT — it passes the source bind, the launch-binding bind, the
    freshness bounds and the sequence watermark, and bills the full
    window. The liveness gate is the only thing between an extracted key
    and the ledger."""
    _binding()
    _envelope()
    end = NOW - 400
    start = end - 3600
    _patch_verify(monkeypatch, _fields(period_start=start, period_end=end))

    settings.VALI_UPTIME_REQUIRE_LIVENESS_ATTESTATION = False
    report = usage.accrue_usage_once()

    assert report.accrued == 1
    assert _credited() == 100 * 3600


def test_a_stale_attestation_does_not_keep_paying_after_the_kill(
    monkeypatch, settings
) -> None:
    """The miner attests once (the VM was genuinely up), then kills the
    VM and keeps signing receipts for the time AFTER. Coverage is
    backward-only, so the last attestation vouches for nothing past
    itself."""
    _binding()
    _envelope()
    kill_at = NOW - 3600
    _live_sample(kill_at)  # the last honest sample
    # A receipt claiming the hour AFTER the VM died.
    _patch_verify(
        monkeypatch,
        _fields(period_start=kill_at, period_end=NOW - 400),
    )

    settings.VALI_UPTIME_REQUIRE_LIVENESS_ATTESTATION = True
    report = usage.accrue_usage_once()

    assert report.accrued == 0
    assert _credited() == 0


def test_replaying_the_covering_attestation_buys_no_extra_credit(
    monkeypatch, settings
) -> None:
    """A captured live attestation re-submitted N times is one row (the
    ingest dedupes it) and therefore one interval of coverage — it can
    never stretch to cover a window it did not."""
    # The ingest dedupes a replayed attestation to ONE row (see
    # `apps.telemetry.tests.test_vm_liveness`), so however many times the
    # miner re-POSTs it, the meter sees exactly one interval.
    _binding()
    _envelope()
    end = NOW - 400
    _live_sample(end)  # covers [end-900, end]
    assert VmLiveAttestation.objects.filter(vm_id=VM).count() == 1

    _patch_verify(monkeypatch, _fields(period_start=end - 3600, period_end=end))
    settings.VALI_UPTIME_REQUIRE_LIVENESS_ATTESTATION = True
    usage.accrue_usage_once()

    # Only the 900 s the single sample vouches for — not the 3600 s
    # claimed.
    assert _credited() == 100 * 900


# ─── armed: covered time IS credited ─────────────────────────────────


def test_a_covered_window_credits_in_full(monkeypatch, settings) -> None:
    _binding()
    _envelope()
    end = NOW - 400
    start = end - 60
    _live_sample(end)  # covers [end-900, end] ⊇ [start, end]
    _patch_verify(monkeypatch, _fields(period_start=start, period_end=end))

    settings.VALI_UPTIME_REQUIRE_LIVENESS_ATTESTATION = True
    report = usage.accrue_usage_once()

    assert report.accrued == 1
    assert _credited() == 100 * 60
    assert UsageAccrual.objects.get().billable_seconds == 60


def test_a_partly_covered_window_credits_only_the_covered_part(
    monkeypatch, settings
) -> None:
    settings.VALI_UPTIME_LIVENESS_COVERAGE_S = 30
    _binding()
    _envelope()
    end = NOW - 400
    start = end - 120
    _live_sample(end)  # covers only [end-30, end]
    _patch_verify(monkeypatch, _fields(period_start=start, period_end=end))

    settings.VALI_UPTIME_REQUIRE_LIVENESS_ATTESTATION = True
    usage.accrue_usage_once()

    assert _credited() == 100 * 30
    assert UsageAccrual.objects.get().billable_seconds == 30


def test_look_back_cannot_predate_the_vms_own_launch(monkeypatch, settings) -> None:
    """A VM's very FIRST attestation must not credit a full span of
    uptime from before the VM existed."""
    end = NOW - 400
    _binding(created_unix=end - 20)
    _envelope()
    _live_sample(end)  # would otherwise cover 900 s back
    _patch_verify(monkeypatch, _fields(period_start=end - 900, period_end=end))

    settings.VALI_UPTIME_REQUIRE_LIVENESS_ATTESTATION = True
    usage.accrue_usage_once()

    assert _credited() == 100 * 20


# ─── armed: deferral, not a premature zero ───────────────────────────


def test_a_too_fresh_uncovered_receipt_is_requeued_not_burned(
    monkeypatch, settings
) -> None:
    """The covering attestation travels on its own path and can land
    just after the receipt. Judging then would burn the receipt's
    sequence on a verdict that was merely early — so the envelope goes
    back on the queue instead."""
    _binding()
    env = _envelope()
    end = NOW - 10  # inside the 300 s grace
    _patch_verify(monkeypatch, _fields(period_start=end - 60, period_end=end))

    settings.VALI_UPTIME_REQUIRE_LIVENESS_ATTESTATION = True
    report = usage.accrue_usage_once()

    assert report.accrued == 0
    assert report.requeued == 1
    assert _credited() == 0
    env.refresh_from_db()
    assert env.processing_status == ProcessingStatus.PENDING.value
    # The sequence was NOT consumed — the receipt can still be billed
    # once its attestation lands.
    assert not ReceiptWatermark.objects.filter(
        vm_id=VM, last_monotonic_seq__gt=0
    ).exists()


def test_a_deferred_receipt_bills_once_its_attestation_lands(
    monkeypatch, settings
) -> None:
    _binding()
    _envelope()
    end = NOW - 10
    _patch_verify(monkeypatch, _fields(period_start=end - 60, period_end=end))
    settings.VALI_UPTIME_REQUIRE_LIVENESS_ATTESTATION = True

    assert usage.accrue_usage_once().requeued == 1
    assert _credited() == 0

    _live_sample(end)  # the attestation arrives
    report = usage.accrue_usage_once()

    assert report.accrued == 1
    assert _credited() == 100 * 60


def test_an_aged_uncovered_receipt_is_judged_not_deferred_forever(
    monkeypatch, settings
) -> None:
    _binding()
    env = _envelope()
    end = NOW - 400  # past the 300 s grace
    _patch_verify(monkeypatch, _fields(period_start=end - 60, period_end=end))

    settings.VALI_UPTIME_REQUIRE_LIVENESS_ATTESTATION = True
    report = usage.accrue_usage_once()

    assert report.requeued == 0
    assert report.skipped == 1
    assert _credited() == 0
    env.refresh_from_db()
    assert env.processing_status == ProcessingStatus.DONE.value
    # The sequence IS consumed — the verdict is final.
    assert ReceiptWatermark.objects.get(vm_id=VM).last_monotonic_seq == 1


# ─── disabled: byte-identical to today ───────────────────────────────


@pytest.mark.parametrize("receipts", [1, 3, 10])
def test_disabled_accrual_is_unchanged_however_many_uncovered_receipts_arrive(
    monkeypatch, settings, receipts: int
) -> None:
    """The roll-out contract: with the flag off, a fleet whose guests
    answer NO liveness challenges accrues exactly as before. Any other
    behaviour would stop all reward on deploy."""
    _binding()
    settings.VALI_UPTIME_REQUIRE_LIVENESS_ATTESTATION = False
    assert VmLiveAttestation.objects.count() == 0

    total = 0
    for i in range(receipts):
        _envelope(seq=i + 1)
        end = NOW - 400 + i  # contiguous, non-overlapping windows
        start = end - 1
        _patch_verify(
            monkeypatch,
            _fields(period_start=start, period_end=end, monotonic_seq=i + 1),
        )
        report = usage.accrue_usage_once()
        assert report.accrued == 1
        assert report.requeued == 0
        total += 1

    assert UsageAccrual.objects.get(vm_id=VM).billable_seconds == total
    assert _credited() == 100 * total


def test_disabled_never_consults_the_liveness_meter(monkeypatch, settings) -> None:
    """Not merely "the numbers match" — the disabled path must not even
    reach the coverage query, so a liveness-side outage can never affect
    billing before the operator arms the gate."""
    from apps.telemetry import vm_liveness

    def explode(**kwargs):  # pragma: no cover — must never run
        raise AssertionError("the disabled path consulted the liveness meter")

    monkeypatch.setattr(vm_liveness, "covered_seconds", explode)

    _binding()
    _envelope()
    end = NOW - 400
    _patch_verify(monkeypatch, _fields(period_start=end - 60, period_end=end))

    settings.VALI_UPTIME_REQUIRE_LIVENESS_ATTESTATION = False
    report = usage.accrue_usage_once()

    assert report.accrued == 1
    assert _credited() == 100 * 60


def test_the_setting_is_wired_and_currently_disabled(settings) -> None:
    assert settings.VALI_UPTIME_REQUIRE_LIVENESS_ATTESTATION is False
    assert usage._require_liveness_attestation() is False


def test_the_accessor_default_is_disabled_when_the_setting_is_absent(
    settings,
) -> None:
    """The meter's `getattr` fallback. A deployment whose settings module
    predates this flag (a rollback, a partial config) must fall back to
    DISABLED — an ARMED fallback would stop reward accrual fleet-wide on
    exactly the deploy least able to notice."""
    del settings.VALI_UPTIME_REQUIRE_LIVENESS_ATTESTATION
    assert usage._require_liveness_attestation() is False


def test_the_settings_module_default_is_disabled() -> None:
    """The OTHER default, and the one that actually ships: settings.py's
    `_env_bool(..., False)`.

    Loaded in a subprocess against the PRODUCTION settings module with
    the env var absent — the true "operator set nothing" case, which a
    test running under `settings_test` (where the value is always
    defined) cannot otherwise observe."""
    import subprocess
    import sys
    from pathlib import Path

    vali_root = Path(__file__).resolve().parents[3]
    env = {
        "PATH": "/usr/bin:/bin",
        "DJANGO_SETTINGS_MODULE": "vali.settings",
        # settings.py refuses to load in production mode without one;
        # it is unrelated to the flag under test.
        "DJANGO_SECRET_KEY": "test-only-not-a-real-key",
    }
    proc = subprocess.run(
        [
            sys.executable,
            "-c",
            "from django.conf import settings;"
            "print(settings.VALI_UPTIME_REQUIRE_LIVENESS_ATTESTATION)",
        ],
        cwd=vali_root,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == "False", proc.stdout
