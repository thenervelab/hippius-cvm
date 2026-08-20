"""Unit tests for `apps.tenant_bake.state_machine` — pure functions; no DB."""

from __future__ import annotations

import pytest

from apps.tenant_bake.models import TenantBakeState
from apps.tenant_bake.state_machine import (
    CAT_BAD_FIELD,
    CAT_MISSING_FIELD,
    FinalizeError,
    FinalizeRequest,
    legal,
    required_args,
)

GOOD_SHA = "a" * 64
GOOD_MEASUREMENT = "b" * 96


# ─── legal() ────────────────────────────────────────────────────────


def test_legal_queued_to_running() -> None:
    assert legal(TenantBakeState.QUEUED, TenantBakeState.RUNNING) is True


def test_legal_running_to_succeeded() -> None:
    assert legal(TenantBakeState.RUNNING, TenantBakeState.SUCCEEDED) is True


def test_legal_running_to_failed() -> None:
    assert legal(TenantBakeState.RUNNING, TenantBakeState.FAILED) is True


def test_illegal_queued_to_succeeded_shortcut() -> None:
    # The worker must claim the row (flip to Running) so `started_at`
    # gets set; skipping straight to a terminal is rejected.
    assert legal(TenantBakeState.QUEUED, TenantBakeState.SUCCEEDED) is False


def test_illegal_queued_to_failed_shortcut() -> None:
    assert legal(TenantBakeState.QUEUED, TenantBakeState.FAILED) is False


def test_illegal_running_to_queued_rewind() -> None:
    # A retry is a new row, not a rewind.
    assert legal(TenantBakeState.RUNNING, TenantBakeState.QUEUED) is False


def test_terminal_states_are_immutable() -> None:
    for state in (TenantBakeState.SUCCEEDED, TenantBakeState.FAILED):
        for target in TenantBakeState:
            assert legal(state, target) is False, f"{state}→{target} must be illegal"


# ─── required_args() — Succeeded ───────────────────────────────────


def test_succeeded_happy_path() -> None:
    req = FinalizeRequest(
        to_state=TenantBakeState.SUCCEEDED,
        if_version=1,
        qcow2_sha256=GOOD_SHA,
        kernel_sha256=GOOD_SHA,
        initrd_sha256=GOOD_SHA,
        measurement_hex=GOOD_MEASUREMENT,
    )
    # No raise.
    required_args(TenantBakeState.SUCCEEDED, req)


@pytest.mark.parametrize(
    "missing_field",
    ["qcow2_sha256", "kernel_sha256", "initrd_sha256"],
)
def test_succeeded_rejects_missing_any_artefact_sha(missing_field: str) -> None:
    kwargs = {
        "to_state": TenantBakeState.SUCCEEDED,
        "if_version": 1,
        "qcow2_sha256": GOOD_SHA,
        "kernel_sha256": GOOD_SHA,
        "initrd_sha256": GOOD_SHA,
        "measurement_hex": GOOD_MEASUREMENT,
    }
    kwargs[missing_field] = None
    req = FinalizeRequest(**kwargs)
    with pytest.raises(FinalizeError) as exc:
        required_args(TenantBakeState.SUCCEEDED, req)
    assert exc.value.category == CAT_MISSING_FIELD
    assert missing_field in exc.value.message


@pytest.mark.parametrize(
    "bad_value",
    ["", "g" * 64, "A" * 64, "a" * 63, "a" * 65],
)
def test_succeeded_rejects_bad_qcow2_sha(bad_value: str) -> None:
    req = FinalizeRequest(
        to_state=TenantBakeState.SUCCEEDED,
        if_version=1,
        qcow2_sha256=bad_value,
        kernel_sha256=GOOD_SHA,
        initrd_sha256=GOOD_SHA,
        measurement_hex=GOOD_MEASUREMENT,
    )
    with pytest.raises(FinalizeError) as exc:
        required_args(TenantBakeState.SUCCEEDED, req)
    # Empty triggers MISSING_FIELD; anything else triggers BAD_FIELD.
    assert exc.value.category in (CAT_MISSING_FIELD, CAT_BAD_FIELD)


def test_succeeded_accepts_missing_measurement() -> None:
    # The SNP launch digest folds OVMF + vcpus — launch-time inputs
    # the bake cannot know; the miner preflight computes the
    # authoritative value AFTER the bake. Succeeded without a
    # measurement is therefore valid (contract relaxed 2026-06-10
    # after every real in-cluster bake failed at finalize).
    req = FinalizeRequest(
        to_state=TenantBakeState.SUCCEEDED,
        if_version=1,
        qcow2_sha256=GOOD_SHA,
        kernel_sha256=GOOD_SHA,
        initrd_sha256=GOOD_SHA,
        measurement_hex=None,
    )
    required_args(TenantBakeState.SUCCEEDED, req)  # must not raise


@pytest.mark.parametrize(
    "bad_measurement",
    # "" is NOT a bad value — measurement_hex is OPTIONAL on Succeeded
    # (the authoritative SNP digest is computed by the miner's
    # tenant-preflight, not the bake), so empty/absent is valid. Only a
    # PRESENT-but-malformed hex (wrong length / case / non-hex) is rejected.
    ["b" * 95, "b" * 97, "B" * 96, "g" * 96],
)
def test_succeeded_rejects_bad_measurement(bad_measurement: str) -> None:
    req = FinalizeRequest(
        to_state=TenantBakeState.SUCCEEDED,
        if_version=1,
        qcow2_sha256=GOOD_SHA,
        kernel_sha256=GOOD_SHA,
        initrd_sha256=GOOD_SHA,
        measurement_hex=bad_measurement,
    )
    with pytest.raises(FinalizeError) as exc:
        required_args(TenantBakeState.SUCCEEDED, req)
    assert exc.value.category in (CAT_MISSING_FIELD, CAT_BAD_FIELD)


# ─── required_args() — Failed ──────────────────────────────────────


def test_failed_happy_path() -> None:
    req = FinalizeRequest(
        to_state=TenantBakeState.FAILED,
        if_version=1,
        failure_reason="qemu-img convert returned non-zero",
    )
    required_args(TenantBakeState.FAILED, req)


def test_failed_rejects_missing_reason() -> None:
    req = FinalizeRequest(
        to_state=TenantBakeState.FAILED, if_version=1, failure_reason=None
    )
    with pytest.raises(FinalizeError) as exc:
        required_args(TenantBakeState.FAILED, req)
    assert exc.value.category == CAT_MISSING_FIELD


def test_failed_rejects_empty_reason() -> None:
    req = FinalizeRequest(
        to_state=TenantBakeState.FAILED, if_version=1, failure_reason=""
    )
    with pytest.raises(FinalizeError):
        required_args(TenantBakeState.FAILED, req)


# ─── required_args() — Running ─────────────────────────────────────


def test_running_requires_nothing() -> None:
    # Running is the worker-claim; no artefact fields needed.
    req = FinalizeRequest(to_state=TenantBakeState.RUNNING, if_version=1)
    required_args(TenantBakeState.RUNNING, req)


# ─── required_args() — Succeeded (GOLDEN, golden-bake PR6) ──────────


def _golden_ok(**overrides) -> FinalizeRequest:
    fields = dict(
        to_state=TenantBakeState.SUCCEEDED,
        if_version=1,
        rootfs_img_sha256=GOOD_SHA,
        rootfs_verity_sha256=GOOD_SHA,
        verity_root_hash=GOOD_SHA,
        kernel_sha256=GOOD_SHA,
        initrd_sha256=GOOD_SHA,
    )
    fields.update(overrides)
    return FinalizeRequest(**fields)


def test_golden_succeeded_accepts_verity_fields() -> None:
    required_args(TenantBakeState.SUCCEEDED, _golden_ok())


def test_golden_succeeded_needs_no_qcow2() -> None:
    # The presence of a golden field selects the golden contract; qcow2 is
    # NOT required (a golden base is unkeyed dm-verity, no per-VM LUKS).
    required_args(TenantBakeState.SUCCEEDED, _golden_ok())


def test_golden_succeeded_rejects_qcow2_present() -> None:
    # A finalize carrying BOTH golden fields AND a qcow2 is a mixed-mode
    # producer bug ⇒ fail closed.
    with pytest.raises(FinalizeError) as exc:
        required_args(TenantBakeState.SUCCEEDED, _golden_ok(qcow2_sha256=GOOD_SHA))
    assert exc.value.category == CAT_BAD_FIELD


def test_golden_succeeded_requires_rootfs_img() -> None:
    with pytest.raises(FinalizeError) as exc:
        required_args(
            TenantBakeState.SUCCEEDED, _golden_ok(rootfs_img_sha256=None)
        )
    # With rootfs_img absent but verity fields present it's still golden.
    assert exc.value.category == CAT_MISSING_FIELD


def test_golden_succeeded_rejects_short_verity_root() -> None:
    with pytest.raises(FinalizeError) as exc:
        required_args(
            TenantBakeState.SUCCEEDED, _golden_ok(verity_root_hash="abc")
        )
    assert exc.value.category == CAT_BAD_FIELD
