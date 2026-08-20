"""Unit tests for `apps.packer.state_machine` — pure functions; no DB."""

from __future__ import annotations

import pytest

from apps.packer.models import PackerBuildState
from apps.packer.state_machine import (
    CAT_BAD_FIELD,
    CAT_MISSING_FIELD,
    FinalizeError,
    FinalizeRequest,
    legal,
    required_args,
)

# Use a representative valid sha256 once — every "Succeeded happy path"
# test reuses it so the comparison readers can focus on the rule
# under test, not the hex literal.
GOOD_SHA = "a" * 64


def test_legal_queued_to_running() -> None:
    assert legal(PackerBuildState.QUEUED, PackerBuildState.RUNNING) is True


def test_legal_running_to_succeeded() -> None:
    assert legal(PackerBuildState.RUNNING, PackerBuildState.SUCCEEDED) is True


def test_legal_running_to_failed() -> None:
    assert legal(PackerBuildState.RUNNING, PackerBuildState.FAILED) is True


def test_illegal_queued_to_succeeded_shortcut() -> None:
    # The worker must claim the row (flip to Running) so `started_at`
    # gets set; skipping straight to a terminal is rejected.
    assert legal(PackerBuildState.QUEUED, PackerBuildState.SUCCEEDED) is False


def test_illegal_terminal_to_anything() -> None:
    for term in (PackerBuildState.SUCCEEDED, PackerBuildState.FAILED):
        for tgt in PackerBuildState:
            assert legal(term, tgt) is False, (term, tgt)


def test_illegal_running_to_queued_rewind() -> None:
    assert legal(PackerBuildState.RUNNING, PackerBuildState.QUEUED) is False


def test_required_args_running_no_extra_fields_needed() -> None:
    # Queued → Running carries no payload — just `if_version`.
    required_args(
        PackerBuildState.RUNNING,
        FinalizeRequest(to_state=PackerBuildState.RUNNING, if_version=1),
    )


def test_required_args_succeeded_demands_sha256() -> None:
    with pytest.raises(FinalizeError) as exc_info:
        required_args(
            PackerBuildState.SUCCEEDED,
            FinalizeRequest(
                to_state=PackerBuildState.SUCCEEDED,
                if_version=1,
                provenance_signed_url="https://x",
            ),
        )
    assert exc_info.value.category == CAT_MISSING_FIELD


def test_required_args_succeeded_demands_provenance() -> None:
    with pytest.raises(FinalizeError) as exc_info:
        required_args(
            PackerBuildState.SUCCEEDED,
            FinalizeRequest(
                to_state=PackerBuildState.SUCCEEDED,
                if_version=1,
                artifact_sha256=GOOD_SHA,
            ),
        )
    assert exc_info.value.category == CAT_MISSING_FIELD


def test_required_args_succeeded_rejects_non_hex_sha() -> None:
    with pytest.raises(FinalizeError) as exc_info:
        required_args(
            PackerBuildState.SUCCEEDED,
            FinalizeRequest(
                to_state=PackerBuildState.SUCCEEDED,
                if_version=1,
                artifact_sha256="zz" + "a" * 62,
                provenance_signed_url="https://x",
            ),
        )
    assert exc_info.value.category == CAT_BAD_FIELD


def test_required_args_succeeded_rejects_uppercase_hex() -> None:
    # Uppercase rejected so the wire form is canonical.
    with pytest.raises(FinalizeError) as exc_info:
        required_args(
            PackerBuildState.SUCCEEDED,
            FinalizeRequest(
                to_state=PackerBuildState.SUCCEEDED,
                if_version=1,
                artifact_sha256="A" * 64,
                provenance_signed_url="https://x",
            ),
        )
    assert exc_info.value.category == CAT_BAD_FIELD


def test_required_args_succeeded_happy() -> None:
    required_args(
        PackerBuildState.SUCCEEDED,
        FinalizeRequest(
            to_state=PackerBuildState.SUCCEEDED,
            if_version=1,
            artifact_sha256=GOOD_SHA,
            provenance_signed_url="https://hippius.example/p",
        ),
    )


def test_required_args_failed_demands_reason() -> None:
    with pytest.raises(FinalizeError) as exc_info:
        required_args(
            PackerBuildState.FAILED,
            FinalizeRequest(to_state=PackerBuildState.FAILED, if_version=1),
        )
    assert exc_info.value.category == CAT_MISSING_FIELD


def test_required_args_failed_happy() -> None:
    required_args(
        PackerBuildState.FAILED,
        FinalizeRequest(
            to_state=PackerBuildState.FAILED,
            if_version=1,
            failure_reason="packer-step-3 exit 1",
        ),
    )
