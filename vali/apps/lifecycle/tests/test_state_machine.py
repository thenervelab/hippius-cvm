"""State-machine rule tests (no DB, no view, no shell-out)."""

from __future__ import annotations

import pytest

from apps.lifecycle.models import VmState
from apps.lifecycle.state_machine import (
    CAT_MISSING_FIELD,
    TransitionError,
    TransitionRequest,
    legal,
    required_args,
    requires_stopped_ack,
)

# ─── Legality matrix ─────────────────────────────────────────────────


@pytest.mark.parametrize(
    "src,dst",
    [
        (VmState.ACTIVE, VmState.MIGRATING),
        (VmState.ACTIVE, VmState.DECOMMISSIONING),
        (VmState.MIGRATING, VmState.ACTIVE),
        (VmState.MIGRATING, VmState.DECOMMISSIONING),
        (VmState.DECOMMISSIONING, VmState.DESTROYED),
    ],
)
def test_legal_transitions(src: VmState, dst: VmState) -> None:
    assert legal(src, dst)


@pytest.mark.parametrize(
    "src,dst",
    [
        # Terminal: Destroyed never transitions.
        (VmState.DESTROYED, VmState.ACTIVE),
        (VmState.DESTROYED, VmState.DESTROYED),
        # Direct destroy bypasses the EOL nonce — must go through Decommissioning.
        (VmState.ACTIVE, VmState.DESTROYED),
        (VmState.MIGRATING, VmState.DESTROYED),
        # Active → Active is a no-op; reject to surface confused callers.
        (VmState.ACTIVE, VmState.ACTIVE),
        # No path from Decommissioning back to Active (§24 EOL is committal).
        (VmState.DECOMMISSIONING, VmState.ACTIVE),
        (VmState.DECOMMISSIONING, VmState.MIGRATING),
    ],
)
def test_illegal_transitions(src: VmState, dst: VmState) -> None:
    assert not legal(src, dst)


# ─── Required-fields gate ────────────────────────────────────────────


def test_migrating_target_requires_new_generation() -> None:
    req = TransitionRequest(
        to_state=VmState.MIGRATING,
        if_version=1,
        new_generation=None,
        migration_dest="dst",
    )
    with pytest.raises(TransitionError) as exc_info:
        required_args(VmState.MIGRATING, req)
    assert exc_info.value.category == CAT_MISSING_FIELD


def test_migrating_target_requires_migration_dest() -> None:
    req = TransitionRequest(
        to_state=VmState.MIGRATING,
        if_version=1,
        new_generation=5,
        migration_dest=None,
    )
    with pytest.raises(TransitionError) as exc_info:
        required_args(VmState.MIGRATING, req)
    assert exc_info.value.category == CAT_MISSING_FIELD


def test_active_target_requires_new_generation() -> None:
    req = TransitionRequest(
        to_state=VmState.ACTIVE,
        if_version=1,
        new_generation=None,
    )
    with pytest.raises(TransitionError) as exc_info:
        required_args(VmState.ACTIVE, req)
    assert exc_info.value.category == CAT_MISSING_FIELD


def test_decommissioning_target_has_no_required_fields() -> None:
    # Should not raise.
    required_args(
        VmState.DECOMMISSIONING,
        TransitionRequest(to_state=VmState.DECOMMISSIONING, if_version=1),
    )


def test_destroyed_target_has_no_required_fields() -> None:
    required_args(
        VmState.DESTROYED,
        TransitionRequest(to_state=VmState.DESTROYED, if_version=1),
    )


# ─── Stopped-ack gate ────────────────────────────────────────────────


@pytest.mark.parametrize(
    "src,dst,expected",
    [
        (VmState.DECOMMISSIONING, VmState.DESTROYED, True),
        (VmState.MIGRATING, VmState.ACTIVE, True),
        # All other legal transitions do NOT require an ack.
        (VmState.ACTIVE, VmState.MIGRATING, False),
        (VmState.ACTIVE, VmState.DECOMMISSIONING, False),
        (VmState.MIGRATING, VmState.DECOMMISSIONING, False),
    ],
)
def test_requires_stopped_ack_matrix(
    src: VmState, dst: VmState, expected: bool
) -> None:
    assert requires_stopped_ack(src, dst) is expected
