"""Unit tests for the §24/§25 generation fence (`release_allowed`).

Pure — `release_allowed` only reads `Vm` attributes, so the tests
construct unsaved `Vm` instances (no DB).
"""

from __future__ import annotations

import pytest

from apps.lifecycle.models import Vm, VmState
from apps.orchestration.fence import release_allowed


def _vm(state: str, generation: int, host: str) -> Vm:
    return Vm(
        vm_id="vm-1",
        lease_id="lease-1",
        state=state,
        generation=generation,
        host=host,
        lifecycle_vk=bytes(32),
    )


def test_release_allowed_for_a_matching_active_vm() -> None:
    vm = _vm(VmState.ACTIVE, 5, "node-a")
    assert release_allowed(vm, node_id="node-a", generation=5) is True


def test_release_denied_on_a_stale_generation() -> None:
    vm = _vm(VmState.ACTIVE, 6, "node-a")
    # A release for the pre-migration generation is refused.
    assert release_allowed(vm, node_id="node-a", generation=5) is False


def test_release_denied_on_the_wrong_host() -> None:
    vm = _vm(VmState.ACTIVE, 5, "node-a")
    # A release aimed at the old source after the VM moved is refused.
    assert release_allowed(vm, node_id="node-b", generation=5) is False


@pytest.mark.parametrize(
    "state",
    [VmState.MIGRATING, VmState.DECOMMISSIONING, VmState.DESTROYED],
)
def test_release_denied_when_vm_is_not_active(state: str) -> None:
    # Mid-migration / decommissioning / a Destroyed tombstone all
    # deny every release outright.
    vm = _vm(state, 5, "node-a")
    assert release_allowed(vm, node_id="node-a", generation=5) is False
