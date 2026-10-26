"""Contract §9: an in-place resize and a reboot-recovery relaunch of a VM
with integrity slots measure the same `x<N>:<GiB>:i` anchor, through the
REAL `launch_on_miner` (the rig of `test_dedicated_pinned_resize.py`)."""

from __future__ import annotations

from typing import Any

import pytest

from apps.disktier.models import PlacementDisk
from apps.orchestration import service
from apps.orchestration.models import LaunchJob, ResizeState

from .test_dedicated_pinned_resize import _real_relaunch_rig
from .test_resize import (  # noqa: F401 — autouse fixtures and the fake miner
    _catalogue,
    _hosts,
    _settings,
    _start,
    _tick,
    miner,
)

pytestmark = pytest.mark.django_db


def _token(cmdline: str) -> list[str]:
    return [t for t in cmdline.split() if t.startswith("hippius.dedicated=")]


def _integrity_relaunch_rig(monkeypatch):
    vm, payloads, outcomes, expected = _real_relaunch_rig(monkeypatch)
    PlacementDisk.objects.filter(placement__vm=vm).update(integrity=True)
    job = LaunchJob.objects.get(vm_id=vm.vm_id)
    job.spec_json = {
        **job.spec_json,
        "dedicated_disks": {**job.spec_json["dedicated_disks"], "integrity": True},
    }
    job.save()
    return vm, payloads, outcomes, expected


def _assert_integrity_token(payload: dict[str, Any], expected: list[dict]) -> None:
    assert payload["require_existing_disks"] is True
    assert payload["extra_disks"] == expected
    assert _token(payload["cmdline"]) == ["hippius.dedicated=x0:16000:i,x1:22300:i"]


def test_an_in_place_resize_relaunches_with_the_integrity_anchor(monkeypatch) -> None:
    vm, payloads, outcomes, expected = _integrity_relaunch_rig(monkeypatch)
    resize_job = _start(vm, "compact-2")
    _tick(3)
    resize_job.refresh_from_db()
    assert resize_job.state in (ResizeState.RELAUNCHING, ResizeState.DONE), resize_job.reason
    assert len(payloads) == 1, outcomes
    _assert_integrity_token(payloads[0], expected)


def test_a_reboot_recovery_relaunch_sends_the_integrity_anchor(monkeypatch) -> None:
    vm, payloads, outcomes, expected = _integrity_relaunch_rig(monkeypatch)
    assert service._reboot_recovery_relaunch(vm, vm.host) is True, outcomes
    (relaunch,) = payloads
    _assert_integrity_token(relaunch, expected)
