"""E4: two placements racing for one node's dedicated disks — a disk is
never assigned twice (`apps.disktier.dedicated.assign`).

Two threads, two DB connections: the first placement holds its row locks
inside its transaction while the second asks for the same node's disks.
The row locks and the `free → assigned` compare-and-set are Postgres
behaviour, so this runs in the CI Postgres lane (`--ds=vali.settings_test_pg`);
on SQLite's per-connection in-memory DB it is skipped (the sequential case
is `test_dedicated.py::test_a_disk_is_never_assigned_twice`)."""

from __future__ import annotations

import threading
import time
from typing import Any

import pytest
from django.db import connection, connections, transaction
from django.test import override_settings

from apps.disktier import dedicated
from apps.disktier.dedicated import DedicatedRequest, DisksTaken
from apps.disktier.models import DedicatedDisk, PlacementDisk
from apps.scheduler.tests.factories import make_placement, make_vm, node_id

from .dedicated_helpers import ON, capable, make_disk

pytestmark = pytest.mark.skipif(
    connection.vendor != "postgresql", reason="row locks need Postgres (CI Postgres lane)"
)

NODE = node_id(1)


def _run(target: Any) -> tuple[threading.Thread, dict[str, Any]]:
    out: dict[str, Any] = {}

    def run() -> None:
        try:
            out["result"] = target()
        except BaseException as exc:  # surfaced by the assertions
            out["error"] = exc
        finally:
            connections.close_all()

    thread = threading.Thread(target=run)
    thread.start()
    return thread, out


@pytest.mark.django_db(transaction=True)
@override_settings(**ON)
@pytest.mark.parametrize(("disks", "second_gets"), [(3, None), (4, 2)])
def test_a_concurrent_placement_never_takes_a_locked_disk(disks, second_gets) -> None:
    capable(NODE)
    for i in range(disks):
        make_disk(f"wwn-0x0{i}", size_gib=20000)
    request = DedicatedRequest("hdd", 2, 16000)
    vm_a, vm_b = make_vm("vm-a", "lease-a"), make_vm("vm-b", "lease-b")
    pa, pb = make_placement(vm_a, NODE), make_placement(vm_b, NODE)
    locked, release = threading.Event(), threading.Event()

    def first() -> list[str]:
        with transaction.atomic():
            rows = dedicated.assign(pa, vm_a, request)
            locked.set()
            assert release.wait(10)
        return [r.dedicated_disk.disk_id for r in rows]

    def second() -> list[str]:
        assert locked.wait(10)
        with transaction.atomic():
            return [r.dedicated_disk.disk_id for r in dedicated.assign(pb, vm_b, request)]

    t1, out1 = _run(first)
    t2, out2 = _run(second)
    # The second blocks on the first's row locks: it cannot have finished.
    time.sleep(1.0)
    assert t2.is_alive(), out2
    release.set()
    t1.join(15)
    t2.join(15)
    assert "error" not in out1, out1
    taken_a = set(out1["result"])
    assert len(taken_a) == 2
    if "error" in out2:
        # It saw the locked rows go: never a disk the first one holds.
        assert isinstance(out2["error"], DisksTaken), out2
    else:
        assert second_gets is not None
        assert len(set(out2["result"])) == second_gets
        assert not taken_a & set(out2["result"])
    # Whatever happened, no disk has two holders and the rows agree.
    holders = DedicatedDisk.objects.filter(state="assigned").values_list("disk_id", "assigned_vm")
    assert len({d for d, _ in holders}) == len(list(holders))
    assert PlacementDisk.objects.filter(placement=pa).count() == 2
    assert {
        r.dedicated_disk_id for r in PlacementDisk.objects.filter(placement=pa)
    }.isdisjoint({r.dedicated_disk_id for r in PlacementDisk.objects.filter(placement=pb)})
