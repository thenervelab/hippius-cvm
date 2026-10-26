"""`preflight.fresh_order_id` — unique per call, even in one process and
one second (concurrent launch jobs share a pid)."""

from __future__ import annotations

import re
from concurrent.futures import ThreadPoolExecutor
from unittest import mock

from apps.orchestration.services import preflight

#: The miner-agent's order-id rule (and vali's launch-error ledger's).
_ORDER_ID_RE = re.compile(r"[A-Za-z0-9._:-]{1,128}")


def test_concurrent_calls_in_one_second_never_repeat() -> None:
    with mock.patch.object(preflight.time, "time", return_value=1_792_700_000.0):
        with ThreadPoolExecutor(max_workers=16) as pool:
            ids = list(pool.map(lambda _: preflight.fresh_order_id(), range(2000)))
    assert len(set(ids)) == len(ids)


def test_the_id_keeps_its_shape_and_the_miner_accepts_it() -> None:
    oid = preflight.fresh_order_id()
    assert oid.startswith("ord-preflight-")
    assert _ORDER_ID_RE.fullmatch(oid)
    assert preflight.fresh_order_id("ord-xgen-probe").startswith("ord-xgen-probe-")
