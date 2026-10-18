"""§18.10 operator host-inventory reads (`apps.disktier.hardware_views`):
the gates (operator principal, family on chain), section status /
staleness, the change history, the disk inventory and its cross-check
against vali's pools and dedicated disks. And the serial-redaction log
filter every vali handler carries."""

from __future__ import annotations

import io
import logging
from datetime import timedelta
from typing import Any

import pytest
from django.conf import settings
from django.urls import reverse
from django.utils import timezone
from rest_framework.test import APIClient

from apps.disktier.models import (
    DedicatedDisk,
    DedicatedDiskState,
    HostInventoryChange,
    HostInventorySection,
    MinerStoragePool,
)
from apps.scheduler.tests.factories import node_id
from vali.log_filters import SerialRedactionFilter, redact

from .conftest import FAMILY_A, FAMILY_B, bind, ss58_encode

pytestmark = pytest.mark.django_db

NODE = node_id(1)
HEADERS = {
    "HTTP_X_HIPPIUS_ACTING_FAMILY": ss58_encode(FAMILY_A),
    "HTTP_X_HIPPIUS_ACTING_USER": "user-42",
}
ROUTES = ("operator_hardware", "operator_hardware_history", "operator_disk_inventory")


def _url(name: str, node: str = NODE) -> str:
    return reverse(name, kwargs={"node_id": node})


def _section(name: str, body: dict[str, Any], *, age: timedelta = timedelta(0)) -> None:
    at = timezone.now() - age
    HostInventorySection.objects.create(
        miner_node_id=NODE,
        section=name,
        digest="0" * 64,
        body=body,
        status=body.get("status", ""),
        reported_at=at,
        sequence=1,
        received_at=at,
    )


def _device(
    name: str, role: str, *, pools: list[str] | None = None, ids: list[str] | None = None
) -> dict[str, Any]:
    return {"name": name, "kind": "disk", "role": role, "ids": ids or [], "pool_ids": pools or []}


def _storage(devices: list[dict[str, Any]], *, status: str = "ok", truncated: bool = False):
    _section(
        "storage",
        {
            "status": status,
            "devices": devices,
            "advisories": [],
            "advisories_truncated": False,
            "devices_truncated": truncated,
        },
    )


@pytest.fixture
def owned(chain: dict[str, Any]) -> dict[str, Any]:
    bind(chain, NODE, FAMILY_A)
    return chain


def test_reads_need_an_operator_and_the_nodes_family(
    chain: dict[str, Any], operator_client: APIClient, tenant_client: APIClient
) -> None:
    bind(chain, NODE, FAMILY_B)
    for route in ROUTES:
        assert APIClient().get(_url(route), **HEADERS).status_code in (401, 403)
        assert tenant_client.get(_url(route), **HEADERS).status_code == 403
        response = operator_client.get(_url(route), **HEADERS)
        assert response.status_code == 403
        assert response.json()["code"] == "not-family-node"


def test_hardware_before_any_report_is_never(
    owned: dict[str, Any], operator_client: APIClient
) -> None:
    body = operator_client.get(_url("operator_hardware"), **HEADERS).json()
    assert body["verified"] is False
    assert body["reported_at"] is None
    assert {s["status"] for s in body["sections"].values()} == {"never"}


def test_hardware_serves_each_section_with_its_status(
    owned: dict[str, Any], operator_client: APIClient
) -> None:
    _section("system", {"status": "ok", "vendor": "Dell Inc.", "serial": "SER1"})
    _section("sensors", {"status": "timeout", "temperatures": []})
    # Counters every 6 h: stale past 13 h. Daily sections: past 26 h.
    _section("software", {"status": "ok", "kernel": "7.0"}, age=timedelta(hours=14))
    _section("cpu", {"status": "partial", "cores": 24}, age=timedelta(hours=14))
    response = operator_client.get(_url("operator_hardware"), **HEADERS)
    assert response.status_code == 200
    sections = response.json()["sections"]
    assert sections["system"]["status"] == "ok"
    assert sections["system"]["data"] == {"vendor": "Dell Inc.", "serial": "SER1"}
    assert sections["sensors"]["status"] == "timeout"
    assert sections["software"]["status"] == "stale"
    assert sections["software"]["reported_status"] == "ok"
    assert sections["cpu"]["status"] == "partial"
    assert sections["pci"]["status"] == "never"


def test_history_is_newest_first_and_bounded(
    owned: dict[str, Any], operator_client: APIClient
) -> None:
    now = timezone.now()
    for i, section in enumerate(("system", "software", "memory")):
        HostInventoryChange.objects.create(
            miner_node_id=NODE, section=section, at=now + timedelta(minutes=i), fields=["x"]
        )
    body = operator_client.get(_url("operator_hardware_history") + "?limit=2", **HEADERS).json()
    assert [c["section"] for c in body["changes"]] == ["memory", "software"]
    bad = operator_client.get(_url("operator_hardware_history") + "?limit=0", **HEADERS)
    assert bad.status_code == 400


def test_disk_inventory_cross_checks_vali_records(
    owned: dict[str, Any], operator_client: APIClient
) -> None:
    for pool in ("default", "nvme0", "hdd0", "gone"):
        MinerStoragePool.objects.create(miner_node_id=NODE, pool_id=pool, declared_class="hdd")
    MinerStoragePool.objects.filter(pool_id="gone").update(retired_at=timezone.now())
    DedicatedDisk.objects.create(miner_node_id=NODE, disk_id="wwn-0x1", state="pending_probe")
    DedicatedDisk.objects.create(miner_node_id=NODE, disk_id="wwn-0x2", state="free")
    DedicatedDisk.objects.create(
        miner_node_id=NODE, disk_id="wwn-0x9", state=DedicatedDiskState.RETIRED
    )
    # vali already knows it vanished: no second flag.
    DedicatedDisk.objects.create(
        miner_node_id=NODE, disk_id="wwn-0x8", state=DedicatedDiskState.FAILED
    )
    _storage(
        [
            # Two pools on one filesystem; `default` (state root) not listed.
            _device("md127", "pool_backing", pools=["nvme0", "scratch"]),
            _device("nvme9n1", "pool_backing", pools=["ghost"]),
            _device("sda", "dedicated_assigned", ids=["ata-M_S1", "wwn-0x1"]),
            _device("sdb", "dedicated_free", ids=["wwn-0x7"]),
        ]
    )
    body = operator_client.get(_url("operator_disk_inventory"), **HEADERS).json()
    assert body["verified"] is False
    assert body["status"] == "ok"
    assert [d["name"] for d in body["devices"]] == ["md127", "nvme9n1", "sda", "sdb"]
    assert {
        (m["kind"], m["device"], m["pool_id"], m["disk_id"])
        for m in body["cross_check"]["mismatches"]
    } == {
        ("pool_not_declared", "md127", "scratch", None),
        ("pool_not_declared", "nvme9n1", "ghost", None),
        ("dedicated_not_declared", "sdb", None, None),
        ("pool_not_reported", None, "hdd0", None),
        ("dedicated_not_reported", None, None, "wwn-0x2"),
    }


@pytest.mark.parametrize(("status", "truncated"), [("partial", False), ("ok", True)])
def test_an_incomplete_report_flags_nothing_missing(
    owned: dict[str, Any], operator_client: APIClient, status: str, truncated: bool
) -> None:
    MinerStoragePool.objects.create(miner_node_id=NODE, pool_id="hdd0", declared_class="hdd")
    DedicatedDisk.objects.create(miner_node_id=NODE, disk_id="wwn-0x1", state="free")
    # A trimmed report may have cut the dedicated disk's by-id names.
    devices = [_device("sda", "dedicated_free", ids=["ata-M_S1"])] if truncated else []
    _storage(devices, status=status, truncated=truncated)
    body = operator_client.get(_url("operator_disk_inventory"), **HEADERS).json()
    assert body["cross_check"]["mismatches"] == []


def test_disk_inventory_before_any_report(
    owned: dict[str, Any], operator_client: APIClient
) -> None:
    MinerStoragePool.objects.create(miner_node_id=NODE, pool_id="hdd0", declared_class="hdd")
    body = operator_client.get(_url("operator_disk_inventory"), **HEADERS).json()
    assert (body["status"], body["devices"], body["cross_check"]) == (
        "never",
        [],
        {"mismatches": []},
    )


# ─── serial redaction ────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("line", "want"),
    [
        (
            '{"serial": "KATSERIAL1", "vendor": "Dell"}',
            '{"serial": "<redacted>", "vendor": "Dell"}',
        ),
        ("product_serial=ABC123 ok", 'product_serial="<redacted>" ok'),
        ("disk wwn-0x5000c500a1b2c3d4 failed", "disk <by-id> failed"),
        ("ids=['ata-KATMODEL_KATSERIAL2']", "ids=['<by-id>']"),
        ("nvme-cli 2.9 missing; serials: 3", "nvme-cli 2.9 missing; serials: 3"),
    ],
)
def test_redact(line: str, want: str) -> None:
    assert redact(line) == want


def test_every_vali_handler_redacts_serials() -> None:
    logging_cfg = settings.LOGGING
    assert (
        logging_cfg["filters"]["redact_serials"]["()"] == "vali.log_filters.SerialRedactionFilter"
    )
    for name, handler in logging_cfg["handlers"].items():
        assert "redact_serials" in handler.get("filters", []), name
    out = io.StringIO()
    handler = logging.StreamHandler(out)
    handler.addFilter(SerialRedactionFilter())
    log = logging.getLogger("apps.disktier.tests.redaction")
    log.addHandler(handler)
    log.propagate = False
    try:
        log.warning("body %s", {"serial": "KATDIMM01", "ids": ["wwn-0x5000c500a1b2c3d4"]})
    finally:
        log.removeHandler(handler)
    assert "KATDIMM01" not in out.getvalue()
    assert "wwn-0x5000c500a1b2c3d4" not in out.getvalue()


def test_a_traceback_quoting_a_body_is_redacted() -> None:
    out = io.StringIO()
    handler = logging.StreamHandler(out)
    handler.addFilter(SerialRedactionFilter())
    log = logging.getLogger("apps.disktier.tests.redaction.exc")
    log.addHandler(handler)
    log.propagate = False
    try:
        try:
            raise ValueError('{"serial": "S3CR3T", "ids": ["nvme-SAMSUNG_MZ7_S3CR3T2"]}')
        except ValueError:
            log.exception("merge failed")
        # A malformed call stays the handler's to report, not the caller's crash.
        log.error("%s %s", "only-one")
    finally:
        log.removeHandler(handler)
    text = out.getvalue()
    assert "merge failed" in text and "ValueError" in text
    assert "S3CR3T" not in text


def test_redaction_is_linear_on_hostile_input() -> None:
    import time

    started = time.monotonic()
    redact("ata-" * 16_384)
    redact("x" * 65_536 + "serial")
    assert time.monotonic() - started < 1.0
