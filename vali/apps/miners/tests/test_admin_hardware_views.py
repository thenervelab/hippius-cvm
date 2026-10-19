"""`GET /v1/admin/miner/<miner_id>/hardware|hardware/history|disk-inventory|
host-disk-advisories` — the miner-admin support reads of a miner's host
inventory (`apps.miners.hardware_views`): the operator readouts, resolved
from the miner id, with every serial and by-id name WITHHELD."""

from __future__ import annotations

import json
from datetime import timedelta
from typing import Any

import pytest
from django.utils import timezone
from rest_framework.test import APIClient

from apps.disktier.models import (
    DedicatedDisk,
    HostDiskAdvisory,
    HostDiskAdvisoryEvent,
    HostInventoryChange,
    HostInventorySection,
)
from apps.disktier.withhold import WITHHELD_PREFIX, withhold
from apps.miners.models import MinerIdentity, MinerStatus

pytestmark = pytest.mark.django_db()

NODE = "ab" * 32
MINER = "miner-x"
BASE = f"/v1/admin/miner/{MINER}"
ROUTES = ("hardware", "hardware/history", "disk-inventory", "host-disk-advisories")

# Every owner-only identifier the fixture plants. None may appear in a body.
SYSTEM_SERIAL = "KATSYS0001"
BOARD_SERIAL = "KATBOARD002"
DIMM_SERIALS = ("KATDIMM0003", "KATDIMM0004")
PSU_SERIAL = "KATPSU00005"
DISK_SERIAL = "KATDISK0006"
NVME_SERIAL = "KATNVME0007"
BY_IDS = (
    f"ata-KATMODEL_{DISK_SERIAL}",
    "wwn-0x5000c500a1b2c3d4",
    f"nvme-KATNVMEMODEL_{NVME_SERIAL}",
    "nvme-eui.0025388b91b2c3d4",
)
DEDICATED_ONLY = "scsi-35000c500deadbeef"  # vali knows it, the report does not list it
# Too short for the by-id shape: only the known set (the report's ids, vali's
# dedicated disks) catches these.
SHORT_REPORTED = "wwn-0x9"
SHORT_DEDICATED = "wwn-0x8"
# udev keeps `+ # = @` and `\xNN` escapes in a by-id name: the log filter's
# shape misses these. Advisory subjects vali never recorded (the agent's own
# dedicated config, the disk since pulled from the report).
UNKNOWN_SUBJECT = "ata-WDC+WD40EFRX_WD-WCC7K1234567"
UNKNOWN_IN_TEXT = "ata-ST4000\\x20NM_ZC12AB34"
# A pool id shaped like a by-id name (prefix, 6+ chars, a digit): kept.
POOL = "nvme-fast01"
SECRETS = (
    SYSTEM_SERIAL,
    BOARD_SERIAL,
    *DIMM_SERIALS,
    PSU_SERIAL,
    DISK_SERIAL,
    NVME_SERIAL,
    *BY_IDS,
    DEDICATED_ONLY,
    SHORT_REPORTED,
    SHORT_DEDICATED,
    UNKNOWN_SUBJECT,
    "WCC7K1234567",
    UNKNOWN_IN_TEXT,
    "ZC12AB34",
)


def _section(name: str, body: dict[str, Any]) -> None:
    now = timezone.now()
    HostInventorySection.objects.create(
        miner_node_id=NODE,
        section=name,
        digest="0" * 64,
        body=body,
        status=body.get("status", ""),
        reported_at=now,
        sequence=1,
        received_at=now,
    )


def _device(name: str, ids: list[str], role: str = "dedicated_free") -> dict[str, Any]:
    return {
        "name": name,
        "kind": "disk",
        "size_bytes": 4 * 10**12,
        "ids": ids,
        "model": "KATMODEL",
        "transport": "sata",
        "role": role,
        "pool_ids": [],
        "partitions": [],
        "holders": [],
        "mounts": [],
        "reasons": [],
    }


@pytest.fixture
def host() -> None:
    """A miner with every section reported, serials everywhere they occur,
    a dedicated disk, advisories on by-id subjects, history."""
    MinerIdentity.objects.create(
        miner_id=MINER,
        pubkey_hex="cd" * 32,
        platform_id="ef" * 64,
        chain_node_id=NODE,
        status=MinerStatus.ACTIVE,
    )
    _section(
        "system",
        {
            "status": "ok",
            "vendor": "KATVENDOR",
            "product": "KATPRODUCT",
            "serial": SYSTEM_SERIAL,
            "board_serial": BOARD_SERIAL,
            "bios_version": "1.2.3",
            "bmc_present": True,
        },
    )
    _section(
        "memory",
        {
            "status": "ok",
            "total_mib": 262_144,
            "dimms": [
                {"locator": "DIMM A1", "size_mib": 32_768, "ecc": "multi_bit", "serial": s}
                for s in DIMM_SERIALS
            ],
        },
    )
    _section(
        "storage",
        {
            "status": "ok",
            "devices": [
                _device("sda", [BY_IDS[0], BY_IDS[1], SHORT_REPORTED]),
                _device("nvme0n1", [BY_IDS[2], BY_IDS[3]], role="pool_backing")
                | {"pool_ids": [POOL]},
            ],
            "advisories": [],
            "advisories_truncated": False,
            "devices_truncated": False,
        },
    )
    _section(
        "sensors",
        {"status": "ok", "psus": [{"label": "PSU1", "state": "ok", "Serial_Number": PSU_SERIAL}]},
    )
    DedicatedDisk.objects.create(miner_node_id=NODE, disk_id=BY_IDS[0], state="free")
    DedicatedDisk.objects.create(miner_node_id=NODE, disk_id=DEDICATED_ONLY, state="free")
    DedicatedDisk.objects.create(miner_node_id=NODE, disk_id=SHORT_DEDICATED, state="free")
    now = timezone.now()
    for kind, ref, sample in (
        ("dedicated_disk", BY_IDS[0], f"reallocated sectors on {BY_IDS[0]}: 12"),
        ("device", "nvme0n1", f"media errors on {BY_IDS[2]} serial={NVME_SERIAL}"),
        ("pool", POOL, "pool mount read-only"),
        ("dedicated_disk", SHORT_DEDICATED, f"{SHORT_REPORTED} and {SHORT_DEDICATED} timing out"),
        ("dedicated_disk", UNKNOWN_SUBJECT, f"io errors on x_{UNKNOWN_IN_TEXT}"),
    ):
        HostDiskAdvisory.objects.create(
            miner_node_id=NODE,
            subject_kind=kind,
            subject_ref=ref,
            code="reallocated_sectors",
            severity="warning",
            count=12,
            first_seen=now,
            last_seen=now,
            sample=sample,
            updated_at=now,
        )
        HostDiskAdvisoryEvent.objects.create(
            miner_node_id=NODE,
            subject_kind=kind,
            subject_ref=ref,
            code="reallocated_sectors",
            transition="opened",
            severity="warning",
            at=now,
        )
    HostInventoryChange.objects.create(
        miner_node_id=NODE, section="memory", at=now - timedelta(hours=1), fields=["dimms"]
    )


def _get(client: APIClient, route: str, query: str = "") -> Any:
    return client.get(f"{BASE}/{route}{query}")


def _keys(value: Any) -> list[str]:
    if isinstance(value, dict):
        return [*value, *(k for v in value.values() for k in _keys(v))]
    if isinstance(value, list):
        return [k for v in value for k in _keys(v)]
    return []


# ─── auth, methods, resolution ───────────────────────────────────────


@pytest.mark.parametrize("route", ROUTES)
def test_only_the_miner_admin(route: str, host: None, plain_client: APIClient) -> None:
    assert _get(plain_client, route).status_code == 403
    assert APIClient().get(f"{BASE}/{route}").status_code == 401


@pytest.mark.parametrize("route", ROUTES)
@pytest.mark.parametrize("method", ["post", "put", "patch", "delete"])
def test_read_only(route: str, method: str, host: None, admin_client: APIClient) -> None:
    resp = getattr(admin_client, method)(f"{BASE}/{route}", {}, format="json")
    assert resp.status_code == 405


@pytest.mark.parametrize("route", ROUTES)
def test_unknown_or_unbridged_miner_is_404(route: str, host: None, admin_client: APIClient) -> None:
    assert admin_client.get(f"/v1/admin/miner/nobody/{route}").status_code == 404
    MinerIdentity.objects.create(
        miner_id="unbridged", pubkey_hex="ee" * 32, platform_id="ff" * 64, chain_node_id=None
    )
    resp = admin_client.get(f"/v1/admin/miner/unbridged/{route}")
    assert resp.status_code == 404
    assert resp.json()["category"] == "not-found"


# ─── the readouts ────────────────────────────────────────────────────


def test_hardware_is_the_operator_readout_with_serials_withheld(
    host: None, admin_client: APIClient
) -> None:
    resp = _get(admin_client, "hardware")
    assert resp.status_code == 200, resp.content
    body = resp.json()
    assert body["miner_id"] == MINER and body["node_id"] == NODE
    assert body["verified"] is False
    system = body["sections"]["system"]["data"]
    assert system["vendor"] == "KATVENDOR" and "serial" not in system
    assert "board_serial" not in system
    dimm = body["sections"]["memory"]["data"]["dimms"][0]
    assert dimm["locator"] == "DIMM A1" and dimm["size_mib"] == 32_768
    assert "serial" not in dimm
    devices = body["sections"]["storage"]["data"]["devices"]
    assert all(i.startswith(WITHHELD_PREFIX) for d in devices for i in d["ids"])
    assert devices[0]["model"] == "KATMODEL"
    # Pool ids are not by-id names, even shaped like one.
    assert devices[1]["pool_ids"] == [POOL]
    assert "attested" in body


def test_disk_inventory_withholds_ids_and_cross_check_names(
    host: None, admin_client: APIClient
) -> None:
    body = _get(admin_client, "disk-inventory").json()
    assert [d["name"] for d in body["devices"]] == ["sda", "nvme0n1"]
    mismatches = body["cross_check"]["mismatches"]
    # The dedicated disk vali holds but the report does not list is flagged …
    assert mismatches, body
    # … by its handle, the same one wherever the disk appears.
    handle = withhold(DEDICATED_ONLY, node_id=NODE)
    assert handle.startswith(WITHHELD_PREFIX)
    assert handle in json.dumps(mismatches)


def test_advisories_withhold_subjects_samples_and_history(
    host: None, admin_client: APIClient
) -> None:
    body = _get(admin_client, "host-disk-advisories", "?history_days=1").json()
    others = {withhold(n, node_id=NODE) for n in (SHORT_DEDICATED, UNKNOWN_SUBJECT)}
    refs = {s["kind"]: s["ref"] for s in body["subjects"] if s["ref"] not in others}
    assert refs["dedicated_disk"].startswith(WITHHELD_PREFIX)
    assert refs["device"] == "nvme0n1"
    assert refs["pool"] == POOL
    # A disk reads the same handle in the advisories as in the disk list.
    devices = _get(admin_client, "disk-inventory").json()["devices"]
    assert refs["dedicated_disk"] == devices[0]["ids"][0]
    history = {(e["kind"], e["subject"]) for e in body["history"]}
    assert ("dedicated_disk", refs["dedicated_disk"]) in history
    assert ("pool", POOL) in history


def test_history_is_served(host: None, admin_client: APIClient) -> None:
    body = _get(admin_client, "hardware/history").json()
    assert [(c["section"], c["fields"]) for c in body["changes"]] == [("memory", ["dimms"])]


@pytest.mark.parametrize(
    ("route", "query"),
    [
        ("hardware/history", "?limit=0"),
        ("host-disk-advisories", "?include_resolved=maybe"),
        ("host-disk-advisories", "?history_days=9999"),
    ],
)
def test_bad_query_is_400(route: str, query: str, host: None, admin_client: APIClient) -> None:
    assert _get(admin_client, route, query).status_code == 400


# ─── no serial leaks, anywhere ───────────────────────────────────────


@pytest.mark.parametrize("route", ROUTES)
def test_no_serial_and_no_by_id_name_leaks(route: str, host: None, admin_client: APIClient) -> None:
    query = "?include_resolved=true&history_days=30" if route == "host-disk-advisories" else ""
    resp = _get(admin_client, route, query)
    assert resp.status_code == 200, resp.content
    body = resp.json()
    assert not [k for k in _keys(body) if "serial" in k.lower()]
    text = resp.content.decode()
    leaked = [s for s in SECRETS if s in text]
    assert leaked == [], leaked


def test_the_owner_route_still_serves_them(host: None) -> None:
    """The withholding is the admin routes' alone: the readout itself is
    untouched (the owner-scoped operator routes serve it as is)."""
    from apps.disktier.hardware_views import hardware_readout

    readout = hardware_readout(NODE, now=timezone.now())
    assert readout["sections"]["system"]["data"]["serial"] == SYSTEM_SERIAL
    withheld = withhold(readout, node_id=NODE)
    assert "serial" not in withheld["sections"]["system"]["data"]
    assert readout["sections"]["system"]["data"]["serial"] == SYSTEM_SERIAL  # not mutated


def test_a_by_id_field_is_withheld_whatever_it_looks_like() -> None:
    """`ids`, `disk_id` and a dedicated-disk subject ARE by-id names: no
    shape test decides, unknown names and odd characters included."""
    out = withhold(
        {
            "ids": ["zz-anything#1", "short"],
            "disk_id": "nonstandard@name",
            "subjects": [{"kind": "dedicated_disk", "ref": "ata-a+b=c"}],
            "history": [{"kind": "dedicated_disk", "subject": "x"}],
        },
        node_id=NODE,
    )
    flat = [*out["ids"], out["disk_id"], out["subjects"][0]["ref"], out["history"][0]["subject"]]
    assert all(v.startswith(WITHHELD_PREFIX) for v in flat), flat


def test_withholding_is_linear_on_hostile_input() -> None:
    import time

    hostile = "nvme-" * 13_000  # ~64 KiB, the envelope cap
    start = time.monotonic()
    withhold({"sample": hostile, "ref": hostile}, node_id=NODE)
    assert time.monotonic() - start < 2.0


def test_handles_are_per_node() -> None:
    a = withhold(BY_IDS[1], node_id=NODE)
    b = withhold(BY_IDS[1], node_id="cd" * 32)
    assert a.startswith(WITHHELD_PREFIX) and b.startswith(WITHHELD_PREFIX) and a != b


# ─── schema ──────────────────────────────────────────────────────────


def test_published_in_the_openapi_schema() -> None:
    from drf_spectacular.generators import SchemaGenerator

    schema = SchemaGenerator().get_schema(request=None, public=True)
    paths = schema["paths"]
    for route in ROUTES:
        op = paths[f"/v1/admin/miner/{{miner_id}}/{route}"]
        assert set(op) - {"parameters"} == {"get"}, (route, set(op))
        assert "WITHHELD" in op["get"]["description"]
        ref = op["get"]["responses"]["200"]["content"]["application/json"]["schema"]["$ref"]
        component = ref.rsplit("/", 1)[1]
        assert "miner_id" in schema["components"]["schemas"][component]["properties"], component
