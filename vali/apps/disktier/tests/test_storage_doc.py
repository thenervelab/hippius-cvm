"""The desired storage document's static checks mirror the agent's
(`binaries/miner-agent/src/storage/remote.rs::validate_static`), codes
included."""

from __future__ import annotations

import json
from typing import Any

import pytest

from apps.disktier import storage_doc
from apps.disktier.storage_doc import DocError, normalize


def _pool(pool_id: str = "default", **over: Any) -> dict[str, Any]:
    pool = {
        "id": pool_id,
        "path": "/var/lib/hippius-miner" if pool_id == "default" else f"/srv/{pool_id}",
        "class": "nvme",
        "budget_gb": 3000 if pool_id == "default" else 500,
        "os_disks": True,
        "state": "active",
    }
    pool.update(over)
    return pool


def _doc(*pools: dict[str, Any], disks: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    out: dict[str, Any] = {"pools": list(pools) or [_pool()]}
    if disks is not None:
        out["dedicated_disks"] = disks
    return out


def _code(raw: Any, **kw: Any) -> tuple[str, str, str]:
    with pytest.raises(DocError) as err:
        normalize(raw, **kw)
    return err.value.code, err.value.pool, err.value.disk


def test_a_valid_document_is_sorted_and_canonical() -> None:
    doc = normalize(
        _doc(
            _pool("hdd0", **{"class": "hdd"}),
            _pool(),
            disks=[
                {"id": "wwn-0x5000c500a1b2c3d4", "state": "active"},
                {"id": "ata-ST18000NM000J_ZR5ABCDE", "state": "draining"},
            ],
        )
    )
    assert [p["id"] for p in doc["pools"]] == ["default", "hdd0"]
    assert [d["id"] for d in doc["dedicated_disks"]] == [
        "ata-ST18000NM000J_ZR5ABCDE",
        "wwn-0x5000c500a1b2c3d4",
    ]
    # Same content, any order ⇒ same key.
    again = normalize(
        _doc(
            _pool(), _pool("hdd0", **{"class": "hdd"}), disks=list(reversed(doc["dedicated_disks"]))
        )
    )
    assert storage_doc.content_key(doc) == storage_doc.content_key(again)


def test_dedicated_disks_default_to_empty() -> None:
    assert normalize(_doc())["dedicated_disks"] == []


@pytest.mark.parametrize(
    ("raw", "code", "pool"),
    [
        (_doc(_pool(), _pool("Bad")), "pool-id-invalid", "Bad"),
        (_doc(_pool(), _pool("x" * 33)), "pool-id-invalid", "x" * 32),
        (_doc(_pool(), _pool("a"), _pool("a", path="/srv/a2")), "pool-id-invalid", "a"),
        (_doc(_pool(), *[_pool(f"p{i}") for i in range(4)]), "too-many-pools", ""),
        (_doc(_pool(), _pool("a", path="srv/a")), "pool-path-invalid", "a"),
        (_doc(_pool(), _pool("a", path="/srv/a/")), "pool-path-invalid", "a"),
        (_doc(_pool(), _pool("a", path="/srv//a")), "pool-path-invalid", "a"),
        (_doc(_pool(), _pool("a", path="/srv/./a")), "pool-path-invalid", "a"),
        (_doc(_pool(), _pool("a", path="/srv/../a")), "pool-path-invalid", "a"),
        (_doc(_pool(), _pool("a", path=7)), "pool-path-invalid", "a"),
        (_doc(_pool(), _pool("a", path="/var/lib/hippius-miner")), "pool-shared-fs", "default"),
        (_doc(_pool(), _pool("a", budget_gb=0)), "pool-budget-invalid", "a"),
        (_doc(_pool(), _pool("a", budget_gb=-1)), "pool-budget-invalid", "a"),
        (_doc(_pool(), _pool("a", budget_gb=2**32)), "pool-budget-invalid", "a"),
        (_doc(_pool(), _pool("a", budget_gb=True)), "pool-budget-invalid", "a"),
        (_doc(_pool(), _pool("a", **{"class": "tape"})), "pool-class-invalid", "a"),
        (_doc(_pool(), _pool("a", state="gone")), "pool-state-invalid", "a"),
        (_doc(_pool("a")), "pool-default-required", "default"),
        (_doc(_pool(state="draining")), "pool-conflicts-local", "default"),
        (_doc(_pool(os_disks=False)), "pool-conflicts-local", "default"),
        (_doc(_pool(), {"id": "a"}), "storage-config-malformed", "a"),
        (_doc(_pool(), {**_pool("a"), "extra": 1}), "storage-config-malformed", "a"),
        (_doc(_pool(), _pool("a", os_disks="yes")), "storage-config-malformed", "a"),
    ],
)
def test_pool_refusals_carry_the_agents_code(raw: Any, code: str, pool: str) -> None:
    got = _code(raw)
    assert got[:2] == (code, pool)


def test_shared_path_names_the_later_pool_in_id_order() -> None:
    # The agent walks pools in id order and names the second holder.
    assert _code(_doc(_pool(), _pool("zz", path="/var/lib/hippius-miner")))[:2] == (
        "pool-shared-fs",
        "zz",
    )


@pytest.mark.parametrize(
    ("disks", "code", "disk"),
    [
        ([{"id": "sda", "state": "active"}], "disk-id-invalid", "sda"),
        ([{"id": "wwn-", "state": "active"}], "disk-id-invalid", "wwn-"),
        (
            [{"id": "wwn-0x5000c500a1b2c3d4-part1", "state": "active"}],
            "disk-id-invalid",
            "wwn-0x5000c500a1b2c3d4-part1",
        ),
        ([{"id": "wwn-0x5000/../x", "state": "active"}], "disk-id-invalid", "wwn-0x5000/../x"),
        ([{"id": "wwn-" + "a" * 93, "state": "active"}], "disk-id-invalid", "wwn-" + "a" * 92),
        (
            [{"id": "wwn-1", "state": "active"}, {"id": "wwn-1", "state": "draining"}],
            "disk-duplicate",
            "wwn-1",
        ),
        ([{"id": f"wwn-{i}", "state": "active"} for i in range(25)], "too-many-disks", ""),
        ([{"id": "wwn-1", "state": "free"}], "disk-state-invalid", "wwn-1"),
        ([{"id": "wwn-1"}], "storage-config-malformed", "wwn-1"),
    ],
)
def test_disk_refusals_carry_the_agents_code(
    disks: list[dict[str, Any]], code: str, disk: str
) -> None:
    got = _code(_doc(disks=disks))
    assert (got[0], got[2]) == (code, disk)


def test_a_partition_like_name_that_is_not_a_partition_is_a_disk() -> None:
    for disk_id in ("wwn-0x5000-part", "nvme-Samsung-partX", "scsi-0QEMU_drive-part1a"):
        assert storage_doc.is_valid_dedicated_disk_id(disk_id), disk_id


def test_twenty_four_disks_are_accepted() -> None:
    disks = [{"id": f"wwn-{i:02d}", "state": "active"} for i in range(24)]
    assert len(normalize(_doc(disks=disks))["dedicated_disks"]) == 24


@pytest.mark.parametrize(
    "raw",
    [[], {"pools": "x"}, {"dedicated_disks": []}, {"pools": [], "other": 1}, {"pools": [1]}],
)
def test_a_malformed_document_is_refused(raw: Any) -> None:
    assert _code(raw)[0] in ("storage-config-malformed", "pool-default-required")


def test_the_default_budget_must_be_the_reported_host_budget() -> None:
    assert normalize(_doc(), default_budget_gb=3000)
    assert _code(_doc(), default_budget_gb=2000)[:2] == ("pool-conflicts-local", "default")


def test_root_is_a_plain_path_the_host_check_judges() -> None:
    assert storage_doc.is_plain_absolute("/")
    assert not storage_doc.is_plain_absolute("")
    assert not storage_doc.is_plain_absolute("/a\x00b")


def test_the_order_payload_matches_the_shared_vector_layout() -> None:
    doc = normalize(_doc())
    body = json.loads(storage_doc.order_payload(doc, revision=3, not_after_unix=9, dry_run=True))
    assert set(body) == {"revision", "not_after_unix", "dry_run", "pools", "dedicated_disks"}
    assert body["dry_run"] is True and body["revision"] == 3


def test_the_accepted_default_path_is_kept() -> None:
    assert normalize(_doc(), default_path="/var/lib/hippius-miner")
    assert _code(_doc(), default_path="/srv/elsewhere")[:2] == ("pool-conflicts-local", "default")


def test_a_pool_holding_disks_can_be_drained_not_moved_or_removed() -> None:
    held = {"hdd0": "/srv/hdd0"}
    assert normalize(_doc(_pool(), _pool("hdd0", state="draining")), held_paths=held)
    assert _code(_doc(_pool(), _pool("hdd0", path="/srv/x")), held_paths=held)[:2] == (
        "pool-has-disks",
        "hdd0",
    )
    assert _code(_doc(_pool()), held_paths=held)[:2] == ("pool-has-disks", "hdd0")
