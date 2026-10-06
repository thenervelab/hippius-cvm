"""The restore orders vali builds, through the REAL `encode-order` binary.

The miner-agent decodes what `hippius-ticket-validator encode-order` emits,
and that encoder refuses a payload it does not know field by field. The
unit tests stub the subprocess, so a vali ⇄ encoder drift on the `restore`
kind or on `migrate-activate.staged_restore_id` would only surface on a
live miner. These run the real binary when it is built (as CI does).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from django.conf import settings

from apps.orchestration import order_dispatch

_REAL_BIN = Path(settings.VALI_TICKET_VALIDATOR_BIN)

pytestmark = pytest.mark.skipif(
    not _REAL_BIN.is_file(),
    reason=f"Rust validator not built at {_REAL_BIN}: cargo build -p hippius-ticket-validator",
)

RID = "0123456789abcdef0123456789abcdef"
GIB = 1 << 30
PART = 512 << 20


def _encode(kind: str, payload: dict) -> bytes:
    return order_dispatch._encode_order_body(
        order_id=f"{kind}-wire-test",
        kind=kind,
        target_miner_id="miner-wire-test",
        issued_at_unix=1_790_000_000,
        payload_json=json.dumps(payload).encode("utf-8"),
    )


def _piece(size: int, part_size: int, parts: int) -> dict:
    # The shape `backup.service.restore_chain` builds.
    return {
        "url": "https://s3.example/obj?sig=x",
        "sha256_hex": "a" * 64,
        "size": size,
        "part_size": part_size,
        "part_sha256_hex": ["b" * 64] * parts,
    }


def test_the_stage_order_vali_builds_encodes() -> None:
    chain = {
        "restore_id": RID,
        "full": _piece(2 * GIB, PART, 4),
        "incrementals": [_piece(3 << 20, 0, 0)],
        "state": _piece(1 << 20, 0, 0),
    }
    payload = {"vm_id": "vm-wire", "restore_id": RID, "op": "stage",
               "chain": chain, "disk_bytes": 2 * GIB, "streams": 8}
    body = _encode("restore", payload)
    assert b"restore" in body and b"part_sha256_hex" in body


@pytest.mark.parametrize("op", ["abort", "reclaim"])
def test_abort_and_reclaim_as_vali_sends_them_encode(op: str) -> None:
    # `restore._order(job, op, disk_bytes=0)`: no chain, no streams keys.
    body = _encode("restore", {"vm_id": "vm-wire", "restore_id": RID, "op": op,
                               "disk_bytes": 0})
    assert op.encode() in body and b"chain" not in body


def test_a_staged_migrate_activate_encodes_without_snapshot_urls() -> None:
    payload = order_dispatch.build_migrate_activate_payload(
        vm_id="vm-wire",
        get_url="",
        new_gen=3,
        ovmf_path="/var/lib/hippius-miner/ovmf/OVMF.fd",
        kernel_path="/var/lib/hippius-miner/k/vmlinuz",
        initrd_path="/var/lib/hippius-miner/k/initrd",
        cmdline="ro hippius.vm_generation=3 hippius.disk_gb=2",
        luks_disk_path="/var/lib/hippius-miner/disks/vm-wire.luks",
        luks_disk_size_gb=10,
        rootfs_data_path="/var/lib/hippius-miner/rootfs/data.img",
        rootfs_hash_path="/var/lib/hippius-miner/rootfs/hash.img",
        cpu_count=2,
        memory_mb=4096,
        cose_ticket=b"\x84\x40\xa0\x40\x40",
        staged_restore_id=RID,
    )
    body = _encode("migrate-activate", payload)
    assert b"staged_restore_id" in body and RID.encode() in body
