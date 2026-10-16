"""End-to-end: the committed heartbeat KAT envelopes → the REAL Rust
`verify-heartbeat` → `verifier.verify_heartbeat`.

The mock tests steer the verifier's JSON by hand; this one pins the
Rust→JSON→Python contract for the capacity-v2 `v3` fields against real
cryptography. If the subcommand renames a capacity key, emits them for a
`v1` body, or drops them for `v3`, the mocks stay happy and THIS fails.

Auto-skips when the binary is not built (`VALI_TICKET_VALIDATOR_BIN`).
"""

from __future__ import annotations

from pathlib import Path

import pytest
from django.conf import settings

from apps.telemetry import verifier

REPO_ROOT = Path(__file__).resolve().parents[4]
VECTORS = REPO_ROOT / "test_vectors" / "heartbeat"
_REAL_BIN = Path(settings.VALI_TICKET_VALIDATOR_BIN)

# The PUBLIC half of `KAT_SEED = [0x3B; 32]` pinned in
# `hippius-types/tests/heartbeat_kat.rs`.
KAT_VK = bytes.fromhex("cf1b37e85dc00aee94f10108b37f151e2a37b3ae2a0cae77521f83488db9c4d7")

pytestmark = pytest.mark.skipif(
    not _REAL_BIN.is_file(),
    reason=(
        f"Rust validator not built at {_REAL_BIN} — run "
        "`cargo build -p hippius-ticket-validator`"
    ),
)


def _verify(name: str) -> verifier.HeartbeatBody:
    return verifier.verify_heartbeat(
        envelope=(VECTORS / name).read_bytes(), verifying_key=KAT_VK
    )


def test_real_v3_vector_carries_the_capacity_declaration() -> None:
    hb = _verify("signed_heartbeat_v3.cbor")
    assert hb.schema_version == 3
    assert hb.miner_id == "miner-a"
    assert hb.memory_available_mib == 131_072
    assert hb.graceful_exit_requested is False
    assert hb.declared_capacity == verifier.DeclaredCapacity(
        cvm_cpu_budget=44, cvm_memory_mb_budget=120_000, asid_capacity=99, asid_used=2
    )


def test_real_v1_vector_carries_no_capacity_declaration() -> None:
    hb = _verify("signed_heartbeat.cbor")
    assert hb.schema_version == 1
    assert hb.declared_capacity is None


_V4_VECTOR = VECTORS / "signed_heartbeat_v4.cbor"


@pytest.mark.skipif(
    not _V4_VECTOR.is_file(),
    reason="no heartbeat-v4 KAT vector yet (ships with the miner-agent v4 PR)",
)
def test_real_v4_vector_carries_the_capacity_and_disk_figures() -> None:
    hb = _verify("signed_heartbeat_v4.cbor")
    assert hb.schema_version == 4
    assert hb.declared_capacity is not None
    assert hb.declared_disk is not None


def test_real_v3_vector_carries_no_disk_figures() -> None:
    assert _verify("signed_heartbeat_v3.cbor").declared_disk is None


def test_real_v5_vector_carries_the_host_health_report() -> None:
    hb = _verify("signed_heartbeat_v5.cbor")
    assert hb.schema_version == 5
    assert hb.declared_disk is not None
    assert hb.declared_host_health is not None
    assert hb.declared_host_health.snp_enabled is True
    assert hb.declared_host_health.cpus_offline == 24
    assert hb.declared_host_health.df_flush_failures == 3


def test_real_v4_vector_carries_no_host_health_report() -> None:
    assert _verify("signed_heartbeat_v4.cbor").declared_host_health is None


def test_real_v6_vector_carries_the_agent_version() -> None:
    hb = _verify("signed_heartbeat_v6.cbor")
    assert hb.schema_version == 6
    assert hb.agent_version == "v1.2.3"
    assert hb.declared_host_health is not None
    assert hb.declared_host_health.df_flush_failures == 3
    assert hb.declared_disk is not None


def test_real_v5_vector_carries_no_agent_version() -> None:
    assert _verify("signed_heartbeat_v5.cbor").agent_version is None


def test_real_v7_vector_carries_the_storage_report() -> None:
    hb = _verify("signed_heartbeat_v7.cbor")
    assert hb.schema_version == 7
    assert hb.agent_version == "v1.2.3"
    assert hb.declared_disk is not None  # the v4 scalars still arrive
    storage = hb.declared_storage
    assert storage is not None
    assert storage.storage_config_revision == 3
    assert [p.pool_id for p in storage.pools] == ["default", "hdd0"]
    assert storage.pools[1].state == "draining"
    assert storage.pools[1].error == "pool-not-a-mount"
    assert [d.disk_id for d in storage.dedicated_disks] == [
        "ata-ST18000NM000J_ZR5ABCDE",
        "wwn-0x5000c500a1b2c3d4",
    ]
    assert storage.dedicated_disks[1].vm == "vm-kat-1"


def test_real_v6_vector_carries_no_storage_report() -> None:
    assert _verify("signed_heartbeat_v6.cbor").declared_storage is None
