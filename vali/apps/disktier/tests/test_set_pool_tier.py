"""`vali_set_pool_tier` and the audited override writer behind it."""

from __future__ import annotations

import json
from io import StringIO

import pytest
from django.core.management import call_command
from django.core.management.base import CommandError
from django.db import transaction
from django.utils import timezone

from apps.disktier import override as override_mod
from apps.disktier.models import MinerStoragePool
from apps.scheduler.models import MinerCapacity, MinerCapacityAudit
from apps.scheduler.tests.factories import make_dispatchable_identity, node_id

pytestmark = pytest.mark.django_db

BY = "ops@example"


def _capacity(seed: int, **disk: object) -> MinerCapacity:
    return MinerCapacity.objects.create(
        miner_node_id=node_id(seed),
        status="active",
        observed_epoch=10,
        data_epoch=10,
        refreshed_at=timezone.now(),
        capacity_slots=4,
        **disk,
    )


def _run(*args: str) -> str:
    out = StringIO()
    call_command("vali_set_pool_tier", *args, stdout=out)
    return out.getvalue()


def _audits(seed: int) -> list[MinerCapacityAudit]:
    return list(
        MinerCapacityAudit.objects.filter(miner_node_id=node_id(seed)).order_by("created_at")
    )


# ─── set / clear ─────────────────────────────────────────────────────


def test_override_is_set_and_audited() -> None:
    MinerStoragePool.objects.create(miner_node_id=node_id(1), pool_id="nvme0", tier="nvme")
    out = _run(
        "--node-id",
        node_id(1),
        "--pool",
        "nvme0",
        "--override",
        "unfit",
        "--by",
        BY,
        "--reason",
        "controller errors",
    )

    pool = MinerStoragePool.objects.get(miner_node_id=node_id(1), pool_id="nvme0")
    assert pool.operator_override == "unfit"
    assert pool.override_reason == "controller errors"
    assert pool.tier == "nvme"  # the probe verdict is untouched
    assert pool.effective_tier == "unfit"

    (row,) = _audits(1)
    assert row.actor == f"op:{BY}"
    assert row.field == "disk_tier_override:nvme0"
    assert row.before == {"override": "", "reason": ""}
    assert row.after == {"override": "unfit", "reason": "controller errors"}
    assert row.reason == "controller errors"

    echoed = json.loads(out.strip().splitlines()[-1])
    assert echoed["after"] == "unfit" and echoed["pool_id"] == "nvme0"
    assert echoed["dry_run"] is False


def test_clear_is_audited() -> None:
    MinerStoragePool.objects.create(
        miner_node_id=node_id(1),
        pool_id="nvme0",
        operator_override="hdd",
        override_reason="old",
    )
    _run(
        "--node-id",
        node_id(1),
        "--pool",
        "nvme0",
        "--clear",
        "--by",
        BY,
        "--reason",
        "probe can decide again",
    )

    pool = MinerStoragePool.objects.get(miner_node_id=node_id(1), pool_id="nvme0")
    assert pool.operator_override == ""
    assert pool.override_reason == ""
    (row,) = _audits(1)
    assert row.before == {"override": "hdd", "reason": "old"}
    assert row.after == {"override": "", "reason": ""}
    assert row.reason == "probe can decide again"


def test_changing_the_override_audits_both_sides() -> None:
    MinerStoragePool.objects.create(
        miner_node_id=node_id(1), pool_id="p", operator_override="hdd", override_reason="a"
    )
    _run("--node-id", node_id(1), "--pool", "p", "--override", "ssd", "--by", BY, "--reason", "b")
    (row,) = _audits(1)
    assert row.before == {"override": "hdd", "reason": "a"}
    assert row.after == {"override": "ssd", "reason": "b"}


def test_a_repeated_override_writes_nothing() -> None:
    MinerStoragePool.objects.create(miner_node_id=node_id(1), pool_id="p")
    args = (
        "--node-id",
        node_id(1),
        "--pool",
        "p",
        "--override",
        "hdd",
        "--by",
        BY,
        "--reason",
        "same",
    )
    _run(*args)
    out = _run(*args)
    assert "no change" in out
    assert len(_audits(1)) == 1


def test_clearing_nothing_writes_nothing() -> None:
    MinerStoragePool.objects.create(miner_node_id=node_id(1), pool_id="p")
    out = _run("--node-id", node_id(1), "--pool", "p", "--clear", "--by", BY, "--reason", "x")
    assert "no change" in out
    assert _audits(1) == []


def test_resolves_a_miner_id() -> None:
    identity = make_dispatchable_identity(4)
    MinerStoragePool.objects.create(miner_node_id=identity.chain_node_id, pool_id="p")
    _run(
        "--miner-id",
        identity.miner_id,
        "--pool",
        "p",
        "--override",
        "ssd",
        "--by",
        BY,
        "--reason",
        "r",
    )
    assert MinerStoragePool.objects.get(pool_id="p").operator_override == "ssd"


# ─── the implicit default pool ───────────────────────────────────────


def test_the_default_pool_is_created_for_a_known_node() -> None:
    _capacity(1)
    _run(
        "--node-id",
        node_id(1),
        "--pool",
        "default",
        "--override",
        "ssd",
        "--by",
        BY,
        "--reason",
        "pin while the probe ships",
    )
    pool = MinerStoragePool.objects.get(miner_node_id=node_id(1), pool_id="default")
    assert pool.tier == "unknown"
    assert pool.operator_override == "ssd"
    assert len(_audits(1)) == 1


def test_the_default_pool_is_seeded_from_the_nodes_disk_columns() -> None:
    reported_at = timezone.now()
    _capacity(
        1,
        reported_data_disk_total_gb=3500,
        reported_data_disk_available_gb=2100,
        declared_disk_gb_budget=3000,
        earned_disk_gb=1200,
        disk_reported_at=reported_at,
        total_disk_gb=3400,
    )
    _run(
        "--node-id",
        node_id(1),
        "--pool",
        "default",
        "--override",
        "ssd",
        "--by",
        BY,
        "--reason",
        "r",
    )
    pool = MinerStoragePool.objects.get(miner_node_id=node_id(1), pool_id="default")
    assert (pool.total_gb, pool.available_gb, pool.budget_gb, pool.earned_gb) == (
        3500,
        2100,
        3000,
        1200,
    )
    assert pool.reported_at == reported_at


def test_an_existing_default_pool_is_not_reseeded() -> None:
    _capacity(1, reported_data_disk_total_gb=3500)
    MinerStoragePool.objects.create(miner_node_id=node_id(1), pool_id="default", total_gb=900)
    _run(
        "--node-id",
        node_id(1),
        "--pool",
        "default",
        "--override",
        "ssd",
        "--by",
        BY,
        "--reason",
        "r",
    )
    assert MinerStoragePool.objects.get(pool_id="default").total_gb == 900


def test_the_default_pool_is_not_created_for_an_unknown_node() -> None:
    with pytest.raises(CommandError, match="no MinerCapacity"):
        _run(
            "--node-id",
            node_id(1),
            "--pool",
            "default",
            "--override",
            "ssd",
            "--by",
            BY,
            "--reason",
            "r",
        )
    assert not MinerStoragePool.objects.exists()


def test_a_clear_never_creates_the_default_pool() -> None:
    _capacity(1)
    out = _run("--node-id", node_id(1), "--pool", "default", "--clear", "--by", BY, "--reason", "r")
    assert "no change" in out
    assert not MinerStoragePool.objects.exists()
    assert _audits(1) == []


def test_any_other_missing_pool_is_refused() -> None:
    _capacity(1)
    with pytest.raises(CommandError, match="no pool 'hdd0'"):
        _run(
            "--node-id",
            node_id(1),
            "--pool",
            "hdd0",
            "--override",
            "hdd",
            "--by",
            BY,
            "--reason",
            "r",
        )
    assert not MinerStoragePool.objects.exists()


# ─── refusals ────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("extra", "message"),
    [
        (("--reason", "r"), "--by"),
        (("--by", BY), "--reason"),
    ],
)
def test_a_real_write_needs_by_and_reason(extra: tuple[str, ...], message: str) -> None:
    MinerStoragePool.objects.create(miner_node_id=node_id(1), pool_id="p")
    with pytest.raises(CommandError, match=message):
        _run("--node-id", node_id(1), "--pool", "p", "--override", "hdd", *extra)
    assert _audits(1) == []


def test_nothing_to_do_is_refused() -> None:
    with pytest.raises(CommandError, match="nothing to do"):
        _run("--node-id", node_id(1), "--pool", "p")


def test_unknown_is_not_an_override_tier() -> None:
    with pytest.raises(CommandError):
        _run(
            "--node-id",
            node_id(1),
            "--pool",
            "p",
            "--override",
            "unknown",
            "--by",
            BY,
            "--reason",
            "r",
        )


@pytest.mark.parametrize("pool", ["Default", "a/b", "x" * 33, ""])
def test_malformed_pool_id_is_refused(pool: str) -> None:
    with pytest.raises(CommandError, match="not a pool id"):
        _run(
            "--node-id",
            node_id(1),
            "--pool",
            pool,
            "--override",
            "hdd",
            "--by",
            BY,
            "--reason",
            "r",
        )


def test_malformed_node_id_is_refused() -> None:
    with pytest.raises(CommandError, match="64 lowercase hex"):
        _run("--node-id", "abc", "--pool", "p", "--override", "hdd", "--by", BY, "--reason", "r")


def test_an_over_long_reason_writes_nothing() -> None:
    _capacity(1)
    with pytest.raises(CommandError, match="reason longer"):
        _run(
            "--node-id",
            node_id(1),
            "--pool",
            "default",
            "--override",
            "hdd",
            "--by",
            BY,
            "--reason",
            "r" * 513,
        )
    # The implicit pool created for the write rolled back with it.
    assert not MinerStoragePool.objects.exists()
    assert _audits(1) == []


# ─── dry run / show ──────────────────────────────────────────────────


def test_dry_run_writes_nothing() -> None:
    _capacity(1)
    MinerStoragePool.objects.create(miner_node_id=node_id(1), pool_id="p")
    out = _run("--node-id", node_id(1), "--pool", "p", "--override", "hdd", "--dry-run")
    assert "dry run" in out
    assert MinerStoragePool.objects.get(pool_id="p").operator_override == ""
    _run("--node-id", node_id(1), "--pool", "default", "--override", "hdd", "--dry-run")
    assert not MinerStoragePool.objects.filter(pool_id="default").exists()
    assert _audits(1) == []


def test_show_writes_nothing() -> None:
    MinerStoragePool.objects.create(miner_node_id=node_id(1), pool_id="p", tier="ssd")
    out = _run("--node-id", node_id(1), "--pool", "p", "--show")
    assert "tier: 'ssd'" in out
    assert "effective_tier: 'ssd'" in out
    assert _audits(1) == []


# ─── the writer itself ───────────────────────────────────────────────


@pytest.mark.django_db(transaction=True)
def test_the_writer_refuses_outside_a_transaction() -> None:
    pool = MinerStoragePool.objects.create(miner_node_id=node_id(1), pool_id="p")
    with pytest.raises(RuntimeError, match="transaction"):
        override_mod.set_pool_override(pool, "hdd", actor="op:x", reason="r")


@pytest.mark.parametrize(
    ("override", "actor", "reason", "message"),
    [
        ("unknown", "op:x", "r", "not an override tier"),
        ("sata", "op:x", "r", "not an override tier"),
        ("hdd", "", "r", "actor"),
        ("hdd", "op:x", "", "reason"),
    ],
)
def test_the_writer_validates(override: str, actor: str, reason: str, message: str) -> None:
    pool = MinerStoragePool.objects.create(miner_node_id=node_id(1), pool_id="p")
    with pytest.raises(ValueError, match=message), transaction.atomic():
        override_mod.set_pool_override(pool, override, actor=actor, reason=reason)
    assert _audits(1) == []
