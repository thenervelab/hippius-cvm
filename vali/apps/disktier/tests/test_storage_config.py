"""The `storage-config` push loop (`apps.disktier.storage_config`):
staging, the push outcomes, the gates, the sync status, drift, drained
pools, the dry run, the reported revision, the metric. The agent and the
digest are stubbed (`FakeAgent`)."""

from __future__ import annotations

from datetime import timedelta
from typing import Any

import pytest
from django.conf import settings
from django.utils import timezone

from apps.disktier import storage_config
from apps.disktier.ingest import record_storage_report
from apps.disktier.models import (
    DedicatedDisk,
    MinerStorageConfig,
    MinerStorageConfigAudit,
    MinerStoragePool,
)
from apps.disktier.storage_config import Actor, StageConflict
from apps.disktier.storage_doc import DocError, normalize
from apps.scheduler.models import MinerCapacity
from apps.scheduler.tests.factories import make_dispatchable_identity, node_id
from apps.telemetry.verifier import DeclaredPool, DeclaredStorage

from .conftest import FAMILY_A, FAMILY_B, FakeAgent, bind, storage_digest

pytestmark = pytest.mark.django_db

ACTOR = Actor(principal="backend-operator-config", family="5Fam", user="42", account=FAMILY_A.hex())
NODE = node_id(1)


@pytest.fixture(autouse=True)
def _owned_on_chain(chain: dict[str, Any]) -> dict[str, Any]:
    """Nodes 1 and 2 are run by family A on chain (the push loop checks)."""
    bind(chain, node_id(1), FAMILY_A)
    bind(chain, node_id(2), FAMILY_A)
    return chain


def _pool(pool_id: str = "default", **over: Any) -> dict[str, Any]:
    pool = {
        "id": pool_id,
        "path": "/var/lib/hippius-miner" if pool_id == "default" else f"/srv/{pool_id}",
        "class": "nvme" if pool_id == "default" else "hdd",
        "budget_gb": 3000 if pool_id == "default" else 500,
        "os_disks": pool_id == "default",
        "state": "active",
    }
    pool.update(over)
    return pool


def _doc(*extra: dict[str, Any], disks: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    return normalize({"pools": [_pool(), *extra], "dedicated_disks": disks or []})


def _miner(seed: int = 1, version: str = "v2026.10.09") -> None:
    make_dispatchable_identity(seed)
    MinerCapacity.objects.create(
        miner_node_id=node_id(seed),
        status="active",
        capacity_slots=1,
        observed_epoch=1,
        data_epoch=1,
        refreshed_at=timezone.now(),
        agent_version=version,
    )


def _stage(doc: dict[str, Any] | None = None, seed: int = 1) -> MinerStorageConfig:
    row, _ = storage_config.stage(node_id(seed), doc or _doc(), actor=ACTOR, action="put")
    return row


def _row(seed: int = 1) -> MinerStorageConfig:
    return MinerStorageConfig.objects.get(miner_node_id=node_id(seed))


def _heartbeat(revision: int, *, at: Any = None, seed: int = 1) -> None:
    storage_config.record_reported_revision(node_id(seed), revision, at or timezone.now())


# ─── staging ─────────────────────────────────────────────────────────


def test_the_revision_moves_only_when_the_content_does() -> None:
    row, changed = storage_config.stage(NODE, _doc(), actor=ACTOR, action="put")
    assert (row.revision, changed) == (1, True)
    row, changed = storage_config.stage(NODE, _doc(), actor=ACTOR, action="put")
    assert (row.revision, changed) == (1, False)
    row, changed = storage_config.stage(NODE, _doc(_pool("hdd0")), actor=ACTOR, action="put")
    assert (row.revision, changed) == (2, True)
    assert row.body_sha == ""  # the push loop's to fill
    assert (row.updated_by_principal, row.updated_by_family, row.updated_by_user) == (
        "backend-operator-config",
        "5Fam",
        "42",
    )
    outcomes = list(
        MinerStorageConfigAudit.objects.filter(miner_node_id=NODE)
        .order_by("id")
        .values_list("revision", "outcome", "user")
    )
    assert outcomes == [(1, "staged", "42"), (1, "unchanged", "42"), (2, "staged", "42")]


def test_if_match_must_name_the_current_revision() -> None:
    with pytest.raises(StageConflict):
        storage_config.stage(NODE, _doc(), actor=ACTOR, action="put", if_match=3)
    storage_config.stage(NODE, _doc(), actor=ACTOR, action="put", if_match=0)
    with pytest.raises(StageConflict) as err:
        storage_config.stage(NODE, _doc(_pool("a")), actor=ACTOR, action="put", if_match=0)
    assert err.value.current == 1
    storage_config.stage(NODE, _doc(_pool("a")), actor=ACTOR, action="put", if_match=1)


def test_edit_needs_a_document_and_revalidates() -> None:
    with pytest.raises(LookupError):
        storage_config.edit(NODE, lambda d: d, actor=ACTOR, action="pool-add")
    _stage()

    def _break(doc: dict[str, Any]) -> dict[str, Any]:
        doc["pools"] = []
        return doc

    with pytest.raises(DocError) as err:
        storage_config.edit(NODE, _break, actor=ACTOR, action="pool-drain")
    assert err.value.code == "pool-default-required"
    assert _row().revision == 1


# ─── gates ───────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("have", "minimum", "ok"),
    [
        ("v2026.10.09", "v2026.10.01", True),
        ("v2026.10.09", "v2026.10.09", True),
        ("v2026.10.09.1", "v2026.10.09", True),
        ("v2026.10.09", "v2026.10.09.1", False),
        ("v2026.9.30", "v2026.10.01", False),
        ("dev", "v2026.10.01", False),
        ("", "v2026.10.01", False),
        ("dev", "*", True),
        ("v2026.10.09", "", False),
        ("v2026.10.09", "garbage", False),
    ],
)
def test_agent_version_gate(have: str, minimum: str, ok: bool) -> None:
    assert storage_config.version_at_least(have, minimum) is ok


def test_flags_off_push_nothing(agent: FakeAgent) -> None:
    _miner()
    _stage()
    report = storage_config.reconcile()
    assert not report.enabled
    assert agent.sent == []


@pytest.mark.usefixtures("push_on")
def test_only_selected_miners_are_pushed(agent: FakeAgent, monkeypatch: pytest.MonkeyPatch) -> None:
    _miner(1)
    _miner(2)
    _stage(seed=1)
    _stage(seed=2)
    monkeypatch.setattr(settings, "VALI_STORAGE_CONFIG_MINERS", ["miner-02"])
    report = storage_config.reconcile()
    assert report.skipped == {node_id(1): "miner-not-selected"}
    assert len(agent.sent) == 1
    assert _row(1).last_error == "held: miner-not-selected"
    monkeypatch.setattr(settings, "VALI_STORAGE_CONFIG_MINERS", [node_id(1)])
    storage_config.reconcile()
    assert len(agent.sent) == 2


@pytest.mark.usefixtures("push_on")
def test_an_old_agent_or_an_empty_minimum_is_not_pushed(
    agent: FakeAgent, monkeypatch: pytest.MonkeyPatch
) -> None:
    _miner(1, version="v2026.09.01")
    _stage()
    assert storage_config.reconcile().skipped == {NODE: "agent-version-below-min"}
    monkeypatch.setattr(settings, "VALI_STORAGE_CONFIG_MIN_AGENT_VERSION", "")
    assert storage_config.reconcile().skipped == {NODE: "agent-version-below-min"}
    assert agent.sent == []


@pytest.mark.usefixtures("push_on")
def test_a_node_without_a_document_or_miner_is_not_pushed(agent: FakeAgent) -> None:
    _miner(1)
    _stage(seed=2)  # no miner for node 2
    report = storage_config.reconcile()
    assert report.skipped == {node_id(2): "miner-unknown"}
    assert agent.sent == []


# ─── push outcomes ───────────────────────────────────────────────────


@pytest.mark.usefixtures("push_on")
def test_an_ack_is_recorded_and_the_heartbeat_completes_the_sync(agent: FakeAgent) -> None:
    _miner()
    _stage(_doc(_pool("hdd0"), disks=[{"id": "wwn-0x1", "state": "active"}]))
    report = storage_config.reconcile()
    assert (report.pushed, report.acked) == (1, 1)
    sent = agent.sent[0]
    assert sent["revision"] == 1 and sent["dry_run"] is False
    assert [p["id"] for p in sent["pools"]] == ["default", "hdd0"]
    assert sent["dedicated_disks"] == [{"id": "wwn-0x1", "state": "active"}]
    ttl = sent["not_after_unix"] - int(timezone.now().timestamp())
    assert 0 < ttl <= settings.VALI_STORAGE_CONFIG_TTL_S
    row = _row()
    assert row.acked_current and row.acked_revision == 1 and row.last_error == ""
    assert row.body_sha == agent.sha
    assert agent.order_ids[0].startswith("sc-miner-01-r1-")
    # Acked, but the agent has not reported it in force yet.
    assert storage_config.sync_status(row) == "pending"
    _heartbeat(1)
    assert storage_config.sync_status(_row()) == "in_sync"
    pushes = MinerStorageConfigAudit.objects.filter(action="push")
    assert list(pushes.values_list("revision", "outcome")) == [(1, "applied")]


@pytest.mark.usefixtures("push_on")
def test_a_new_revision_goes_at_once_an_acked_one_waits_for_sync(agent: FakeAgent) -> None:
    _miner()
    _stage()
    storage_config.reconcile()
    storage_config.reconcile()
    assert len(agent.sent) == 1  # acked: next send after SYNC_S
    _stage(_doc(_pool("hdd0")))
    storage_config.reconcile()
    assert [b["revision"] for b in agent.sent] == [1, 2]
    later = timezone.now() + timedelta(seconds=settings.VALI_STORAGE_CONFIG_SYNC_S + 1)
    storage_config.reconcile(now=later)
    assert [b["revision"] for b in agent.sent] == [1, 2, 2]
    assert len(set(agent.order_ids)) == 3  # a fresh order_id per push
    assert MinerStorageConfigAudit.objects.filter(action="push").count() == 2


@pytest.mark.usefixtures("push_on")
def test_an_ack_of_other_content_is_not_an_ack(agent: FakeAgent) -> None:
    _miner()
    _stage()
    agent.script.append((200, "applied:1:" + "0" * 64))
    assert storage_config.reconcile().failed == [NODE]
    row = _row()
    assert not row.acked_current and row.last_error.startswith("ack-mismatch")
    assert storage_config.sync_status(row) == "pending"


@pytest.mark.usefixtures("push_on")
def test_a_stale_revision_jumps_past_the_agents(agent: FakeAgent) -> None:
    _miner()
    agent.revision, agent.sha = 9, "x"
    _stage()
    _heartbeat(9)
    storage_config.reconcile()
    row = _row()
    assert not row.acked_current and "storage-config-stale-revision" in row.last_error
    assert row.revision == 9 and row.content_key == ""
    retry = settings.VALI_STORAGE_CONFIG_RETRY_S
    # Re-staged at once, but sent only after the backoff of the 409.
    storage_config.reconcile()
    assert _row().revision == 10 and len(agent.sent) == 1
    storage_config.reconcile(now=timezone.now() + timedelta(seconds=retry + 1))
    row = _row()
    assert row.revision == 10 and row.acked_current and row.apply_failures == 0
    assert [b["revision"] for b in agent.sent] == [1, 10]
    actions = list(
        MinerStorageConfigAudit.objects.order_by("id").values_list("action", "revision", "outcome")
    )
    assert ("rebase", 10, "staged") in actions
    assert ("push", 1, "status-409:storage-config-stale-revision") in actions


@pytest.mark.usefixtures("push_on")
def test_a_stale_revision_without_a_heartbeat_doubles(agent: FakeAgent) -> None:
    _miner()
    agent.revision, agent.sha = 3, "x"
    for extra in ("a", "b", "c"):
        _stage(_doc(_pool(extra)))  # vali at r3 too
    clock = timezone.now()
    storage_config.reconcile(now=clock)  # r3, other content: conflict
    clock += timedelta(hours=1)
    storage_config.reconcile(now=clock)  # r4 acked
    assert [b["revision"] for b in agent.sent] == [3, 4]
    assert _row().acked_current
    agent.revision = 20
    _stage(_doc(_pool("d")))  # r5 < 20: stale
    storage_config.reconcile(now=clock)
    assert _row().revision == 9  # 2×5 - 1, re-staged to 10
    for _ in range(3):
        clock += timedelta(hours=1)
        storage_config.reconcile(now=clock)
    # 10 is stale too (doubled to 20), 20 is the agent's own with other
    # content (one up).
    assert [b["revision"] for b in agent.sent] == [3, 4, 5, 10, 20, 21]
    assert _row().acked_revision == 21


@pytest.mark.usefixtures("push_on")
def test_an_agent_that_answers_409_to_everything_is_backed_off(agent: FakeAgent) -> None:
    _miner()
    _stage()
    clock = timezone.now()
    for _ in range(40):
        agent.script.append((409, '{"code":"storage-config-revision-conflict"}'))
        storage_config.reconcile(now=clock)
        clock += timedelta(seconds=settings.VALI_STORAGE_CONFIG_RETRY_S)
    # 60 s, 120 s, 240 s … : a handful of pushes in 40 minutes, not 40.
    assert len(agent.sent) <= 6
    assert _row().apply_failures >= 5


@pytest.mark.usefixtures("push_on")
def test_a_refusal_is_kept_with_its_pool_and_backs_off(agent: FakeAgent) -> None:
    _miner()
    _stage(_doc(_pool("hdd0")))
    agent.script.append((422, '{"code":"pool-not-a-mount","pool":"hdd0"}'))
    storage_config.reconcile()
    row = _row()
    assert (row.refusal_code, row.refusal_pool, row.apply_failures) == (
        "pool-not-a-mount",
        "hdd0",
        1,
    )
    assert storage_config.sync_status(row) == "refused:pool-not-a-mount:hdd0"
    retry = settings.VALI_STORAGE_CONFIG_RETRY_S
    storage_config.reconcile(now=timezone.now() + timedelta(seconds=retry - 5))
    assert len(agent.sent) == 1
    agent.script.append((422, '{"code":"disk-has-signature","disk":"wwn-0x1"}'))
    storage_config.reconcile(now=timezone.now() + timedelta(seconds=retry + 1))
    row = _row()
    assert (row.refusal_code, row.refusal_disk, row.apply_failures) == (
        "disk-has-signature",
        "wwn-0x1",
        2,
    )
    # Second failure: 2 × RETRY_S.
    storage_config.reconcile(now=timezone.now() + timedelta(seconds=2 * retry - 5))
    assert len(agent.sent) == 2
    outcomes = MinerStorageConfigAudit.objects.filter(action="push").values_list(
        "outcome", flat=True
    )
    assert set(outcomes) == {
        "refused:pool-not-a-mount:hdd0",
        "refused:disk-has-signature:wwn-0x1",
    }
    # The operator fixes the document: the refusal is cleared, sent at once.
    _stage(_doc(_pool("hdd0", budget_gb=400)))
    assert storage_config.sync_status(_row()) == "pending"
    storage_config.reconcile()
    assert _row().acked_current and _row().refusal_code == ""


@pytest.mark.usefixtures("push_on")
def test_the_same_refusal_is_audited_once(agent: FakeAgent) -> None:
    _miner()
    _stage(_doc(_pool("hdd0")))
    refusal = (422, '{"code":"pool-not-a-mount","pool":"hdd0"}')
    agent.script.extend([refusal, refusal])
    storage_config.reconcile()
    storage_config.reconcile(now=timezone.now() + timedelta(hours=1))
    assert len(agent.sent) == 2
    assert MinerStorageConfigAudit.objects.filter(action="push").count() == 1


@pytest.mark.usefixtures("push_on")
@pytest.mark.parametrize("answer", [(404, ""), (503, "storage-config-disabled")])
def test_an_agent_without_the_route_is_held(agent: FakeAgent, answer: tuple[int, str]) -> None:
    _miner()
    _stage()
    agent.script.append(answer)
    storage_config.reconcile()
    row = _row()
    assert row.agent_unsupported_at is not None
    assert storage_config.sync_status(row) == "agent-unsupported"
    hold = settings.VALI_STORAGE_CONFIG_UNSUPPORTED_RETRY_S
    storage_config.reconcile(now=timezone.now() + timedelta(seconds=hold - 60))
    _stage(_doc(_pool("hdd0")))  # even a new revision waits
    storage_config.reconcile()
    assert len(agent.sent) == 1
    storage_config.reconcile(now=timezone.now() + timedelta(seconds=hold + 1))
    row = _row()
    assert len(agent.sent) == 2 and row.acked_current and row.agent_unsupported_at is None


@pytest.mark.usefixtures("push_on")
def test_a_store_failure_backs_off_exponentially(agent: FakeAgent) -> None:
    _miner()
    _stage()
    retry = settings.VALI_STORAGE_CONFIG_RETRY_S
    agent.script.extend([(500, '{"code":"storage-config-store"}')] * 3)
    start = timezone.now()
    storage_config.reconcile(now=start)
    assert _row().apply_failures == 1
    storage_config.reconcile(now=start + timedelta(seconds=retry + 1))
    assert _row().apply_failures == 2
    sent = _row().sent_at
    storage_config.reconcile(now=sent + timedelta(seconds=2 * retry - 1))
    assert len(agent.sent) == 2
    storage_config.reconcile(now=sent + timedelta(seconds=2 * retry + 1))
    assert _row().apply_failures == 3
    row = _row()
    assert storage_config._retry_period_s(row) == 4 * retry
    row.apply_failures = 30
    assert storage_config._retry_period_s(row) == settings.VALI_STORAGE_CONFIG_APPLY_BACKOFF_MAX_S


@pytest.mark.usefixtures("push_on")
def test_an_unreachable_agent_is_retried(agent: FakeAgent) -> None:
    _miner()
    _stage()
    agent.unreachable = True
    assert storage_config.reconcile().failed == [NODE]
    assert _row().last_error.startswith("unreachable")
    agent.unreachable = False
    storage_config.reconcile()
    assert len(agent.sent) == 0  # retried after RETRY_S, not at once
    later = timezone.now() + timedelta(seconds=settings.VALI_STORAGE_CONFIG_RETRY_S + 1)
    storage_config.reconcile(now=later)
    assert _row().acked_current


@pytest.mark.usefixtures("push_on")
def test_drift_is_re_pushed(agent: FakeAgent) -> None:
    _miner()
    _stage()
    storage_config.reconcile()
    acked = _row().acked_at
    _heartbeat(1, at=acked + timedelta(seconds=10))
    assert storage_config.sync_status(_row()) == "in_sync"
    # The agent restarted onto its local config.
    _heartbeat(0, at=acked + timedelta(seconds=70))
    row = _row()
    assert storage_config.sync_status(row) == "drift"
    soon = acked + timedelta(seconds=settings.VALI_STORAGE_CONFIG_RETRY_S + 1)
    storage_config.reconcile(now=soon)
    assert len(agent.sent) == 2


def test_a_heartbeat_from_before_the_ack_is_not_drift() -> None:
    row = MinerStorageConfig(
        miner_node_id=NODE,
        revision=2,
        body_sha="s",
        acked_revision=2,
        acked_sha="s",
        acked_at=timezone.now(),
        reported_revision=1,
        reported_at=timezone.now() - timedelta(seconds=5),
    )
    assert storage_config.sync_status(row) == "pending"
    assert storage_config.sync_status(None) == "unmanaged"


# ─── drained pools ───────────────────────────────────────────────────


@pytest.mark.usefixtures("push_on")
def test_a_drained_pool_leaves_the_document_once_empty(agent: FakeAgent) -> None:
    _miner()
    _stage(_doc(_pool("hdd0", state="draining")))
    storage_config.reconcile()
    acked = _row().acked_at
    hdd0 = MinerStoragePool.objects.create(
        miner_node_id=NODE, pool_id="hdd0", reported_state="draining", committed_gb=40
    )
    _heartbeat(1, at=acked + timedelta(seconds=5))
    late = timezone.now() + timedelta(seconds=settings.VALI_STORAGE_CONFIG_SYNC_S + 1)
    storage_config.reconcile(now=late)
    assert _row().revision == 1  # still holds disks
    MinerStoragePool.objects.filter(pk=hdd0.pk).update(committed_gb=0)
    # The next heartbeat after the (re-)ack shows it empty.
    _heartbeat(1, at=late + timedelta(seconds=5))
    storage_config.reconcile(now=late + timedelta(seconds=10))
    row = _row()
    assert row.revision == 2 and [p["id"] for p in row.body["pools"]] == ["default"]
    assert agent.sent[-1]["revision"] == 2
    removal = MinerStorageConfigAudit.objects.get(action="pool-removed")
    assert (removal.principal, removal.revision) == ("vali", 2)


@pytest.mark.usefixtures("push_on")
def test_a_draining_pool_stays_until_the_agent_runs_that_revision(agent: FakeAgent) -> None:
    _miner()
    _stage(_doc(_pool("hdd0", state="draining")))
    storage_config.reconcile()
    MinerStoragePool.objects.create(
        miner_node_id=NODE, pool_id="hdd0", reported_state="draining", committed_gb=0
    )
    _heartbeat(0, at=_row().acked_at + timedelta(seconds=5))  # drifted, not in force
    storage_config.reconcile(now=timezone.now() + timedelta(hours=1))
    assert [p["id"] for p in _row().body["pools"]] == ["default", "hdd0"]


# ─── dry run ─────────────────────────────────────────────────────────


@pytest.mark.usefixtures("push_on")
def test_a_dry_run_returns_the_verdict_and_stores_nothing(agent: FakeAgent) -> None:
    _miner()
    verdict = storage_config.dry_run(NODE, _doc(), revision=0)
    assert verdict.ok and verdict.code.startswith("dry-run-ok:1:")
    assert agent.sent[0]["dry_run"] is True
    assert agent.order_ids[0].startswith("scv-")
    assert not MinerStorageConfig.objects.exists()
    agent.script.append((422, '{"code":"pool-fstype-unsupported","pool":"hdd0"}'))
    verdict = storage_config.dry_run(NODE, _doc(_pool("hdd0")), revision=4)
    assert (verdict.ok, verdict.status, verdict.code, verdict.pool) == (
        False,
        422,
        "pool-fstype-unsupported",
        "hdd0",
    )
    agent.script.append((200, "dry-run-ok:4:" + "0" * 64))
    assert storage_config.dry_run(NODE, _doc(), revision=4).code == "ack-mismatch"


def test_a_dry_run_honours_the_gates(agent: FakeAgent) -> None:
    _miner()
    with pytest.raises(storage_config.DryRunUnavailable, match="storage-config-push-disabled"):
        storage_config.dry_run(NODE, _doc(), revision=1)
    assert agent.sent == []


# ─── reported revision, adopt, metric ────────────────────────────────


def test_the_heartbeat_revision_lands_on_a_managed_node_only() -> None:
    now = timezone.now()
    pool = DeclaredPool(
        pool_id="default",
        declared_class="nvme",
        total_gb=3500,
        available_gb=2900,
        budget_gb=3000,
        committed_gb=0,
        os_disks=True,
        state="active",
        error="",
    )
    report = DeclaredStorage(pools=(pool,), dedicated_disks=(), storage_config_revision=7)
    record_storage_report(NODE, report, now)
    assert not MinerStorageConfig.objects.exists()
    _stage()
    record_storage_report(NODE, report, now)
    row = _row()
    assert (row.reported_revision, row.reported_at) == (7, now)


def _reported(pool_id: str, at: Any, **fields: Any) -> MinerStoragePool:
    defaults = {
        "declared_class": "nvme",
        "budget_gb": 3000,
        "os_disks": True,
        "reported_state": "active",
        "reported_at": at,
    }
    defaults.update(fields)
    return MinerStoragePool.objects.create(miner_node_id=NODE, pool_id=pool_id, **defaults)


def test_adopt_builds_the_reported_document() -> None:
    now = timezone.now()
    _reported("default", now, declared_class="")
    _reported(
        "hdd0",
        now,
        declared_class="hdd",
        budget_gb=16000,
        os_disks=False,
        reported_state="draining",
    )
    _reported("old", now - timedelta(days=1), retired_at=now)
    DedicatedDisk.objects.create(
        miner_node_id=NODE, disk_id="wwn-0x1", reported_at=now, reported_state="free"
    )
    DedicatedDisk.objects.create(
        miner_node_id=NODE, disk_id="wwn-0x2", reported_at=now, reported_state="draining"
    )
    DedicatedDisk.objects.create(
        miner_node_id=NODE, disk_id="wwn-0x3", reported_at=now - timedelta(hours=1)
    )
    paths = {
        "default": {"path": "/var/lib/hippius-miner", "class": "ssd"},
        "hdd0": {"path": "/srv/hdd0"},
    }
    doc = storage_config.adopt_document(NODE, paths)
    assert doc == {
        "pools": [
            {
                "id": "default",
                "path": "/var/lib/hippius-miner",
                "class": "ssd",
                "budget_gb": 3000,
                "os_disks": True,
                "state": "active",
            },
            {
                "id": "hdd0",
                "path": "/srv/hdd0",
                "class": "hdd",
                "budget_gb": 16000,
                "os_disks": False,
                "state": "draining",
            },
        ],
        "dedicated_disks": [
            {"id": "wwn-0x1", "state": "active"},
            {"id": "wwn-0x2", "state": "draining"},
        ],
    }
    row, changed = storage_config.adopt(NODE, paths, actor=ACTOR, force=False)
    assert (row.revision, changed) == (1, True)
    with pytest.raises(StageConflict):
        storage_config.adopt(NODE, paths, actor=ACTOR, force=False)
    row, changed = storage_config.adopt(NODE, paths, actor=ACTOR, force=True)
    assert (row.revision, changed) == (1, False)


@pytest.mark.parametrize(
    ("paths", "code"),
    [
        ({}, "adopt-path-required"),
        ({"default": {"path": "/var/lib/hippius-miner"}}, "adopt-class-required"),
        ({"default": {"path": "/x", "class": "ssd"}, "nope": {"path": "/y"}}, "adopt-unknown-pool"),
        ({"default": "/x"}, "storage-config-malformed"),
        ({"default": {"path": "relative", "class": "ssd"}}, "pool-path-invalid"),
    ],
)
def test_adopt_refusals(paths: Any, code: str) -> None:
    _reported("default", timezone.now(), declared_class="")
    with pytest.raises(DocError) as err:
        storage_config.adopt_document(NODE, paths)
    assert err.value.code == code


def test_adopt_needs_a_report() -> None:
    with pytest.raises(DocError) as err:
        storage_config.adopt_document(NODE, {})
    assert err.value.code == "storage-report-missing"


def test_the_sync_metric_is_one_hot(monkeypatch: pytest.MonkeyPatch) -> None:
    from apps.scheduler.management.commands import vali_scheduler_reeval
    from apps.synthetic import metrics

    pushed: list[Any] = []
    monkeypatch.setattr(settings, "VALI_SYNTHETIC_PUSHGATEWAY_URL", "http://gw.invalid")
    monkeypatch.setattr(metrics, "push", lambda ms, **kw: pushed.append((ms, kw)) or True)
    _stage()
    MinerStorageConfig.objects.filter(miner_node_id=NODE).update(
        refusal_code="pool-not-a-mount", refusal_pool="hdd0"
    )
    vali_scheduler_reeval.storage_config_survey()
    ms, kw = pushed[0]
    assert kw["job"] == "vali-storage-config" and kw["replace"] is True
    samples = {
        s.labels["state"]: s.value for s in ms.samples if s.name == "hippius_storage_config_sync"
    }
    assert samples == {
        "in_sync": 0.0,
        "pending": 0.0,
        "refused": 1.0,
        "agent-unsupported": 0.0,
        "drift": 0.0,
    }
    assert {s.labels["node_id"] for s in ms.samples} == {NODE}


def test_the_digest_stub_leaves_the_expiry_out() -> None:
    a = b'{"revision": 1, "not_after_unix": 5, "dry_run": false, "pools": []}'
    b = b'{"revision": 1, "not_after_unix": 9, "dry_run": false, "pools": []}'
    assert storage_digest(a) == storage_digest(b)


def test_the_orchestration_tick_runs_the_push_pass(monkeypatch: pytest.MonkeyPatch) -> None:
    from apps.orchestration import service

    calls: list[bool] = []
    monkeypatch.setattr(storage_config, "reconcile", lambda: calls.append(True))
    service.tick_once()
    assert calls == [True]


# ─── local facts learned from the agent ──────────────────────────────


@pytest.mark.usefixtures("push_on")
def test_the_accepted_document_pins_default_and_held_pools(agent: FakeAgent) -> None:
    _miner()
    _stage(_doc(_pool("hdd0")))
    assert storage_config.local_limits(NODE) == {
        "default_budget_gb": None,
        "default_path": None,
        "held_paths": {},
    }
    storage_config.reconcile()
    assert _row().acked_body == _row().body
    _heartbeat(1, at=_row().acked_at + timedelta(seconds=5))  # in force
    MinerStoragePool.objects.create(miner_node_id=NODE, pool_id="default", budget_gb=3000)
    MinerStoragePool.objects.create(miner_node_id=NODE, pool_id="hdd0", committed_gb=40)
    assert storage_config.local_limits(NODE) == {
        "default_budget_gb": 3000,
        "default_path": "/var/lib/hippius-miner",
        "held_paths": {"hdd0": "/srv/hdd0"},
    }

    def _move(doc: dict[str, Any]) -> dict[str, Any]:
        doc["pools"][1]["path"] = "/srv/other"
        return doc

    with pytest.raises(DocError) as err:
        storage_config.edit(NODE, _move, actor=ACTOR, action="pool-update")
    assert (err.value.code, err.value.pool) == ("pool-has-disks", "hdd0")


def test_a_huge_reported_revision_is_clamped() -> None:
    _stage()
    storage_config.record_reported_revision(NODE, 2**64 - 1, timezone.now())
    assert _row().reported_revision == storage_config.MAX_REVISION


@pytest.mark.usefixtures("push_on")
def test_an_exhausted_revision_counter_holds_instead_of_overflowing(agent: FakeAgent) -> None:
    _miner()
    _stage()
    MinerStorageConfig.objects.filter(miner_node_id=NODE).update(
        revision=storage_config.MAX_REVISION
    )
    agent.script.append((409, '{"code":"storage-config-stale-revision"}'))
    storage_config.reconcile()
    row = _row()
    assert row.revision == storage_config.MAX_REVISION and row.content_key
    assert "exhausted" in row.last_error and row.apply_failures == 1
    with pytest.raises(DocError) as err:
        storage_config.stage(NODE, _doc(_pool("x")), actor=ACTOR, action="put")
    assert err.value.code == "storage-config-revision-exhausted"


# ─── the family that wrote the document ──────────────────────────────


@pytest.mark.usefixtures("push_on")
def test_a_node_that_changed_family_is_not_pushed_its_former_document(
    agent: FakeAgent, _owned_on_chain: dict[str, Any]
) -> None:
    from apps.disktier import node_family

    _miner()
    _stage()
    node_family.node_family(NODE)  # family A, cached
    bind(_owned_on_chain, NODE, FAMILY_B)
    retry = timedelta(seconds=settings.VALI_STORAGE_CONFIG_RETRY_S + 1)
    clock = timezone.now()
    # The push reads the chain afresh: the cached binding does not count.
    assert storage_config.reconcile(now=clock).skipped == {NODE: "family-changed"}
    assert _row().last_error == "held: family-changed"
    calls = len(_owned_on_chain["__calls__"])
    # Held counts as an attempt: no chain read on every tick.
    assert storage_config.reconcile(now=clock).skipped == {}
    assert len(_owned_on_chain["__calls__"]) == calls
    _owned_on_chain[NODE] = node_family.FamilyCheckUnavailable("rpc down")
    clock += retry
    assert storage_config.reconcile(now=clock).skipped == {NODE: "chain-unavailable"}
    bind(_owned_on_chain, NODE, FAMILY_A, status="unbonding")
    clock += retry
    assert storage_config.reconcile(now=clock).skipped == {NODE: "family-changed"}
    assert agent.sent == []
    bind(_owned_on_chain, NODE, FAMILY_A)
    clock += retry
    storage_config.reconcile(now=clock)
    assert _row().acked_current


def test_a_new_family_sees_no_document_and_replaces_the_former_one() -> None:
    _stage()
    other = Actor(principal="p", family="5B", user="7", account=FAMILY_B.hex())
    assert storage_config.owned_by(_row(), FAMILY_B.hex()) is None
    assert storage_config.visible_revision(_row(), other) == 0
    with pytest.raises(LookupError):
        storage_config.edit(NODE, lambda d: d, actor=other, action="pool-drain")
    # Same content, new family: a new revision, owned by it.
    row, changed = storage_config.stage(NODE, _doc(), actor=other, action="put", if_match=0)
    assert (row.revision, changed, row.owner_family) == (2, True, FAMILY_B.hex())
    assert storage_config.visible_revision(row, ACTOR) == 0


def test_a_disk_first_reported_after_the_document_takes_its_state() -> None:
    from apps.telemetry.verifier import DeclaredDedicatedDisk

    _stage(_doc(disks=[{"id": "wwn-0x9", "state": "draining"}]))
    pool = DeclaredPool(
        pool_id="default",
        declared_class="nvme",
        total_gb=0,
        available_gb=0,
        budget_gb=3000,
        committed_gb=0,
        os_disks=True,
        state="active",
        error="",
    )
    disk = DeclaredDedicatedDisk(disk_id="wwn-0x9", size_mb=1, state="free", vm="", error="")
    report = DeclaredStorage(pools=(pool,), dedicated_disks=(disk,), storage_config_revision=0)
    record_storage_report(NODE, report, timezone.now())
    assert DedicatedDisk.objects.get(disk_id="wwn-0x9").desired_state == "draining"


@pytest.mark.usefixtures("push_on")
def test_local_facts_bind_only_while_the_accepted_document_is_in_force(
    agent: FakeAgent,
) -> None:
    _miner()
    _stage()
    storage_config.reconcile()
    _heartbeat(1, at=_row().acked_at + timedelta(seconds=5))
    assert storage_config.local_limits(NODE)["default_path"] == "/var/lib/hippius-miner"
    # The miner moved its data root; the agent refused the stored document
    # at boot and runs its local config.
    _heartbeat(0, at=_row().acked_at + timedelta(seconds=60))
    assert storage_config.local_limits(NODE)["default_path"] is None
    row, changed = storage_config.stage(
        NODE, normalize({"pools": [_pool(path="/data/hippius")]}), actor=ACTOR, action="put"
    )
    assert changed and row.body["pools"][0]["path"] == "/data/hippius"


@pytest.mark.usefixtures("push_on")
def test_a_late_answer_to_an_older_revision_does_not_touch_the_new_one(
    agent: FakeAgent,
) -> None:
    _miner()
    old = _stage()
    old = storage_config._ensure_digest(old)
    _stage(_doc(_pool("hdd0")))  # r2 staged meanwhile
    agent.script.append((404, ""))
    from apps.miners.models import MinerIdentity

    storage_config._push(MinerIdentity.objects.get(miner_id="miner-01"), old, now=timezone.now())
    row = _row()
    assert row.revision == 2
    assert row.agent_unsupported_at is None and row.sent_at is None and row.last_error == ""


@pytest.mark.usefixtures("push_on")
def test_the_former_familys_accepted_document_neither_binds_nor_leaks(
    agent: FakeAgent,
) -> None:
    _miner()
    _stage()
    storage_config.reconcile()
    _heartbeat(1, at=_row().acked_at + timedelta(seconds=5))
    MinerStoragePool.objects.create(miner_node_id=NODE, pool_id="default", budget_gb=3000)
    assert storage_config.local_limits(NODE, FAMILY_A.hex())["default_path"]
    assert storage_config.local_limits(NODE, FAMILY_B.hex()) == {
        "default_budget_gb": 3000,
        "default_path": None,
        "held_paths": {},
    }
    other = Actor(principal="p", family="5B", user="7", account=FAMILY_B.hex())
    doc = normalize({"pools": [_pool(path="/data/b")]})
    row, changed = storage_config.stage(NODE, doc, actor=other, action="put", if_match=0)
    assert changed and row.acked_body == {}
    # A late ack of family A's revision does not land on family B's row.
    old = MinerStorageConfig(
        pk=row.pk,
        miner_node_id=NODE,
        revision=1,
        body=_doc(),
        body_sha="x",
        owner_family=FAMILY_A.hex(),
    )
    agent.script.append((200, "applied:1:x"))
    from apps.miners.models import MinerIdentity

    storage_config._push(MinerIdentity.objects.get(miner_id="miner-01"), old, now=timezone.now())
    row = _row()
    assert row.acked_body == {} and row.acked_revision == 1  # unchanged from before


# ─── a pool leaves only once drained (`pool-not-drained`) ────────────


def _in_force(doc: dict[str, Any]) -> MinerStorageConfig:
    """Stage `doc` and make it the document the agent runs."""
    row = _stage(doc)
    MinerStorageConfig.objects.filter(pk=row.pk).update(
        acked_revision=row.revision, acked_body=doc, reported_revision=row.revision
    )
    return _row()


def _reports(pool_id: str, **fields: Any) -> MinerStoragePool:
    fields.setdefault("reported_state", "active")
    fields.setdefault("committed_gb", 0)
    return MinerStoragePool.objects.create(miner_node_id=NODE, pool_id=pool_id, **fields)


def _refused(doc: dict[str, Any]) -> str:
    with pytest.raises(storage_config.PoolNotDrained) as exc:
        _stage(doc)
    return exc.value.pool


def test_a_document_cannot_drop_a_pool_the_agent_runs_from_its_local_config() -> None:
    # A node before any push: nvme0 declared locally, reported v7.
    _reports("default")
    _reports("nvme0")
    assert _refused(_doc()) == "nvme0"
    assert not MinerStorageConfig.objects.filter(miner_node_id=NODE, revision__gt=0).exists()
    # Keeping it is fine.
    _stage(_doc(_pool("nvme0")))


def test_a_pool_in_force_leaves_only_drained_and_empty() -> None:
    _reports("default")
    nvme0 = _reports("nvme0", committed_gb=40)
    _in_force(_doc(_pool("nvme0")))
    assert _refused(_doc()) == "nvme0", "active in force"
    _in_force(_doc(_pool("nvme0", state="draining")))
    MinerStoragePool.objects.filter(pk=nvme0.pk).update(reported_state="draining")
    assert _refused(_doc()) == "nvme0", "draining but still holds disks"
    MinerStoragePool.objects.filter(pk=nvme0.pk).update(committed_gb=0)
    row = _stage(_doc())
    assert [p["id"] for p in row.body["pools"]] == ["default"]


def test_a_draining_pool_no_longer_reported_can_leave() -> None:
    _reports("default")
    _in_force(_doc(_pool("hdd0", state="draining")))
    _stage(_doc())


def test_only_the_set_in_force_binds() -> None:
    # Desired but never applied: removing it removes nothing on the host.
    _reports("default")
    _stage(_doc(_pool("hdd0")))
    _stage(_doc())
    # Draining in the desired document only (not yet in force) is not drained.
    _reports("nvme0")
    _in_force(_doc(_pool("nvme0")))
    _stage(_doc(_pool("nvme0", state="draining")))
    assert _refused(_doc()) == "nvme0"


def test_every_write_path_is_guarded_adopt_included() -> None:
    _reports("default", budget_gb=3000, declared_class="nvme", reported_at=timezone.now())
    _reports("nvme0", budget_gb=500, declared_class="hdd", reported_at=timezone.now())
    _in_force(_doc(_pool("nvme0")))

    def drop(doc: dict[str, Any]) -> dict[str, Any]:
        doc["pools"] = [p for p in doc["pools"] if p["id"] != "nvme0"]
        return doc

    with pytest.raises(storage_config.PoolNotDrained):
        storage_config.edit(NODE, drop, actor=ACTOR, action="pool-update")
    # An adopt that would drop it (the report lost it) is refused too.
    MinerStoragePool.objects.filter(miner_node_id=NODE, pool_id="nvme0").update(
        retired_at=timezone.now()
    )
    with pytest.raises(storage_config.PoolNotDrained) as exc:
        storage_config.adopt(
            NODE, {"default": {"path": "/var/lib/hippius-miner"}}, actor=ACTOR, force=True
        )
    assert (exc.value.pool, exc.value.field) == ("nvme0", "removed")


def test_moving_or_re_classing_a_pool_in_force_needs_a_drain() -> None:
    _reports("default")
    _reports("nvme0")
    _in_force(_doc(_pool("nvme0")))
    for change, field in (({"path": "/srv/elsewhere"}, "path"), ({"class": "ssd"}, "class")):
        with pytest.raises(storage_config.PoolNotDrained) as exc:
            _stage(_doc(_pool("nvme0", **change)))
        assert (exc.value.pool, exc.value.field) == ("nvme0", field)
    # Other fields are free.
    _stage(_doc(_pool("nvme0", budget_gb=400)))


def test_a_vm_disk_placed_on_a_pool_keeps_it_from_leaving() -> None:
    from apps.disktier.models import OS_SLOT, PlacementDisk
    from apps.orchestration.tests.factories import make_vm
    from apps.scheduler.models import PlacementStatus
    from apps.scheduler.tests.factories import make_placement

    _reports("default")
    _reports("hdd0", reported_state="draining", committed_gb=0)
    _in_force(_doc(_pool("hdd0", state="draining")))
    placement = make_placement(
        make_vm("vm-on-hdd0"), NODE, status=PlacementStatus.BOUND.value, resource_class="small"
    )
    PlacementDisk.objects.create(
        placement=placement,
        slot=OS_SLOT,
        kind="pool",
        pool_id="hdd0",
        size_gb=50,
        required_tier="nvme",
    )
    assert _refused(_doc()) == "hdd0"
    placement.status = PlacementStatus.MIGRATED.value
    placement.reason = "moved"
    placement.save(update_fields=["status", "reason"])
    _stage(_doc())


def test_a_new_family_is_held_to_the_set_the_node_runs() -> None:
    _reports("default")
    _reports("nvme0")
    _in_force(_doc(_pool("nvme0")))
    other = Actor(
        principal="backend-operator-config", family="5Fb", user="7", account=FAMILY_B.hex()
    )
    with pytest.raises(storage_config.PoolNotDrained):
        storage_config.stage(NODE, _doc(), actor=other, action="put")


@pytest.mark.usefixtures("push_on")
def test_a_document_staged_before_the_guard_is_not_pushed(agent: FakeAgent) -> None:
    _miner()
    _reports("default")
    _reports("nvme0")
    # Written straight to the row, as a pre-guard staging would have been.
    _stage(_doc(_pool("nvme0")))
    MinerStorageConfig.objects.filter(miner_node_id=NODE).update(body=_doc(), content_key="")
    assert storage_config.sync_node(NODE, force=True) == "pool-not-drained:nvme0"
    assert agent.sent == []


def test_a_pool_reported_with_an_out_of_range_committed_is_not_empty() -> None:
    # `None` is a figure past the decoder's range, never "nothing".
    _reports("default")
    _reports("hdd0", reported_state="draining", committed_gb=None)
    _in_force(_doc(_pool("hdd0", state="draining")))
    assert _refused(_doc()) == "hdd0"


@pytest.mark.usefixtures("push_on")
def test_vali_keeps_a_drained_pool_while_a_vm_disk_is_placed_on_it(
    agent: FakeAgent, monkeypatch: pytest.MonkeyPatch
) -> None:
    from apps.disktier.models import OS_SLOT, PlacementDisk
    from apps.orchestration.tests.factories import make_vm
    from apps.scheduler.models import PlacementStatus
    from apps.scheduler.tests.factories import make_placement

    _miner()
    _stage(_doc(_pool("hdd0", state="draining")))
    storage_config.reconcile()
    acked = _row().acked_at
    MinerStoragePool.objects.create(
        miner_node_id=NODE, pool_id="hdd0", reported_state="draining", committed_gb=0
    )
    # A queued launch on it: its disk is not created yet.
    placement = make_placement(make_vm("vm-queued"), NODE, resource_class="small")
    assert placement.status == PlacementStatus.PENDING.value
    PlacementDisk.objects.create(
        placement=placement,
        slot=OS_SLOT,
        kind="pool",
        pool_id="hdd0",
        size_gb=50,
        required_tier="nvme",
    )
    _heartbeat(1, at=acked + timedelta(seconds=5))
    late = timezone.now() + timedelta(seconds=settings.VALI_STORAGE_CONFIG_SYNC_S + 1)
    warned: list[str] = []
    monkeypatch.setattr(storage_config.log, "warning", lambda msg, *a: warned.append(msg % a))
    storage_config.reconcile(now=late)
    assert [p["id"] for p in _row().body["pools"]] == ["default", "hdd0"]
    # Not even attempted (the guard would refuse it, every tick).
    assert not [w for w in warned if "drained-pool removal refused" in w]
    # The launch's placement ends: the next pass removes it.
    PlacementDisk.objects.filter(placement=placement).delete()
    _heartbeat(1, at=late + timedelta(seconds=5))
    storage_config.reconcile(now=late + timedelta(seconds=10))
    assert [p["id"] for p in _row().body["pools"]] == ["default"]
