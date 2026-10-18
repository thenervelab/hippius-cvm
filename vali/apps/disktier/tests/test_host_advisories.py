"""§18.5 host disk advisories from the §18.10 inventory: the upsert and
its transitions, resolution only from a complete report, the operator
feed, the ops-only metrics (no serial / by-id / subject in a label), the
retention, and the suggested-action table covering every crate code."""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from django.conf import settings
from django.urls import reverse
from rest_framework.test import APIClient

from apps.disktier import gc, host_advisories
from apps.disktier.host_advisories import SUGGESTED_ACTIONS, merge_advisories
from apps.disktier.host_inventory import record_host_inventory
from apps.disktier.models import HostDiskAdvisory, HostDiskAdvisoryEvent, HostInventorySection
from apps.scheduler.tests.factories import node_id

from .conftest import FAMILY_A, FAMILY_B, bind, ss58_encode

pytestmark = pytest.mark.django_db

NODE = node_id(1)
NOW = datetime(2026, 10, 17, 12, tzinfo=UTC)


@pytest.fixture(autouse=True)
def _no_pushgateway(settings: Any) -> None:
    # A report pushes the node's metrics; tests that want it set the URL.
    settings.VALI_SYNTHETIC_PUSHGATEWAY_URL = ""


HEADERS = {
    "HTTP_X_HIPPIUS_ACTING_FAMILY": ss58_encode(FAMILY_A),
    "HTTP_X_HIPPIUS_ACTING_USER": "user-42",
}


def _adv(subject: str, code: str, severity: str = "warning", **over: Any) -> dict[str, Any]:
    kind = "dedicated_disk" if subject.startswith("wwn-") else "device"
    a = {
        "subject_kind": kind,
        "subject": subject,
        "code": code,
        "severity": severity,
        "count": 1,
        "value": 0,
        "first_seen_unix": int(NOW.timestamp()) - 3600,
        "last_seen_unix": int(NOW.timestamp()),
    }
    a.update(over)
    return a


def _storage(advisories: list[dict[str, Any]], *, status: str = "ok", truncated: bool = False):
    return {
        "status": status,
        "devices": [],
        "advisories": advisories,
        "advisories_truncated": truncated,
        "devices_truncated": False,
    }


def _transitions() -> list[tuple[str, str, str]]:
    return list(
        HostDiskAdvisoryEvent.objects.order_by("id").values_list("code", "transition", "severity")
    )


def test_open_update_escalate_and_resolve() -> None:
    merge_advisories(NODE, _storage([_adv("sda", "pending_sectors")]), NOW)
    merge_advisories(
        NODE, _storage([_adv("sda", "pending_sectors", count=5)]), NOW + timedelta(hours=6)
    )
    row = HostDiskAdvisory.objects.get()
    assert (row.count, row.severity) == (5, "warning")
    merge_advisories(NODE, _storage([_adv("sda", "pending_sectors", "critical")]), NOW)
    merge_advisories(NODE, _storage([_adv("sda", "pending_sectors", "info")]), NOW)
    merge_advisories(NODE, _storage([]), NOW + timedelta(hours=12))
    assert HostDiskAdvisory.objects.get().resolved_at == NOW + timedelta(hours=12)
    # Back again: reopened.
    merge_advisories(NODE, _storage([_adv("sda", "pending_sectors")]), NOW + timedelta(days=1))
    assert HostDiskAdvisory.objects.get().resolved_at is None
    assert _transitions() == [
        ("pending_sectors", "opened", "warning"),
        ("pending_sectors", "escalated", "critical"),
        ("pending_sectors", "deescalated", "info"),
        ("pending_sectors", "resolved", "info"),
        ("pending_sectors", "opened", "warning"),
    ]


@pytest.mark.parametrize(
    ("status", "truncated"), [("partial", False), ("timeout", False), ("ok", True)]
)
def test_only_a_complete_report_resolves(status: str, truncated: bool) -> None:
    merge_advisories(NODE, _storage([_adv("sda", "kernel_io_error")]), NOW)
    merge_advisories(NODE, _storage([], status=status, truncated=truncated), NOW)
    assert HostDiskAdvisory.objects.get().resolved_at is None


def test_a_report_feeds_the_advisories_through_the_merge() -> None:
    body = {
        "sequence": 1,
        "sections": {"storage": _storage([_adv("md0", "md_degraded", "critical")])},
    }
    record_host_inventory(NODE, "m", body, {"storage": "0" * 64}, reported_at=NOW, now=NOW)
    assert HostDiskAdvisory.objects.get().code == "md_degraded"
    # A report without a storage section leaves them alone.
    body = {"sequence": 2, "sections": {"cpu": {"status": "ok"}}}
    record_host_inventory(NODE, "m", body, {"cpu": "0" * 64}, reported_at=NOW, now=NOW)
    assert HostDiskAdvisory.objects.get().resolved_at is None


def test_wild_counts_and_times_are_clamped_not_fatal() -> None:
    wild = _adv(
        "sda", "reallocated_sectors", count=2**64 - 1, first_seen_unix=2**63 - 1, last_seen_unix=-5
    )
    merge_advisories(NODE, _storage([wild]), NOW)
    row = HostDiskAdvisory.objects.get()
    assert row.count == 2**63 - 1
    assert row.first_seen == NOW + timedelta(seconds=settings.VALI_HOST_INVENTORY_MAX_SKEW_S)
    assert row.last_seen == row.first_seen


def test_partial_reports_cannot_pile_up_open_advisories(settings: Any) -> None:
    from apps.disktier import host_advisories as ha

    settings.VALI_HOST_INVENTORY_MAX_SKEW_S = 300
    for batch in range(5):
        advisories = [_adv(f"sd{chr(97 + batch)}{i}", "fs_error") for i in range(1, 65)]
        merge_advisories(NODE, _storage(advisories, status="partial"), NOW + timedelta(hours=batch))
    open_rows = HostDiskAdvisory.objects.filter(resolved_at__isnull=True)
    assert open_rows.count() == ha.MAX_OPEN_PER_NODE
    # The oldest batch went first.
    assert not open_rows.filter(subject_ref__startswith="sda").exists()
    # A week without being carried: resolved, even from a partial report.
    merge_advisories(NODE, _storage([], status="partial"), NOW + timedelta(days=8))
    assert not HostDiskAdvisory.objects.filter(resolved_at__isnull=True).exists()


# ─── the operator feed ───────────────────────────────────────────────


@pytest.fixture
def owned(chain: dict[str, Any]) -> dict[str, Any]:
    bind(chain, NODE, FAMILY_A)
    return chain


def _url(query: str = "") -> str:
    return reverse("operator_host_disk_advisories", kwargs={"node_id": NODE}) + query


def test_the_feed_groups_by_subject_with_actions(
    owned: dict[str, Any], operator_client: APIClient
) -> None:
    from django.utils import timezone

    now = timezone.now()
    HostInventorySection.objects.create(
        miner_node_id=NODE,
        section="storage",
        digest="0" * 64,
        body=_storage([]),
        status="ok",
        reported_at=now,
        sequence=1,
        received_at=now,
    )
    merge_advisories(
        NODE,
        _storage(
            [
                _adv("sda", "pending_sectors", "warning"),
                _adv("sda", "smart_overall_failed", "critical"),
                _adv("wwn-0x5000c5", "temperature_high", "info"),
                _adv("sdc", "udma_crc_errors"),
            ]
        ),
        now - timedelta(days=2),
    )
    merge_advisories(
        NODE,
        _storage(
            [
                _adv("sda", "pending_sectors", "warning"),
                _adv("sda", "smart_overall_failed", "critical"),
                _adv("wwn-0x5000c5", "temperature_high", "info"),
            ]
        ),
        now - timedelta(days=1),
    )
    body = operator_client.get(_url(), **HEADERS).json()
    assert body["verified"] is False
    assert body["collector"] == {"status": "ok"}
    subjects = {(s["kind"], s["ref"]): s for s in body["subjects"]}
    assert set(subjects) == {("device", "sda"), ("dedicated_disk", "wwn-0x5000c5")}
    sda = subjects[("device", "sda")]
    assert sda["severity"] == "critical"
    assert [(a["code"], a["suggested_action"]) for a in sda["advisories"]] == [
        ("pending_sectors", "replace_disk"),
        ("smart_overall_failed", "replace_disk"),
    ]
    assert "history" not in body

    full = operator_client.get(_url("?include_resolved=true&history_days=7"), **HEADERS).json()
    sdc = next(s for s in full["subjects"] if s["ref"] == "sdc")
    assert sdc["severity"] == "ok"
    assert sdc["advisories"][0]["resolved_at"] is not None
    assert full["history"][0]["transition"] == "resolved"

    for bad in ("?history_days=91", "?history_days=-1", "?include_resolved=yes"):
        assert operator_client.get(_url(bad), **HEADERS).status_code == 400


def test_the_feed_before_any_report(owned: dict[str, Any], operator_client: APIClient) -> None:
    body = operator_client.get(_url(), **HEADERS).json()
    assert (body["collector"], body["subjects"], body["reported_at"]) == (
        {"status": "never"},
        [],
        None,
    )


def test_the_feed_is_the_nodes_family_only(
    chain: dict[str, Any], operator_client: APIClient
) -> None:
    bind(chain, NODE, FAMILY_B)
    response = operator_client.get(_url(), **HEADERS)
    assert response.status_code == 403
    assert response.json()["code"] == "not-family-node"


# ─── metrics ─────────────────────────────────────────────────────────


@pytest.fixture
def pushed(monkeypatch: pytest.MonkeyPatch, settings: Any) -> list[dict[str, Any]]:
    from apps.synthetic import metrics

    calls: list[dict[str, Any]] = []
    # pytest-django's `settings` (not monkeypatch): both restore, and mixed
    # they leak the autouse override past the test.
    settings.VALI_SYNTHETIC_PUSHGATEWAY_URL = "http://pgw:9091"
    monkeypatch.setattr(
        metrics, "push", lambda ms, **kw: calls.append({"text": ms.render(), **kw}) or True
    )
    return calls


def test_metrics_carry_models_and_counts_never_a_serial(pushed: list[dict[str, Any]]) -> None:
    sections = {
        "cpu": {"status": "ok", "model": "AMD EPYC 9254"},
        "system": {"status": "ok", "bios_version": "2.24.1", "serial": "KATSERIAL1"},
        "storage": _storage(
            [
                _adv("wwn-0x5000c500a1b2c3d4", "pending_sectors"),
                _adv("ata-M_KATSERIAL2", "pending_sectors"),
            ]
        ),
    }
    body = {"sequence": 1, "sections": sections}
    digests = {name: "0" * 64 for name in sections}
    record_host_inventory(NODE, "m", body, digests, reported_at=NOW, now=NOW)
    (call,) = pushed
    assert (call["job"], call["grouping_key"], call["replace"]) == (
        "vali-host-inventory",
        {"node_id": NODE},
        True,
    )
    text = call["text"]
    assert 'cpu_model="AMD EPYC 9254"' in text and 'bios_version="2.24.1"' in text
    assert (
        f'hippius_host_advisory{{code="pending_sectors",kind="dedicated_disk",node_id="{NODE}",'
        'severity="warning"} 1'
    ) in text
    for secret in ("KATSERIAL", "wwn-0x", "ata-"):
        assert secret not in text


def test_a_failed_push_never_costs_the_report(
    monkeypatch: pytest.MonkeyPatch, settings: Any
) -> None:
    from apps.synthetic import metrics

    settings.VALI_SYNTHETIC_PUSHGATEWAY_URL = "http://pgw:9091"

    def boom(*_a: Any, **_k: Any) -> bool:
        raise OSError("gateway down")

    monkeypatch.setattr(metrics, "push", boom)
    body = {"sequence": 1, "sections": {"cpu": {"status": "ok"}}}
    record_host_inventory(NODE, "m", body, {"cpu": "0" * 64}, reported_at=NOW, now=NOW)
    assert HostInventorySection.objects.filter(miner_node_id=NODE).count() == 1


def test_no_gateway_no_push(pushed: list[dict[str, Any]], settings: Any) -> None:
    settings.VALI_SYNTHETIC_PUSHGATEWAY_URL = ""
    host_advisories.push_node_metrics(NODE)
    assert pushed == []


# ─── retention, vocabulary ───────────────────────────────────────────


def test_resolved_advisories_and_old_transitions_are_reaped() -> None:
    def row(ref: str, resolved_days: int | None) -> None:
        HostDiskAdvisory.objects.create(
            miner_node_id=NODE,
            subject_kind="device",
            subject_ref=ref,
            code="fs_error",
            severity="warning",
            first_seen=NOW,
            last_seen=NOW,
            resolved_at=None if resolved_days is None else NOW - timedelta(days=resolved_days),
            updated_at=NOW,
        )

    row("sda", None)
    row("sdb", 89)
    row("sdc", 91)
    for days in (179, 181):
        HostDiskAdvisoryEvent.objects.create(
            miner_node_id=NODE,
            subject_kind="device",
            subject_ref="sda",
            code="fs_error",
            transition="opened",
            severity="warning",
            at=NOW - timedelta(days=days),
        )
    deleted = gc.gc(now=NOW)
    assert (deleted["host_disk_advisory_resolved"], deleted["host_disk_advisory_event"]) == (1, 1)
    assert sorted(HostDiskAdvisory.objects.values_list("subject_ref", flat=True)) == ["sda", "sdb"]


def test_every_crate_code_has_a_suggested_action_entry() -> None:
    src = (Path(settings.BASE_DIR).parent / "hippius-host-inventory" / "src" / "lib.rs").read_text()
    block = re.search(r"pub enum AdvisoryCode \{(.*?)\n\}", src, re.S)
    assert block
    variants = re.findall(r"^\s{4}([A-Z][A-Za-z0-9]*),", block.group(1), re.M)
    assert len(variants) >= 27
    codes = {re.sub(r"(?<!^)(?=[A-Z])", "_", v).lower() for v in variants}
    assert len(codes) == len(variants)
    assert codes == set(SUGGESTED_ACTIONS)
    allowed = {
        "replace_disk",
        "check_cabling",
        "check_cooling",
        "rebuild_array",
        "fsck_and_remount",
        "free_space_or_drain_pool",
        "switch_controller_to_hba_mode",
        "install_smartmontools",
        "investigate_collector_timeout",
        "request_reprobe",
    }
    assert {a for a in SUGGESTED_ACTIONS.values() if a} <= allowed


def test_the_feed_history_is_bounded(owned: dict[str, Any], operator_client: APIClient) -> None:
    from django.utils import timezone

    now = timezone.now()
    HostDiskAdvisoryEvent.objects.bulk_create(
        HostDiskAdvisoryEvent(
            miner_node_id=NODE,
            subject_kind="device",
            subject_ref="sda",
            code="fs_error",
            transition="opened",
            severity="warning",
            at=now - timedelta(minutes=i),
        )
        for i in range(host_advisories.HISTORY_MAX + 5)
    )
    body = operator_client.get(_url("?history_days=1"), **HEADERS).json()
    assert len(body["history"]) == host_advisories.HISTORY_MAX
    assert body["history_truncated"] is True
