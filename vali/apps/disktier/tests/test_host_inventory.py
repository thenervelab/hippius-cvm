"""§18.10 host inventory: the per-section merge, the replay floor, the
hourly budget, the change log and its retention — and who may read it
(UNTRUSTED, owner-facing only: nothing that decides may import it)."""

from __future__ import annotations

import ast
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from apps.disktier import gc
from apps.disktier.host_inventory import InventoryRefused, record_host_inventory
from apps.disktier.models import HostInventoryChange, HostInventorySection, HostInventoryState
from apps.scheduler.tests.factories import node_id

pytestmark = pytest.mark.django_db

NODE = node_id(1)
NOW = datetime(2026, 10, 17, 12, tzinfo=UTC)


@pytest.fixture(autouse=True)
def _no_pushgateway(settings: Any) -> None:
    # A report pushes the node's metrics; tests that want it set the URL.
    settings.VALI_SYNTHETIC_PUSHGATEWAY_URL = ""


def _record(
    seq: int,
    sections: dict[str, Any],
    *,
    now: datetime = NOW,
    node: str = NODE,
    miner_id: str = "miner-1",
) -> Any:
    body = {"sequence": seq, "report": "change", "sections": sections}
    digests = {name: f"{hash(repr(v)) & (2**64 - 1):064x}" for name, v in sections.items()}
    return record_host_inventory(node, miner_id, body, digests, reported_at=now, now=now)


def test_a_section_is_replaced_whole_and_an_absent_one_kept() -> None:
    _record(1, {"cpu": {"status": "ok", "cores": 24}, "software": {"status": "ok", "kernel": "a"}})
    out = _record(2, {"software": {"status": "partial", "kernel": "b"}})
    assert out.sections == ("software",)
    assert out.changed == ("software",)
    rows = {r.section: r for r in HostInventorySection.objects.filter(miner_node_id=NODE)}
    assert rows["cpu"].body == {"status": "ok", "cores": 24}
    assert rows["cpu"].sequence == 1
    assert rows["software"].body == {"status": "partial", "kernel": "b"}
    assert rows["software"].status == "partial"
    assert rows["software"].sequence == 2


def test_a_change_records_which_fields_changed_and_an_identical_report_nothing() -> None:
    _record(1, {"system": {"status": "ok", "bios_version": "2.1", "vendor": "Dell"}})
    _record(2, {"system": {"status": "ok", "bios_version": "2.1", "vendor": "Dell"}})
    assert not HostInventoryChange.objects.exists()
    _record(3, {"system": {"status": "ok", "bios_version": "2.4", "bmc_present": True}})
    change = HostInventoryChange.objects.get()
    assert (change.section, change.fields) == ("system", ["bios_version", "bmc_present", "vendor"])


def test_the_sequence_must_rise() -> None:
    _record(5, {"cpu": {"status": "ok"}})
    for seq in (5, 4):
        with pytest.raises(InventoryRefused) as exc:
            _record(seq, {"cpu": {"status": "timeout"}})
        assert exc.value.category == "replay"
    assert HostInventorySection.objects.get().status == "ok"
    # A sequence 0 first report is accepted (the floor starts unset).
    _record(0, {"cpu": {"status": "ok"}}, node=node_id(2))


def test_a_new_registry_identity_starts_a_new_floor() -> None:
    # A reinstall: same on-chain node, new identity, its sequence from 1.
    _record(900, {"cpu": {"status": "ok"}}, miner_id="miner-old")
    _record(1, {"cpu": {"status": "partial"}}, miner_id="miner-new")
    state = HostInventoryState.objects.get(pk=NODE)
    assert (state.miner_id, state.last_sequence) == ("miner-new", 1)
    with pytest.raises(InventoryRefused):
        _record(1, {"cpu": {"status": "ok"}}, miner_id="miner-new")


def test_the_budget_is_spent_by_refused_reports_too(settings: Any) -> None:
    settings.VALI_HOST_INVENTORY_MAX_PER_HOUR = 2
    _record(5, {"cpu": {"status": "ok"}})
    with pytest.raises(InventoryRefused):
        _record(1, {"cpu": {"status": "ok"}})  # replay, still counted
    with pytest.raises(InventoryRefused) as exc:
        _record(6, {"cpu": {"status": "ok"}})
    assert exc.value.category == "rate-limited"
    assert exc.value.retry_after_s == 3600
    # The window rolls after an hour.
    _record(6, {"cpu": {"status": "ok"}}, now=NOW + timedelta(hours=1))
    assert HostInventoryState.objects.get(pk=NODE).last_sequence == 6


def test_digests_must_match_the_sections() -> None:
    body = {"sequence": 1, "sections": {"cpu": {"status": "ok"}}}
    with pytest.raises(InventoryRefused):
        record_host_inventory(NODE, "m", body, {"pci": "0" * 64}, reported_at=NOW, now=NOW)
    assert not HostInventoryState.objects.exists()


def test_changes_are_reaped_past_their_retention() -> None:
    for days in (1, 179, 181):
        HostInventoryChange.objects.create(
            miner_node_id=NODE, section="cpu", at=NOW - timedelta(days=days)
        )
    assert gc.gc(now=NOW)["host_inventory_change"] == 1
    assert HostInventoryChange.objects.count() == 2


# ─── who may read it ─────────────────────────────────────────────────

_APPS = Path(__file__).resolve().parents[2]
#: The only modules that may name the host inventory: its own module and
#: models, the retention sweep, the migration, the Edge-relayed ingest and
#: the owner-scoped operator reads. Tiers, placement, cordon, pay, strikes and billing never do.
_ALLOWED = {
    "disktier/host_inventory.py",
    "disktier/host_advisories.py",
    "disktier/models.py",
    "disktier/gc.py",
    # The owner-scoped operator reads (serials stay behind the family check).
    "disktier/hardware_views.py",
    "telemetry/views.py",
    "telemetry/verifier.py",
    "telemetry/urls.py",
    "telemetry/schemas.py",
    # vali/vali/settings.py: the flags and the throttle scope.
    "settings.py",
}
_NAMES = (
    "HostInventory",
    "host_inventory",
    "hostinventory",
    "HostDiskAdvisory",
    "host_advisor",
    "hostdiskadvisory",
)


def _names_in(path: Path) -> set[str]:
    found: set[str] = set()
    for node in ast.walk(ast.parse(path.read_text())):
        names: list[str] = []
        if isinstance(node, ast.ImportFrom):
            names = [node.module or "", *(a.name for a in node.names)]
        elif isinstance(node, ast.Import):
            names = [a.name for a in node.names]
        elif isinstance(node, ast.Attribute):
            names = [node.attr]
        elif isinstance(node, ast.Name):
            names = [node.id]
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            # `apps.get_model("disktier", "HostInventorySection")`, raw SQL.
            names = [node.value]
        found.update(n for n in names if any(k in n for k in _NAMES))
    return found


def test_only_the_ingest_and_its_own_module_name_the_host_inventory() -> None:
    offenders = {}
    paths = [*_APPS.rglob("*.py"), *(_APPS.parent / "vali").rglob("*.py")]
    for path in sorted(paths):
        rel = path.relative_to(_APPS).as_posix() if path.is_relative_to(_APPS) else path.name
        if "/tests/" in rel or "/migrations/" in rel or rel in _ALLOWED:
            continue
        if names := _names_in(path):
            offenders[rel] = sorted(names)
    assert offenders == {}


def test_the_isolation_check_sees_an_import_and_a_model_lookup(tmp_path: Path) -> None:
    assert "HostInventoryChange" in _names_in(Path(__file__).parents[1] / "gc.py")
    probe = tmp_path / "probe.py"
    probe.write_text(
        'from django.apps import apps\napps.get_model("disktier", "HostInventorySection")\n'
    )
    assert _names_in(probe) == {"HostInventorySection"}
