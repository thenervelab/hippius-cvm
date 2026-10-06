"""Capacity v2 policy writes: `vali_set_miner_capacity`'s new flags, the
audited writer (`capacity_admin`), the 0013 backfill, and the rule that
the chain refresh never touches a policy column."""

from __future__ import annotations

import importlib
from decimal import Decimal
from io import StringIO

import pytest
from django.apps import apps as django_apps
from django.contrib.admin.sites import site as admin_site
from django.core.management import CommandError, call_command
from django.db import transaction
from django.test import override_settings
from django.utils import timezone

from apps.scheduler import capacity_admin, service
from apps.scheduler.chain import ChainSnapshot, MinerView
from apps.scheduler.models import (
    CapacityTrustClass,
    MinerCapacity,
    MinerCapacityAudit,
    PlacementStatus,
)

from .factories import make_placement, make_vm, node_id

pytestmark = pytest.mark.django_db

NODE = node_id(4)


def _row(**over: object) -> MinerCapacity:
    fields: dict[str, object] = dict(
        miner_node_id=NODE,
        status="active",
        capacity_slots=8,
        observed_epoch=10,
        data_epoch=10,
        refreshed_at=timezone.now(),
    )
    fields.update(over)
    return MinerCapacity.objects.create(**fields)


def _run(*args: str, by: str | None = "ops", reason: str | None = "why") -> str:
    out, err = StringIO(), StringIO()
    extra = ["--by", by] if by is not None else []
    extra += ["--reason", reason] if reason is not None else []
    call_command(
        "vali_set_miner_capacity", "--node-id", NODE, *args, *extra, stdout=out, stderr=err
    )
    return out.getvalue()


def _audits(field: str | None = None) -> list[MinerCapacityAudit]:
    qs = MinerCapacityAudit.objects.filter(miner_node_id=NODE).order_by("field")
    return list(qs.filter(field=field) if field else qs)


def _place(n: int, resource_class: str = "medium") -> None:
    for i in range(n):
        make_placement(
            make_vm(f"vm-{i}", f"lease-{i}"),
            NODE,
            status=PlacementStatus.BOUND.value,
            resource_class=resource_class,
        )


# ─── the audit trail ────────────────────────────────────────────────


def test_anchor_write_lands_one_audit_row_per_field() -> None:
    _row()
    _run("--cpus", "24", "--memory-mb", "125000")
    rows = _audits()
    assert [(a.field, a.before, a.after, a.actor, a.reason) for a in rows] == [
        ("total_cpus", None, 24, "op:ops", "why"),
        ("total_memory_mb", None, 125000, "op:ops", "why"),
    ]


def test_dry_run_and_no_op_audit_nothing() -> None:
    _row(capacity_slots=32)
    _run("--slots", "48", "--dry-run", by=None, reason=None)
    _run("--slots", "32")
    assert _audits() == []
    assert MinerCapacity.objects.get().capacity_slots == 32


def test_reason_is_required_on_a_real_write() -> None:
    _row()
    with pytest.raises(CommandError, match="--reason"):
        _run("--slots", "16", reason=None)
    with pytest.raises(CommandError, match="--reason"):
        _run("--slots", "16", reason="   ")
    assert MinerCapacity.objects.get().capacity_slots == 8
    assert _audits() == []


def test_nothing_to_do_is_refused() -> None:
    _row()
    with pytest.raises(CommandError, match="nothing to do"):
        _run()


# ─── --slots ────────────────────────────────────────────────────────


def test_slots_sets_the_vm_ceiling_and_audits() -> None:
    _row()
    _run("--slots", "48")
    assert MinerCapacity.objects.get().capacity_slots == 48
    [a] = _audits("capacity_slots")
    assert (a.before, a.after) == (8, 48)


def test_slots_below_placed_vms_is_refused() -> None:
    _row(capacity_slots=32)
    _place(3)
    with pytest.raises(CommandError, match="below the 3 VM"):
        _run("--slots", "2")
    _run("--slots", "3")  # equal to the load is fine
    assert MinerCapacity.objects.get().capacity_slots == 3


@pytest.mark.parametrize("value", ["0", "1025", "-1"])
def test_slots_out_of_range(value: str) -> None:
    _row()
    with pytest.raises(CommandError, match="out of range"):
        _run("--slots", value)
    assert MinerCapacity.objects.get().capacity_slots == 8


# ─── --cpu-ratio ────────────────────────────────────────────────────


def test_cpu_ratio_sets_and_default_clears() -> None:
    _row()
    _run("--cpu-ratio", "2")
    assert MinerCapacity.objects.get().cpu_ratio == Decimal("2.00")
    _run("--cpu-ratio-default")
    assert MinerCapacity.objects.get().cpu_ratio is None
    history = MinerCapacityAudit.objects.filter(field="cpu_ratio").order_by("created_at")
    assert [(a.before, a.after) for a in history] == [(None, "2.00"), ("2.00", None)]


@pytest.mark.parametrize("value", ["0.99", "4.01", "abc", "nan", "inf"])
def test_cpu_ratio_out_of_range(value: str) -> None:
    _row()
    with pytest.raises(CommandError, match="--cpu-ratio"):
        _run("--cpu-ratio", value)
    assert MinerCapacity.objects.get().cpu_ratio is None


def test_cpu_ratio_flags_are_exclusive() -> None:
    _row()
    with pytest.raises(CommandError):
        _run("--cpu-ratio", "2", "--cpu-ratio-default")


# ─── --trust ────────────────────────────────────────────────────────


def test_trust_operator_needs_an_anchor() -> None:
    _row()
    with pytest.raises(CommandError, match="needs a hardware anchor"):
        _run("--trust", "operator")
    assert MinerCapacity.objects.get().trust_class == CapacityTrustClass.EARNED


def test_trust_operator_with_anchor_on_the_same_call() -> None:
    _row()
    _run("--trust", "operator", "--cpus", "24", "--memory-mb", "125000")
    row = MinerCapacity.objects.get()
    assert row.trust_class == CapacityTrustClass.OPERATOR
    assert (row.total_cpus, row.total_memory_mb) == (24, 125000)
    assert [a.field for a in _audits()] == ["total_cpus", "total_memory_mb", "trust_class"]


def test_clearing_an_operator_anchor_needs_the_earned_class() -> None:
    _row(total_cpus=24, total_memory_mb=125000, trust_class=CapacityTrustClass.OPERATOR)
    with pytest.raises(CommandError, match="needs a hardware anchor"):
        _run("--clear")
    _run("--clear", "--trust", "earned")
    row = MinerCapacity.objects.get()
    assert row.total_memory_mb is None and row.trust_class == CapacityTrustClass.EARNED


# ─── earned ─────────────────────────────────────────────────────────


def test_earned_grant_sets_the_ceiling_and_audits_it() -> None:
    _row()
    _run("--earned-grant", "10", "20", "65536")
    row = MinerCapacity.objects.get()
    assert (row.earned_vms, row.earned_vcpus, row.earned_memory_mb) == (10, 20, 65536)
    assert row.earned_last_reason == "op-grant"
    # Working state (reason, timestamp) is not audited; the decision is.
    assert [a.field for a in _audits()] == ["earned_memory_mb", "earned_vcpus", "earned_vms"]


@override_settings(VALI_CAPACITY_EARN_HARD_CAP_VMS=64)
def test_earned_grant_is_bounded_by_the_hard_caps() -> None:
    _row()
    with pytest.raises(CommandError, match="VMS 65 out of range"):
        _run("--earned-grant", "65", "8", "32768")
    with pytest.raises(CommandError, match="VCPUS 0 out of range"):
        _run("--earned-grant", "4", "0", "32768")
    assert MinerCapacity.objects.get().earned_vms is None


def test_earned_reset_returns_to_the_floor_and_restarts_the_proof() -> None:
    now = timezone.now()
    _row(
        earned_vms=12,
        earned_vcpus=24,
        earned_memory_mb=98304,
        proven_peak_vms=10,
        proven_peak_vcpus=20,
        proven_peak_memory_mb=81920,
        proven_at=now,
        candidate_vms=11,
        candidate_since=now,
    )
    _run("--earned-reset")
    row = MinerCapacity.objects.get()
    assert (row.earned_vms, row.earned_vcpus, row.earned_memory_mb) == (None, None, None)
    assert (row.proven_peak_vms, row.proven_peak_vcpus, row.proven_peak_memory_mb) == (0, 0, 0)
    assert row.proven_at is None and row.candidate_since is None and row.candidate_vms == 0
    assert row.earned_last_reason == "op-reset"
    assert {a.field for a in _audits()} == {
        "earned_vms",
        "earned_vcpus",
        "earned_memory_mb",
        "proven_peak_vms",
        "proven_peak_vcpus",
        "proven_peak_memory_mb",
    }


def test_earned_reset_and_grant_are_exclusive() -> None:
    _row()
    with pytest.raises(CommandError):
        _run("--earned-reset", "--earned-grant", "4", "8", "32768")


# ─── --note / --show ────────────────────────────────────────────────


def test_note_records_a_decision_and_changes_nothing() -> None:
    _row(capacity_slots=32)
    _run("--note", reason="manual ORM bump 8->32 on 2026-09-26, recorded retroactively")
    [a] = _audits()
    assert (a.field, a.before, a.after) == ("note", None, None)
    assert a.reason.startswith("manual ORM bump")
    assert MinerCapacity.objects.get().capacity_slots == 32


def test_note_needs_a_reason_even_on_a_dry_run() -> None:
    _row()
    with pytest.raises(CommandError, match="--note records --reason"):
        _run("--note", "--dry-run", by=None, reason=None)


def test_show_prints_the_policy_and_writes_nothing() -> None:
    _row(total_cpus=24, total_memory_mb=125000, capacity_slots=32)
    _place(2)
    out = _run("--show", by=None, reason=None)
    assert "capacity_slots" in out and " 32" in out
    assert "2 VMs / 4 vCPU / 16384 MiB" in out
    assert _audits() == []


def test_show_refuses_to_be_combined_with_a_write() -> None:
    _row()
    with pytest.raises(CommandError, match="--show writes nothing"):
        _run("--show", "--slots", "16")
    assert MinerCapacity.objects.get().capacity_slots == 8


def test_a_failed_check_writes_nothing_at_all() -> None:
    """Atomic: `--slots` is valid, `--trust operator` is not — neither lands."""
    _row()
    with pytest.raises(CommandError, match="needs a hardware anchor"):
        _run("--slots", "16", "--trust", "operator")
    assert MinerCapacity.objects.get().capacity_slots == 8
    assert _audits() == []


# ─── capacity_admin ─────────────────────────────────────────────────


def test_apply_refuses_a_non_policy_column() -> None:
    row = _row()
    with transaction.atomic(), pytest.raises(ValueError, match="not a capacity-policy column"):
        capacity_admin.apply_capacity_change(row, {"status": "inactive"}, actor="x", reason="y")
    assert MinerCapacity.objects.get().status == "active"


@pytest.mark.django_db(transaction=True)
def test_apply_needs_a_transaction() -> None:
    """Outside `transaction.atomic()` the diff would be taken on an
    unlocked row and could audit a `before` that was never true."""
    row = _row()
    with pytest.raises(RuntimeError, match="transaction"):
        capacity_admin.apply_capacity_change(row, {"capacity_slots": 9}, actor="x", reason="y")
    assert MinerCapacity.objects.get().capacity_slots == 8


def test_apply_is_targeted_and_does_not_roll_back_concurrent_writes() -> None:
    row = _row(quality=7)
    MinerCapacity.objects.filter(pk=row.pk).update(quality=99, status="inactive")
    with transaction.atomic():
        capacity_admin.apply_capacity_change(row, {"capacity_slots": 9}, actor="x", reason="y")
    fresh = MinerCapacity.objects.get()
    assert (fresh.capacity_slots, fresh.quality, fresh.status) == (9, 99, "inactive")


def test_apply_audits_decisions_but_not_working_state() -> None:
    row = _row()
    with transaction.atomic():
        applied = capacity_admin.apply_capacity_change(
            row,
            {"earned_vms": 6, "candidate_vms": 5, "candidate_since": timezone.now()},
            actor="tick:earn",
            reason="proof-held",
        )
    assert {c.field for c in applied} == {"earned_vms", "candidate_vms", "candidate_since"}
    assert [(a.field, a.actor) for a in _audits()] == [("earned_vms", "tick:earn")]


# ─── the chain refresh preserves policy ─────────────────────────────


def test_chain_refresh_never_touches_a_policy_column() -> None:
    now = timezone.now()
    policy = dict(
        capacity_slots=48,
        total_cpus=24,
        total_memory_mb=125000,
        trust_class=CapacityTrustClass.OPERATOR,
        cpu_ratio=Decimal("2.00"),
        earned_vms=6,
        earned_vcpus=12,
        earned_memory_mb=49152,
        proven_peak_vms=5,
        proven_peak_vcpus=10,
        proven_peak_memory_mb=40960,
        proven_at=now,
        candidate_vms=5,
        candidate_since=now,
        declared_cpu_budget=40,
        declared_memory_mb_budget=98304,
        declared_asid_capacity=99,
        declared_asid_used=3,
        declared_at=now,
    )
    _row(**policy)
    snapshot = ChainSnapshot(
        current_epoch=20,
        miners=(MinerView(
                node_id=NODE,
                status="active",
                last_transition_epoch=1,
                data_epoch=20,
                quality=5,
            ),),
    )
    service.refresh_miner_capacity(snapshot)
    row = MinerCapacity.objects.get()
    assert row.observed_epoch == 20  # the refresh did run
    for field, value in policy.items():
        assert getattr(row, field) == value, field


# ─── 0013 backfill ──────────────────────────────────────────────────


def test_backfill_marks_only_anchored_rows_operator() -> None:
    anchored = _row(total_cpus=24, total_memory_mb=125000)
    bare = _row(miner_node_id=node_id(5))
    migration = importlib.import_module("apps.scheduler.migrations.0013_capacity_v2")
    migration._forward(django_apps, None)
    anchored.refresh_from_db()
    bare.refresh_from_db()
    assert anchored.trust_class == CapacityTrustClass.OPERATOR
    assert bare.trust_class == CapacityTrustClass.EARNED


def test_new_rows_default_to_earned() -> None:
    assert _row().trust_class == CapacityTrustClass.EARNED


# ─── admin ──────────────────────────────────────────────────────────


def test_admin_cannot_edit_any_policy_column() -> None:
    model_admin = admin_site._registry[MinerCapacity]
    readonly = set(model_admin.readonly_fields)
    assert capacity_admin.AUDITED_FIELDS <= readonly
    assert capacity_admin.WORKING_FIELDS <= readonly
    audit_admin = admin_site._registry[MinerCapacityAudit]
    assert not audit_admin.has_change_permission(None)
    assert not audit_admin.has_delete_permission(None)
    assert not audit_admin.has_add_permission(None)


# ─── capacity_config ────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("VALI_SCHEDULER_CPU_OVERCOMMIT", "0.5"),
        ("VALI_SCHEDULER_CPU_OVERCOMMIT", "8"),
        ("VALI_SCHEDULER_CPU_OVERCOMMIT", "nan"),
        ("VALI_SCHEDULER_CPU_OVERCOMMIT", "two"),
        ("VALI_SCHEDULER_PER_VM_OVERHEAD_MB", "-1"),
        ("VALI_SCHEDULER_PER_VM_OVERHEAD_MB", "lots"),
    ],
)
def test_a_malformed_knob_fails_loudly(name: str, value: str) -> None:
    from django.core.exceptions import ImproperlyConfigured

    from apps.scheduler import capacity_config

    getter = {
        "VALI_SCHEDULER_CPU_OVERCOMMIT": capacity_config.cpu_overcommit_default,
        "VALI_SCHEDULER_PER_VM_OVERHEAD_MB": capacity_config.per_vm_overhead_mb,
    }[name]
    with override_settings(**{name: value}), pytest.raises(ImproperlyConfigured, match=name):
        getter()


def test_knob_defaults_match_the_approved_policy() -> None:
    from apps.scheduler import capacity_config as c

    assert c.cpu_overcommit_default() == Decimal("2.0")
    assert c.resource_admission_enabled() is False
    assert (c.earn_floor_vms(), c.earn_floor_vcpus(), c.earn_floor_memory_mb()) == (4, 8, 32768)
    assert c.earn_hard_cap_vms() == 64
    assert c.earn_growth() == Decimal("1.5")
    assert c.earn_util_trigger() == Decimal("0.8")
    assert c.earn_hold_s() == 1800
    assert c.earned_inflight_max() == 2
    assert c.asid_reserve() == 3


# ─── review follow-ups ──────────────────────────────────────────────


def test_half_anchored_row_stays_earned_and_remains_operable() -> None:
    """Memory-only anchor (the old admin allowed it): not `operator` —
    and the command must not lock the row out of unrelated changes."""
    half = _row(total_memory_mb=125000)
    migration = importlib.import_module("apps.scheduler.migrations.0013_capacity_v2")
    migration._forward(django_apps, None)
    half.refresh_from_db()
    assert half.trust_class == CapacityTrustClass.EARNED
    _run("--slots", "16")
    _run("--note", reason="noted")
    assert MinerCapacity.objects.get().capacity_slots == 16


def test_repeated_earned_reset_is_a_no_op() -> None:
    _row(earned_vms=9)
    _run("--earned-reset")
    stamped = MinerCapacity.objects.get().earned_last_change_at
    out = _run("--earned-reset")
    assert "no change" in out
    assert MinerCapacity.objects.get().earned_last_change_at == stamped


def test_repeated_note_with_an_idempotent_grant_writes_only_the_note() -> None:
    _row(earned_vms=4, earned_vcpus=8, earned_memory_mb=32768)
    _run("--earned-grant", "4", "8", "32768", "--note", reason="n")
    assert [a.field for a in _audits()] == ["note"]
    assert MinerCapacity.objects.get().earned_last_change_at is None


def test_huge_cpu_ratio_is_a_command_error_not_a_crash() -> None:
    _row()
    with pytest.raises(CommandError, match="outside"):
        _run("--cpu-ratio", "1e30")


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("cpu_ratio", float("nan")),
        ("cpu_ratio", True),
        ("cpu_ratio", "inf"),
        ("earned_vms", -1),
        ("earned_vms", 2.5),
        ("earned_vms", True),
        ("proven_peak_vms", None),
        ("trust_class", "admin"),
        ("candidate_since", "yesterday"),
    ],
)
def test_apply_rejects_values_the_column_cannot_hold(field: str, value: object) -> None:
    row = _row()
    with transaction.atomic(), pytest.raises(ValueError):
        capacity_admin.apply_capacity_change(row, {field: value}, actor="x", reason="y")
    assert _audits() == []


def test_apply_normalises_a_ratio_before_comparing() -> None:
    row = _row(cpu_ratio=Decimal("2.00"))
    with transaction.atomic():
        assert capacity_admin.apply_capacity_change(
            row, {"cpu_ratio": "2"}, actor="x", reason="y"
        ) == []


def test_old_image_insert_gets_database_defaults() -> None:
    """The running old image INSERTs without any v2 column; the DATABASE
    must fill them (`db_default`), or its INSERTs fail on NOT NULL."""
    from django.db import connection

    table = MinerCapacity._meta.db_table
    with connection.cursor() as cur:
        cur.execute(
            f"INSERT INTO {table} (id, miner_node_id, status, quality, capacity_slots, "
            "cvm_fail_streak, cvm_last_fail_reason, observed_epoch, data_epoch, "
            "refreshed_at, created_at) VALUES (%s, %s, 'active', 0, 8, 0, '', 1, 1, %s, %s)",
            ["0" * 32, NODE, timezone.now(), timezone.now()],
        )
    row = MinerCapacity.objects.get(miner_node_id=NODE)
    assert row.trust_class == CapacityTrustClass.EARNED
    assert (row.proven_peak_vms, row.candidate_vms, row.earned_last_reason) == (0, 0, "")


def test_settings_env_wiring_passes_only_present_knobs() -> None:
    from vali import settings as vali_settings

    got = vali_settings._capacity_v2_env(
        {"VALI_SCHEDULER_CPU_OVERCOMMIT": "1.0", "UNRELATED": "x"}
    )
    assert got == {"VALI_SCHEDULER_CPU_OVERCOMMIT": "1.0"}


@pytest.mark.parametrize("raw", ["ture", "2", "enabled"])
def test_resource_admission_flag_is_strict(raw: str) -> None:
    from django.core.exceptions import ImproperlyConfigured

    from apps.scheduler import capacity_config

    with override_settings(VALI_SCHEDULER_RESOURCE_ADMISSION=raw):
        with pytest.raises(ImproperlyConfigured, match="not a boolean"):
            capacity_config.resource_admission_enabled()


@pytest.mark.parametrize(("raw", "want"), [("1", True), ("off", False), ("", False)])
def test_resource_admission_flag_parses(raw: str, want: bool) -> None:
    from apps.scheduler import capacity_config

    with override_settings(VALI_SCHEDULER_RESOURCE_ADMISSION=raw):
        assert capacity_config.resource_admission_enabled() is want


def test_a_floor_above_its_cap_is_refused() -> None:
    from django.core.exceptions import ImproperlyConfigured

    from apps.scheduler import capacity_config

    with override_settings(VALI_CAPACITY_EARN_FLOOR_VMS=10, VALI_CAPACITY_EARN_HARD_CAP_VMS=8):
        with pytest.raises(ImproperlyConfigured, match="above its hard cap"):
            capacity_config.earn_floor_vms()


def test_an_inconsistent_operator_row_can_still_be_repaired() -> None:
    """An `operator` row missing half its anchor (written outside the
    command) must not lock every other change out — only a change to the
    trust class or the anchor is checked against the rule."""
    _row(trust_class=CapacityTrustClass.OPERATOR, total_memory_mb=125000)
    _run("--slots", "16")
    _run("--note", reason="found half-anchored")
    assert MinerCapacity.objects.get().capacity_slots == 16
    with pytest.raises(CommandError, match="needs a hardware anchor"):
        _run("--clear")
