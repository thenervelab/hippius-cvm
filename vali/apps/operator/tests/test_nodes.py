"""Tests for `GET /v1/operator/nodes`."""

from __future__ import annotations

import logging
from datetime import timedelta

import pytest
from django.test import override_settings
from django.urls import reverse
from django.utils import timezone
from rest_framework.test import APIClient

from apps.miners.models import MinerStatus
from apps.scheduler.models import MinerCapacity, PlacementFailureSource, PlacementStatus
from apps.scheduler.tests.factories import (
    make_dispatchable_identity,
    make_placement,
    make_vm,
    node_id,
)
from apps.telemetry.models import HostAttestor, HostAttestorRelease, HostAttestorStatus

pytestmark = pytest.mark.django_db

URL = reverse("operator_nodes")
MEAS_A = "a1" * 48

ROW_KEYS = {
    "node_id",
    "miner_id",
    "status",
    "last_seen_at",
    "attestor",
    "schedulable",
    "schedulable_reason",
    "hosted_vm_count",
    "capacity",
    "recent_refusals",
    "refusal_count_30d",
    "refusal_breakdown_30d",
    "location",
}

#: A stored reason the scheduler's §13 re-eval writes — a real refusal.
DRAIN_STALE = "drain:miner-stale"
#: A stored reason the destroy paths write — the tenant deleted the VM.
RELEASED = "released:vm-destroyed"
#: A stored reason `launch._fail_placement` writes — the miner-agent
#: answered the launch order with a non-2xx. A real refusal.
MINER_REJECTED = "miner-rejected"
#: A stored reason `launch._fail_placement` writes — Vault failed vali. NOT
#: a refusal: the node never got to answer.
VAULT_FAILURE = "vault-failure"

# The provenance each write site stamps (`Placement.failure_source`).
DRAIN = PlacementFailureSource.SCHEDULER_DRAIN.value
LAUNCH = PlacementFailureSource.LAUNCH.value
RELEASE = PlacementFailureSource.RELEASE.value
MANUAL = PlacementFailureSource.MANUAL.value
MIGRATION = PlacementFailureSource.MIGRATION.value
LEGACY = PlacementFailureSource.LEGACY.value


def _get(client: APIClient, *node_ids: str):
    return client.get(URL, {"node_id": list(node_ids)})


def _failed(seed: int, tag: str, reason: str, *, source: str, at=None):
    """A FAILED placement on `node_id(seed)` with the given stored reason
    and provenance, optionally back-dated to `at`."""
    vm = make_vm(f"vm-{seed}-{tag}", f"lease-{seed}-{tag}")
    p = make_placement(
        vm,
        node_id(seed),
        status=PlacementStatus.FAILED.value,
        reason=reason,
        failure_source=source,
    )
    if at is not None:
        p.failed_at = at
        p.save(update_fields=["failed_at"])
    return p


def _drained(seed: int, tag: str, cause: str = DRAIN_STALE, *, at=None):
    return _failed(seed, tag, cause, source=DRAIN, at=at)


def _launch_failed(seed: int, tag: str, outcome: str = MINER_REJECTED, *, at=None):
    return _failed(seed, tag, outcome, source=LAUNCH, at=at)


def _attestor(seed: int, **overrides) -> HostAttestor:
    fields = {
        "chip_id": format(seed, "0128x"),
        "node_id": node_id(seed),
        "signer_pubkey": bytes(32),
        "measurement": MEAS_A,
        "cert_expiry_at": timezone.now() + timedelta(days=30),
        "status": HostAttestorStatus.ATTESTED.value,
        "last_seen_at": timezone.now(),
    }
    fields.update(overrides)
    return HostAttestor.objects.create(**fields)


def _capacity(seed: int, slots: int = 6) -> MinerCapacity:
    return MinerCapacity.objects.create(
        miner_node_id=node_id(seed),
        status="active",
        capacity_slots=slots,
        observed_epoch=10,
        data_epoch=10,
        refreshed_at=timezone.now(),
    )


# ─── auth / scope ────────────────────────────────────────────────────


def test_unauthenticated_is_refused() -> None:
    resp = APIClient().get(URL, {"node_id": node_id(1)})
    assert resp.status_code in (401, 403)


def test_tenant_principal_is_refused(tenant_client: APIClient) -> None:
    make_dispatchable_identity(1)
    resp = _get(tenant_client, node_id(1))
    assert resp.status_code == 403


# ─── wire ────────────────────────────────────────────────────────────


def test_missing_node_id_is_400(operator_client: APIClient) -> None:
    resp = operator_client.get(URL)
    assert resp.status_code == 400
    assert resp.json()["category"] == "wire"


@pytest.mark.parametrize(
    "bad",
    [
        "abc",
        "zz" * 32,
        "0" * 63,
        "0" * 65,
        "00" * 30 + "  " + "00",  # 64 chars, `bytes.fromhex` would accept the inner blanks
        " " + "0" * 63,  # 64 chars once padded; must not be silently stripped
        "0" * 63 + "\n",
        "0x" + "0" * 62,
    ],
)
def test_malformed_node_id_is_400(operator_client: APIClient, bad: str) -> None:
    resp = _get(operator_client, bad)
    assert resp.status_code == 400
    assert resp.json()["category"] == "wire"


def test_more_than_100_node_ids_is_400(operator_client: APIClient) -> None:
    resp = _get(operator_client, *(node_id(i) for i in range(101)))
    assert resp.status_code == 400
    assert "at most 100" in resp.json()["error"]


def test_exactly_100_node_ids_is_accepted(operator_client: APIClient) -> None:
    resp = _get(operator_client, *(node_id(i) for i in range(100)))
    assert resp.status_code == 200


# ─── rows ────────────────────────────────────────────────────────────


def test_unknown_node_id_is_absent(operator_client: APIClient) -> None:
    make_dispatchable_identity(1)
    resp = _get(operator_client, node_id(1), node_id(42))
    assert resp.status_code == 200
    body = resp.json()
    assert body["count"] == 1
    assert [n["node_id"] for n in body["nodes"]] == [node_id(1)]


def test_node_id_is_case_insensitive_and_deduplicated(operator_client: APIClient) -> None:
    make_dispatchable_identity(1)
    resp = _get(operator_client, node_id(1).upper(), node_id(1))
    assert resp.status_code == 200
    assert resp.json()["count"] == 1
    assert resp.json()["nodes"][0]["node_id"] == node_id(1)


def test_full_row_for_a_healthy_node(operator_client: APIClient) -> None:
    miner = make_dispatchable_identity(1)
    HostAttestorRelease.objects.create(measurement=MEAS_A, version="v1", is_active=True)
    attestor = _attestor(1)
    _capacity(1, slots=6)
    vm_a = make_vm("vm-a", "lease-a")
    vm_b = make_vm("vm-b", "lease-b")
    vm_c = make_vm("vm-c", "lease-c")
    make_placement(vm_a, node_id(1), status=PlacementStatus.BOUND.value)
    make_placement(vm_b, node_id(1), status=PlacementStatus.PENDING.value)
    drained = make_placement(
        vm_c,
        node_id(1),
        status=PlacementStatus.FAILED.value,
        reason=DRAIN_STALE,
        failure_source=DRAIN,
    )

    resp = _get(operator_client, node_id(1))
    assert resp.status_code == 200
    body = resp.json()
    assert body["count"] == 1
    row = body["nodes"][0]
    assert set(row) == ROW_KEYS
    assert row == {
        "node_id": node_id(1),
        "miner_id": miner.miner_id,
        "status": "active",
        "last_seen_at": miner.last_seen_at.isoformat(),
        "attestor": {
            "status": "attested",
            "cert_expiry_at": attestor.cert_expiry_at.isoformat(),
            "measurement": MEAS_A,
            "last_seen_at": attestor.last_seen_at.isoformat(),
        },
        "schedulable": True,
        "schedulable_reason": None,
        "hosted_vm_count": 2,
        "capacity": {"total_units": 6, "committed_units": 2},
        "recent_refusals": [
            {"at": drained.failed_at.isoformat(), "reason": "heartbeat-stale", "detail": None}
        ],
        "refusal_count_30d": 1,
        "refusal_breakdown_30d": {"heartbeat-stale": 1},
        "location": None,
    }


def test_no_tenant_data_in_row(operator_client: APIClient) -> None:
    make_dispatchable_identity(1)
    vm = make_vm("vm-secret-name", "lease-secret")
    make_placement(
        vm, node_id(1), status=PlacementStatus.BOUND.value, vm_family="tenant-x", owner="owner-y"
    )
    resp = _get(operator_client, node_id(1))
    blob = resp.content.decode()
    for secret in ("vm-secret-name", "lease-secret", "tenant-x", "owner-y"):
        assert secret not in blob


def test_attestor_and_capacity_null_when_absent(operator_client: APIClient) -> None:
    make_dispatchable_identity(1)
    row = _get(operator_client, node_id(1)).json()["nodes"][0]
    assert row["attestor"] is None
    assert row["capacity"] is None
    assert row["hosted_vm_count"] == 0
    assert row["recent_refusals"] == []
    assert row["refusal_count_30d"] == 0
    assert row["refusal_breakdown_30d"] == {}


def test_best_attestor_row_is_reported(operator_client: APIClient) -> None:
    make_dispatchable_identity(1)
    _attestor(1, chip_id="aa" * 64, status=HostAttestorStatus.EXPIRED.value)
    _attestor(1, chip_id="bb" * 64, status=HostAttestorStatus.PENDING.value)
    row = _get(operator_client, node_id(1)).json()["nodes"][0]
    assert row["attestor"]["status"] == "pending"


def test_recent_refusals_are_newest_first_and_capped(operator_client: APIClient) -> None:
    make_dispatchable_identity(1)
    base = timezone.now() - timedelta(hours=1)
    stamps = []
    for i in range(12):
        p = _drained(1, str(i), at=base + timedelta(minutes=i))
        stamps.append(p.failed_at.isoformat())
    row = _get(operator_client, node_id(1)).json()["nodes"][0]
    assert [r["at"] for r in row["recent_refusals"]] == stamps[:1:-1]
    # the count is NOT capped with the listing
    assert row["refusal_count_30d"] == 12


# ─── which FAILED placements are refusals: provenance first ──────────


def test_released_vms_are_not_refusals(operator_client: APIClient) -> None:
    """`Placement.failed_at` is stamped at EVERY placement end. Ten tenants
    deleting their VMs on a healthy node is not ten refusals: with no
    scheduler drain, the node shows none."""
    make_dispatchable_identity(1)
    for i in range(10):
        _failed(1, str(i), RELEASED, source=RELEASE)
    row = _get(operator_client, node_id(1)).json()["nodes"][0]
    assert row["schedulable"] is True
    assert row["recent_refusals"] == []
    assert row["refusal_count_30d"] == 0


@pytest.mark.parametrize("source", [MANUAL, RELEASE, MIGRATION, LEGACY])
@pytest.mark.parametrize(
    "stored",
    [
        # the very strings the two refusal sources write — under any OTHER
        # provenance they are not refusals, whatever they spell
        "miner-rejected",
        "preflight-failure",
        "misconfigured",
        "edge-unreachable",
        "edge-error",
        "launch-failed",
        "dispatch-failed-after-register",
        "drain:miner-stale",
        "drain:miner-quarantined",
        # a bare public word
        "launch-rejected",
        "quarantined",
        # what those sources really write
        "released:vm-destroyed",
        "image tenant-x/app:1.2 not found on owner-y",
        "seed",
    ],
)
def test_only_drain_and_launch_provenance_can_be_a_refusal(
    operator_client: APIClient, stored: str, source: str
) -> None:
    """Selection is by `failure_source`, not by the text of `reason`: a
    root `/fail` body that literally spells `miner-rejected` is a MANUAL
    row and is never surfaced; a legacy row (ended before provenance was
    recorded) is unattributable and is refused rather than guessed."""
    make_dispatchable_identity(1)
    _failed(1, "x", stored, source=source)
    resp = _get(operator_client, node_id(1))
    row = resp.json()["nodes"][0]
    assert row["recent_refusals"] == []
    assert row["refusal_count_30d"] == 0
    assert row["refusal_breakdown_30d"] == {}
    if stored not in ("quarantined", "launch-rejected", "seed"):
        assert stored not in resp.content.decode()


def test_manual_fail_spelling_a_launch_outcome_is_not_a_refusal_but_a_launch_is(
    operator_client: APIClient,
) -> None:
    """The exact collision the provenance column exists for: the same
    stored string, two writers, two verdicts."""
    make_dispatchable_identity(1)
    _failed(1, "manual", MINER_REJECTED, source=MANUAL)
    launched = _failed(1, "launch", MINER_REJECTED, source=LAUNCH)
    row = _get(operator_client, node_id(1)).json()["nodes"][0]
    assert row["recent_refusals"] == [
        {"at": launched.failed_at.isoformat(), "reason": "launch-rejected", "detail": None}
    ]
    assert row["refusal_count_30d"] == 1
    assert row["refusal_breakdown_30d"] == {"launch-rejected": 1}


def test_legacy_rows_are_excluded_even_when_they_look_like_drains(
    operator_client: APIClient,
) -> None:
    """Rows that ended before `failure_source` existed keep `legacy`. A
    `drain:` text on one is ALMOST certainly a scheduler drain — and
    "almost" is exactly the guess the readout refuses to make. Only the
    rows written by the new code count."""
    make_dispatchable_identity(1)
    _failed(1, "old-drain", DRAIN_STALE, source=LEGACY)
    _failed(1, "old-launch", MINER_REJECTED, source=LEGACY)
    new = _drained(1, "new-drain")
    row = _get(operator_client, node_id(1)).json()["nodes"][0]
    assert row["recent_refusals"] == [
        {"at": new.failed_at.isoformat(), "reason": "heartbeat-stale", "detail": None}
    ]
    assert row["refusal_count_30d"] == 1


def test_vm_side_drain_is_not_a_refusal(operator_client: APIClient) -> None:
    """A scheduler drain whose cause judges the VM (`drain:vm-terminal`),
    not the node — excluded despite its provenance."""
    make_dispatchable_identity(1)
    _drained(1, "t", "drain:vm-terminal")
    resp = _get(operator_client, node_id(1))
    row = resp.json()["nodes"][0]
    assert row["recent_refusals"] == []
    assert row["refusal_count_30d"] == 0
    assert "vm-terminal" not in resp.content.decode()


@pytest.mark.parametrize(
    "stored",
    [
        # `launch._fail_placement` — the launch died on VALI's side of the
        # wire (`reasons.NON_NODE_LAUNCH_OUTCOMES`); the node never answered
        "vault-failure",
        "lifecycle-keygen-failure",
        "mint-failure",
        "kbs-admin-conflict",
        "kbs-admin-terminal",
        "kbs-admin-unavailable",
        "kbs-admin-error",
        "allowlist-pin-failure",
        "launch-digest-not-configured",
        "launch-digest-recompute-failure",
        "launch-digest-mismatch",
        "netbird-bad-userdata",
        "netbird-mint-failure",
        # the control plane's own image fault — explicitly excluded
        "golden-base-unresolved",
        # the excluded prefix families, if one ever reached a placement
        "kbs-admin-something-new",
        "secret-fetch-failed",
        "secret-fetch-failed: boom",
        "source-ack-timeout:quarantine-source",
        # a bare public word is not something the launch path writes
        "launch-rejected",
        "quarantined",
        # near-misses of a launch outcome: exact match only
        "Miner-Rejected",
        "miner-rejected: EBUSY",
        # the factory placeholder
        "seed",
    ],
)
def test_launch_rows_with_a_control_plane_outcome_are_excluded(
    operator_client: APIClient, stored: str
) -> None:
    make_dispatchable_identity(1)
    _launch_failed(1, "x", stored)
    resp = _get(operator_client, node_id(1))
    row = resp.json()["nodes"][0]
    assert row["recent_refusals"] == []
    assert row["refusal_count_30d"] == 0
    assert row["refusal_breakdown_30d"] == {}
    if stored not in ("quarantined", "launch-rejected", "seed"):
        assert stored not in resp.content.decode()


def test_every_vali_side_launch_outcome_is_excluded(operator_client: APIClient) -> None:
    """The whole declared set at once, so the parametrized list above
    cannot silently lag behind `reasons.NON_NODE_LAUNCH_OUTCOMES`."""
    from apps.scheduler.reasons import NON_NODE_LAUNCH_OUTCOMES

    make_dispatchable_identity(1)
    for i, stored in enumerate(sorted(NON_NODE_LAUNCH_OUTCOMES)):
        _launch_failed(1, str(i), stored)
    resp = _get(operator_client, node_id(1))
    row = resp.json()["nodes"][0]
    assert row["recent_refusals"] == []
    assert row["refusal_count_30d"] == 0
    assert row["refusal_breakdown_30d"] == {}
    body = resp.content.decode()
    assert not any(stored in body for stored in NON_NODE_LAUNCH_OUTCOMES)


# ─── launch-time refusals ────────────────────────────────────────────


@pytest.mark.parametrize(
    "stored, public",
    [
        # miner-agent answered the launch order with a non-2xx
        ("miner-rejected", "launch-rejected"),
        # miner-agent could not stage / verify the boot artefacts
        ("preflight-failure", "launch-rejected"),
        # the dispatch to this node could not be formed
        ("misconfigured", "launch-rejected"),
        # the dispatch to the host failed at the transport / timed out
        ("edge-unreachable", "launch-unreachable"),
        # the dispatch to the host errored
        ("edge-error", "launch-unreachable"),
        # `_fail_placement`'s default when an outcome carries no `outcome`
        ("launch-failed", "launch-failed"),
        # `LaunchResult.outcome` after the same-miner retries are exhausted
        ("dispatch-failed-after-register", "launch-failed"),
    ],
)
def test_launch_outcomes_are_refusals_under_the_public_word(
    operator_client: APIClient, stored: str, public: str
) -> None:
    make_dispatchable_identity(1)
    p = _launch_failed(1, "l", stored)
    resp = _get(operator_client, node_id(1))
    row = resp.json()["nodes"][0]
    assert row["recent_refusals"] == [
        {"at": p.failed_at.isoformat(), "reason": public, "detail": None}
    ]
    assert row["refusal_count_30d"] == 1
    assert row["refusal_breakdown_30d"] == {public: 1}
    # the stored outcome is not echoed — unless it IS the public word
    if stored != public:
        assert stored not in resp.content.decode()
    # a launch refusal is never the schedulable verdict: the node is fine
    assert (row["schedulable"], row["schedulable_reason"]) == (True, None)


def test_launch_and_drain_refusals_interleave_newest_first(operator_client: APIClient) -> None:
    make_dispatchable_identity(1)
    base = timezone.now() - timedelta(hours=1)
    a = _launch_failed(1, "a", MINER_REJECTED, at=base)
    b = _drained(1, "b", at=base + timedelta(minutes=1))
    _failed(1, "c", RELEASED, source=RELEASE, at=base + timedelta(minutes=2))
    _launch_failed(1, "d", VAULT_FAILURE, at=base + timedelta(minutes=3))
    _failed(1, "d2", MINER_REJECTED, source=MANUAL, at=base + timedelta(minutes=3, seconds=30))
    e = _launch_failed(1, "e", "edge-unreachable", at=base + timedelta(minutes=4))
    row = _get(operator_client, node_id(1)).json()["nodes"][0]
    assert row["recent_refusals"] == [
        {"at": e.failed_at.isoformat(), "reason": "launch-unreachable", "detail": None},
        {"at": b.failed_at.isoformat(), "reason": "heartbeat-stale", "detail": None},
        {"at": a.failed_at.isoformat(), "reason": "launch-rejected", "detail": None},
    ]
    assert row["refusal_count_30d"] == 3


def test_refusal_breakdown_counts_per_public_reason(operator_client: APIClient) -> None:
    """`refusal_breakdown_30d` folds STORED reasons onto the public word
    (`miner-rejected` + `preflight-failure` both count as `launch-rejected`),
    is windowed like the count, is sparse, and sums to `refusal_count_30d`."""
    make_dispatchable_identity(1)
    now = timezone.now()
    for i in range(2):
        _launch_failed(1, f"mr{i}", MINER_REJECTED)
    _launch_failed(1, "pf", "preflight-failure")
    _launch_failed(1, "eu", "edge-unreachable")
    _drained(1, "ds", DRAIN_STALE)
    _drained(1, "dq", "drain:miner-quarantined")
    # excluded rows: not counted anywhere
    _failed(1, "rel", RELEASED, source=RELEASE)
    _launch_failed(1, "vf", VAULT_FAILURE)
    _failed(1, "man", MINER_REJECTED, source=MANUAL)
    _failed(1, "leg", DRAIN_STALE, source=LEGACY)
    # a refusal outside the 30-day window: listed, not counted
    _launch_failed(1, "old", MINER_REJECTED, at=now - timedelta(days=31))
    row = _get(operator_client, node_id(1)).json()["nodes"][0]
    assert row["refusal_breakdown_30d"] == {
        "heartbeat-stale": 1,
        "launch-rejected": 3,
        "launch-unreachable": 1,
        "quarantined": 1,
    }
    assert row["refusal_count_30d"] == 6 == sum(row["refusal_breakdown_30d"].values())
    assert len(row["recent_refusals"]) == 7


def test_refusal_breakdown_keys_are_the_public_vocabulary(operator_client: APIClient) -> None:
    from apps.scheduler.reasons import REFUSAL_REASONS

    make_dispatchable_identity(1)
    for i, stored in enumerate(("miner-rejected", "edge-unreachable", "launch-failed")):
        _launch_failed(1, str(i), stored)
    _drained(1, "ds", DRAIN_STALE)
    _drained(1, "df", "drain:foo")
    row = _get(operator_client, node_id(1)).json()["nodes"][0]
    assert set(row["refusal_breakdown_30d"]) <= REFUSAL_REASONS
    # an unmapped drain is counted under `unknown` exactly as it is listed
    assert row["refusal_breakdown_30d"]["unknown"] == 1
    assert "drain:foo" not in str(row)


def test_refusals_are_per_node(operator_client: APIClient) -> None:
    make_dispatchable_identity(1)
    make_dispatchable_identity(2)
    _launch_failed(1, "a", MINER_REJECTED)
    _drained(2, "b")
    _drained(2, "c")
    rows = {r["node_id"]: r for r in _get(operator_client, node_id(1), node_id(2)).json()["nodes"]}
    assert rows[node_id(1)]["refusal_breakdown_30d"] == {"launch-rejected": 1}
    assert rows[node_id(2)]["refusal_breakdown_30d"] == {"heartbeat-stale": 2}
    assert [r["reason"] for r in rows[node_id(1)]["recent_refusals"]] == ["launch-rejected"]


@pytest.mark.parametrize(
    "stored, public",
    [
        ("drain:miner-stale", "heartbeat-stale"),
        ("drain:miner-quarantined", "quarantined"),
        ("drain:miner-decommissioned", "not-active"),
        ("drain:miner-missing", "not-active"),
        ("drain:miner-inactive", "not-active"),
    ],
)
def test_drain_causes_map_to_the_vocabulary(
    operator_client: APIClient, stored: str, public: str
) -> None:
    make_dispatchable_identity(1)
    p = _drained(1, "d", stored)
    row = _get(operator_client, node_id(1)).json()["nodes"][0]
    assert row["recent_refusals"] == [
        {"at": p.failed_at.isoformat(), "reason": public, "detail": None}
    ]
    assert row["refusal_count_30d"] == 1
    assert row["refusal_breakdown_30d"] == {public: 1}


def test_unknown_drain_cause_is_unknown_and_warned_once(
    operator_client: APIClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A `drain:` cause without an alias is a stale vocabulary: still
    reported as `unknown` (never echoed), but logged ONCE per cause so the
    gap is visible. The project's LOGGING sets `propagate = False` on the
    `apps` loggers, so `caplog` (root) sees nothing — attach a sink to the
    module logger directly."""
    from apps.scheduler import reasons

    records: list[logging.LogRecord] = []

    class _Sink(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            records.append(record)

    monkeypatch.setattr(reasons, "_WARNED_UNKNOWN_DRAINS", set())
    make_dispatchable_identity(1)
    _drained(1, "a", "drain:foo")
    _drained(1, "b", "drain:foo")
    _drained(1, "c", "drain:bar")
    logger = logging.getLogger("apps.scheduler.reasons")
    sink = _Sink(level=logging.WARNING)
    logger.addHandler(sink)
    try:
        resp = _get(operator_client, node_id(1))
        _get(operator_client, node_id(1))
    finally:
        logger.removeHandler(sink)
    row = resp.json()["nodes"][0]
    assert [r["reason"] for r in row["recent_refusals"]] == ["unknown"] * 3
    body = resp.content.decode()
    assert "drain:foo" not in body and "drain:bar" not in body
    # three rows, two requests → one warning per distinct cause
    messages = sorted(r.getMessage() for r in records if r.levelno == logging.WARNING)
    assert len(messages) == 2, messages
    assert "'drain:bar'" in messages[0] and "'drain:foo'" in messages[1]


def test_refusal_count_window_is_30_days(operator_client: APIClient) -> None:
    make_dispatchable_identity(1)
    now = timezone.now()
    _drained(1, "in", at=now - timedelta(days=29))
    _drained(1, "out", at=now - timedelta(days=31))
    row = _get(operator_client, node_id(1)).json()["nodes"][0]
    # the listing is not windowed; the count is
    assert len(row["recent_refusals"]) == 2
    assert row["refusal_count_30d"] == 1


def test_query_count_does_not_grow_with_node_count(
    operator_client: APIClient, django_assert_num_queries
) -> None:
    """Refusals are fetched in ONE query for the whole request (window
    function, top-N per node) and their 30-day breakdown — which the count
    is the sum of — in ONE more, not one query per row or per reason."""
    from django.db import connection
    from django.test.utils import CaptureQueriesContext

    def _seed(seeds: range) -> None:
        for s in seeds:
            make_dispatchable_identity(s)
            for i in range(3):
                _drained(s, str(i))
            # both refusal families, several public reasons per node
            _launch_failed(s, "mr", MINER_REJECTED)
            _launch_failed(s, "pf", "preflight-failure")
            _launch_failed(s, "eu", "edge-unreachable")
            # excluded rows cost no query either
            _failed(s, "released", RELEASED, source=RELEASE)
            _launch_failed(s, "vault", VAULT_FAILURE)
            _failed(s, "manual", MINER_REJECTED, source=MANUAL)
            _failed(s, "legacy", DRAIN_STALE, source=LEGACY)

    _seed(range(1, 2))
    with CaptureQueriesContext(connection) as one:
        assert _get(operator_client, node_id(1)).json()["count"] == 1

    _seed(range(2, 51))
    with CaptureQueriesContext(connection) as fifty:
        body = _get(operator_client, *(node_id(s) for s in range(1, 51))).json()
    assert body["count"] == 50
    assert all(len(r["recent_refusals"]) == 6 for r in body["nodes"])
    assert all(r["refusal_count_30d"] == 6 for r in body["nodes"])
    assert all(
        r["refusal_breakdown_30d"]
        == {"heartbeat-stale": 3, "launch-rejected": 2, "launch-unreachable": 1}
        for r in body["nodes"]
    )
    assert len(fifty) == len(one), (len(one), len(fifty))


def test_query_count_is_unchanged_by_the_breakdown(
    operator_client: APIClient, django_assert_num_queries
) -> None:
    """The breakdown REPLACES the flat count query (grouped by stored
    reason, folded in Python) — it does not add one. Pin the absolute
    number so a regression to per-reason or per-node queries is loud."""
    from django.db import connection
    from django.test.utils import CaptureQueriesContext

    make_dispatchable_identity(1)
    with CaptureQueriesContext(connection) as none:
        _get(operator_client, node_id(1))
    _launch_failed(1, "a", MINER_REJECTED)
    _drained(1, "b")
    _launch_failed(1, "c", "edge-unreachable")
    with CaptureQueriesContext(connection) as three:
        _get(operator_client, node_id(1))
    assert len(three) == len(none), (len(none), len(three))
    placement_sql = [q["sql"] for q in three if "scheduler_placement" in q["sql"]]
    # exactly one ranked listing and exactly one aggregate over the refusals
    assert sum("ROW_NUMBER() OVER" in q for q in placement_sql) == 1, placement_sql
    assert sum("GROUP BY" in q for q in placement_sql) == 1, placement_sql


# ─── schedulable + reason come from the scheduler's predicate ────────


def test_quarantined_node_reason(operator_client: APIClient) -> None:
    m = make_dispatchable_identity(1)
    m.status = MinerStatus.QUARANTINED
    m.save(update_fields=["status"])
    row = _get(operator_client, node_id(1)).json()["nodes"][0]
    assert row["status"] == "quarantined"
    assert row["schedulable"] is False
    assert row["schedulable_reason"] == "quarantined"


def test_stale_heartbeat_reason(operator_client: APIClient) -> None:
    m = make_dispatchable_identity(1)
    m.last_seen_at = timezone.now() - timedelta(hours=1)
    m.save(update_fields=["last_seen_at"])
    row = _get(operator_client, node_id(1)).json()["nodes"][0]
    assert (row["schedulable"], row["schedulable_reason"]) == (False, "heartbeat-stale")


def test_gate_off_attestor_state_does_not_block(operator_client: APIClient) -> None:
    make_dispatchable_identity(1)
    _attestor(1, status=HostAttestorStatus.EXPIRED.value)
    row = _get(operator_client, node_id(1)).json()["nodes"][0]
    assert row["attestor"]["status"] == "expired"
    assert (row["schedulable"], row["schedulable_reason"]) == (True, None)


@override_settings(VALI_HOST_ATTESTOR_GATE_ENFORCE=True)
def test_gate_on_attestor_reasons(operator_client: APIClient) -> None:
    make_dispatchable_identity(1)
    make_dispatchable_identity(2)
    make_dispatchable_identity(3)
    HostAttestorRelease.objects.create(measurement=MEAS_A, version="v1", is_active=True)
    _attestor(1)
    _attestor(3, status=HostAttestorStatus.EXPIRED.value)
    resp = _get(operator_client, node_id(1), node_id(2), node_id(3))
    rows = {r["node_id"]: r for r in resp.json()["nodes"]}
    assert (rows[node_id(1)]["schedulable"], rows[node_id(1)]["schedulable_reason"]) == (
        True,
        None,
    )
    assert rows[node_id(2)]["schedulable_reason"] == "attestor-missing"
    assert rows[node_id(3)]["schedulable_reason"] == "cert-expired"


# ─── published schema: closed vocabularies + response codes ──────────


def test_schema_publishes_enums_and_response_codes() -> None:
    from drf_spectacular.generators import SchemaGenerator

    from apps.scheduler.reasons import REFUSAL_REASONS, SCHEDULABLE_REASONS

    schema = SchemaGenerator().get_schema(request=None, public=True)
    op = next(
        v["get"]
        for k, v in schema["paths"].items()
        if k.endswith("/operator/nodes") or k.endswith("/operator/nodes/")
    )
    assert {"200", "400", "401", "403"} <= set(op["responses"])

    comps = schema["components"]["schemas"]
    node = comps["OperatorNode"]["properties"]
    assert set(_enum(comps, node["status"])) == {"active", "quarantined"}
    assert set(_enum(comps, node["schedulable_reason"])) - {None} == SCHEDULABLE_REASONS
    refusal = comps["OperatorRefusal"]
    refusal_reasons = set(_enum(comps, refusal["properties"]["reason"]))
    assert refusal_reasons == REFUSAL_REASONS
    # the three launch-time values are published; none of them is a gate
    assert {"launch-rejected", "launch-unreachable", "launch-failed"} <= refusal_reasons
    assert not ({"launch-rejected", "launch-unreachable", "launch-failed"} & SCHEDULABLE_REASONS)
    # `detail` is null-only: nullable, NO type (a generated consumer cannot
    # type it as a string), and optional for the rollout
    detail = refusal["properties"]["detail"]
    assert detail["nullable"] is True
    assert "type" not in detail and "$ref" not in detail and "oneOf" not in detail
    assert set(refusal["required"]) == {"at", "reason"}
    breakdown = node["refusal_breakdown_30d"]
    assert breakdown["type"] == "object"
    assert breakdown["additionalProperties"]["type"] == "integer"
    # the new fields are OPTIONAL during the rollout (consumers default to
    # `{}` / `0` / `null`); a later contract bump makes them required again
    required = set(comps["OperatorNode"]["required"])
    assert "refusal_breakdown_30d" not in required
    assert "refusal_count_30d" not in required
    assert {"node_id", "schedulable", "recent_refusals"} <= required
    assert set(_enum(comps, comps["OperatorAttestor"]["properties"]["status"])) == {
        "pending",
        "attested",
        "expired",
    }


def _enum(comps: dict, prop: dict) -> list:
    """drf-spectacular emits either an inline `enum` or a `$ref` to a
    `*Enum` component, wrapped in `allOf` (plain) or `oneOf` (nullable)."""
    if "enum" in prop:
        return prop["enum"]
    if "$ref" in prop:
        return comps[prop["$ref"].rsplit("/", 1)[1]]["enum"]
    out: list = []
    for alt in prop.get("oneOf", []) + prop.get("allOf", []):
        out.extend(_enum(comps, alt))
    return out


def test_location_is_serialised_from_the_probe_row(operator_client: APIClient) -> None:
    from apps.miners.models import LocationVerdict, MinerLocation

    miner = make_dispatchable_identity(1)
    row = MinerLocation.objects.create(
        miner=miner,
        connection_ip="146.10.20.30",
        country_code="FR",
        city="",
        latitude=48.8582,
        longitude=2.3387,
        asn=64500,
        as_holder="EXAMPLE-AS",
        rtt_ms=4.0,
        verdict=LocationVerdict.UNVERIFIED,
        verdict_reasons=["peer-stale"],
        observed_at=timezone.now(),
    )
    node = _get(operator_client, node_id(1)).json()["nodes"][0]
    assert node["location"] == {
        "country_code": "FR",
        "region": "FR",
        "city": "",
        "connection_ip": "146.10.20.30",
        "asn": 64500,
        "as_holder": "EXAMPLE-AS",
        "rtt_ms": 4.0,
        "verdict": "unverified",
        "verdict_reasons": ["peer-stale"],
        "observed_at": row.observed_at.isoformat(),
    }
