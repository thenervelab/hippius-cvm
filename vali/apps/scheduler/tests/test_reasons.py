"""`apps.scheduler.reasons` — the ONE public vocabulary the dispatchability
predicate emits and the operator readout serializes. An internal
`Placement.reason` never round-trips: it is either mapped onto the
vocabulary or reported as `unknown`."""

from __future__ import annotations

import contextlib
import inspect
import logging
import re
from collections.abc import Iterator

import pytest

from apps.scheduler import reasons, service
from apps.telemetry import release_service

SCHEDULING_GATES = {
    "quarantined",
    "failover-quarantined",
    "not-active",
    "not-bridged",
    "unreachable",
    "heartbeat-stale",
    "platform-id-invalid",
    "release-unpinned",
    "attestor-missing",
    "attestor-pending",
    "cert-expired",
    "measurement-stale",
    "attestor-stale",
}


#: The launch-time refusals — a `recent_refusals[].reason` only, never a
#: `schedulable_reason` (a placement WAS decided, then the launch died).
LAUNCH_REFUSALS = {"launch-rejected", "launch-unreachable", "launch-failed"}


def test_vocabulary_is_the_scheduling_gates_plus_three_launch_refusals() -> None:
    assert reasons.SCHEDULABLE_REASONS == frozenset(SCHEDULING_GATES)
    assert reasons.LAUNCH_REASONS == frozenset(LAUNCH_REFUSALS)
    assert reasons.REFUSAL_REASONS == frozenset(SCHEDULING_GATES | LAUNCH_REFUSALS | {"unknown"})
    assert reasons.REASON_UNKNOWN == "unknown"
    assert "unknown" not in reasons.SCHEDULABLE_REASONS
    # a launch refusal is not a gate: `schedulable_reason` can never carry one
    assert not (reasons.LAUNCH_REASONS & reasons.SCHEDULABLE_REASONS)


def test_predicate_modules_use_the_shared_constants() -> None:
    # `dispatchability()` and the attestor gate import from `reasons`, so the
    # two cannot drift from what the operator serializer whitelists.
    assert service.REASON_QUARANTINED is reasons.REASON_QUARANTINED
    assert service.REASON_PLATFORM_ID_INVALID is reasons.REASON_PLATFORM_ID_INVALID
    assert release_service.REASON_RELEASE_UNPINNED is reasons.REASON_RELEASE_UNPINNED
    assert release_service.REASON_ATTESTOR_STALE is reasons.REASON_ATTESTOR_STALE
    assert set(release_service._REASON_RANK) <= reasons.SCHEDULABLE_REASONS


@pytest.mark.parametrize("gate", sorted(SCHEDULING_GATES))
def test_gate_values_pass_through(gate: str) -> None:
    assert reasons.public_refusal_reason(gate) == gate


@pytest.mark.parametrize(
    "internal, public",
    [
        ("drain:miner-quarantined", "quarantined"),
        ("drain:miner-inactive", "not-active"),
        ("drain:miner-decommissioned", "not-active"),
        ("drain:miner-missing", "not-active"),
        ("drain:miner-stale", "heartbeat-stale"),
    ],
)
def test_internal_drain_causes_map_onto_the_vocabulary(internal: str, public: str) -> None:
    assert reasons.public_refusal_reason(internal) == public


#: `launch_on_miner` outcome (stored verbatim by `launch._fail_placement`)
#: → public reason. EXACTLY the three-sided contract; the node is the party
#: that failed in each of these.
LAUNCH_OUTCOME_TO_PUBLIC = [
    ("miner-rejected", "launch-rejected"),
    ("preflight-failure", "launch-rejected"),
    ("misconfigured", "launch-rejected"),
    ("edge-unreachable", "launch-unreachable"),
    ("edge-error", "launch-unreachable"),
    ("launch-failed", "launch-failed"),
    ("dispatch-failed-after-register", "launch-failed"),
]

#: Launch outcomes that are control-plane faults — the launch died on
#: vali's side of the wire (Vault, ticket mint, KBS admin, vali settings,
#: the C2 digest policy, the golden-base resolution). NOT refusals.
VALI_SIDE_OUTCOMES = {
    "launch-digest-not-configured",
    "platform-id-mismatch",
    "netbird-bad-userdata",
    "netbird-mint-failure",
    "customer-keys-cmdline-refused",
    "cdn-role-refused",
    "vault-failure",
    "lifecycle-keygen-failure",
    "launch-digest-recompute-failure",
    "launch-digest-mismatch",
    "explicit-measurement-stale",
    "cmdline-too-long",
    "allowlist-pin-failure",
    "allowlist-pin-busy",
    "mint-failure",
    "kbs-admin-conflict",
    "kbs-admin-terminal",
    "kbs-admin-unavailable",
    "kbs-admin-error",
    "kbs-admin-vm-state-refused",
    "supersede-mark-failed",
    "golden-base-unresolved",
    "guest-epoch-below-required",
}

#: The contract's explicit exclusions, spelled the way the contract spells
#: them (`*` = prefix family).
CONTRACT_EXCLUDED = [
    "vault-failure",
    "mint-failure",
    "kbs-admin-*",
    "secret-fetch-failed*",
    "golden-base-unresolved",
    "source-ack-timeout*",
]


@pytest.mark.parametrize("internal, public", LAUNCH_OUTCOME_TO_PUBLIC)
def test_launch_outcomes_map_onto_the_vocabulary(internal: str, public: str) -> None:
    assert reasons.public_refusal_reason(internal) == public
    assert public in reasons.LAUNCH_REASONS
    assert internal in reasons.LAUNCH_REFUSAL_OUTCOMES


def test_launch_selection_set_is_exactly_the_mapped_outcomes() -> None:
    assert reasons.LAUNCH_REFUSAL_OUTCOMES == {k for k, _ in LAUNCH_OUTCOME_TO_PUBLIC}
    assert reasons.NON_NODE_LAUNCH_OUTCOMES == frozenset(VALI_SIDE_OUTCOMES)
    assert not (reasons.LAUNCH_REFUSAL_OUTCOMES & reasons.NON_NODE_LAUNCH_OUTCOMES)
    assert not any(
        k.startswith(reasons.NON_NODE_OUTCOME_PREFIXES) for k in reasons.LAUNCH_REFUSAL_OUTCOMES
    )
    # neither set collides with the drain family or the public vocabulary
    # (except `launch-failed`, which is both the stored default and the
    # public value — deliberately identical)
    assert not any(k.startswith("drain:") for k in reasons.LAUNCH_REFUSAL_OUTCOMES)
    assert reasons.LAUNCH_REFUSAL_OUTCOMES & reasons.REFUSAL_REASONS == {"launch-failed"}
    assert not (reasons.NON_NODE_LAUNCH_OUTCOMES & reasons.REFUSAL_REASONS)


@pytest.mark.parametrize("raw", sorted(VALI_SIDE_OUTCOMES))
def test_vali_side_launch_outcomes_are_not_refusals(raw: str) -> None:
    """Excluded at SELECTION (`apps.operator.service._refusals` selects
    `failure_source = launch AND reason IN LAUNCH_REFUSAL_OUTCOMES`); the
    mapper never sees them in production, and if it did it would still not
    echo them."""
    assert raw not in reasons.LAUNCH_REFUSAL_OUTCOMES
    assert reasons.is_control_plane_fault(raw)
    assert reasons.public_refusal_reason(raw) == "unknown"


@pytest.mark.parametrize("spelled", CONTRACT_EXCLUDED)
def test_every_contract_exclusion_is_declared(spelled: str) -> None:
    """Each exclusion the contract names is either an exact member of
    `NON_NODE_LAUNCH_OUTCOMES` or a declared prefix family — and is never
    a refusal outcome. `golden-base-unresolved` in particular: a
    control-plane image fault, excluded explicitly."""
    if spelled.endswith("*"):
        prefix = spelled[:-1]
        assert prefix in reasons.NON_NODE_OUTCOME_PREFIXES, prefix
        for probe in (prefix, prefix + "x", prefix + ": boom"):
            assert reasons.is_control_plane_fault(probe)
            assert probe not in reasons.LAUNCH_REFUSAL_OUTCOMES
            assert reasons.public_refusal_reason(probe) == "unknown"
    else:
        assert spelled in reasons.NON_NODE_LAUNCH_OUTCOMES
        assert spelled not in reasons.LAUNCH_REFUSAL_OUTCOMES
        assert reasons.is_control_plane_fault(spelled)


def test_kbs_admin_literals_all_fall_under_the_declared_prefix() -> None:
    kbs = {k for k in reasons.NON_NODE_LAUNCH_OUTCOMES if k.startswith("kbs-admin-")}
    assert len(kbs) == 5, kbs
    assert "kbs-admin-" in reasons.NON_NODE_OUTCOME_PREFIXES


@pytest.mark.parametrize("raw", sorted(reasons.LAUNCH_REFUSAL_OUTCOMES))
def test_refusal_outcomes_are_never_control_plane_faults(raw: str) -> None:
    assert not reasons.is_control_plane_fault(raw)


@pytest.mark.parametrize(
    "raw",
    [
        "seed",
        "vm-secret-name refused by owner-y",
        "image tenant-x/app:1.2 not found",
        "vault-failure",
        "kbs-admin-conflict",
        "secret-fetch-failed",
        "golden-base-unresolved",
        "drain:vm-terminal",
        "released:vm-destroyed",
        "10.0.0.7 unreachable",
        "Quarantined",  # case matters — the vocabulary is exact
        " quarantined",
        "Miner-Rejected",
        " miner-rejected",
        "miner-rejected: EBUSY",
        "",
        None,
    ],
)
def test_anything_else_is_unknown_and_never_round_trips(raw: str | None) -> None:
    out = reasons.public_refusal_reason(raw)
    assert out == "unknown"
    assert out in reasons.REFUSAL_REASONS
    if raw:
        assert raw not in reasons.REFUSAL_REASONS or out == raw


@pytest.mark.parametrize("raw", ["launch-rejected", "launch-unreachable"])
def test_bare_public_launch_values_do_not_pass_through(raw: str) -> None:
    """Unlike the gates, the public launch values are not what vali stores
    (the stored strings are `launch_on_miner`'s outcomes), so a `/fail` body
    that happens to spell one is not promoted to a refusal."""
    assert raw in reasons.REFUSAL_REASONS
    assert reasons.public_refusal_reason(raw) == "unknown"


# ─── which FAILED placements are refusals ────────────────────────────


def test_every_drain_cause_is_aliased_or_declared_vm_side() -> None:
    """`reeval_once` writes `drain:<cause>` for every literal `_drain_cause`
    returns. Each one must be either mapped onto the vocabulary or
    explicitly declared a VM-side drain — a new cause without a decision
    here fails this test before it reaches production as `unknown`."""
    causes = set(re.findall(r'return "([a-z-]+)"', inspect.getsource(service._drain_cause)))
    assert causes, "no literal causes found — the regex or `_drain_cause` changed"
    prefix = reasons.DRAIN_REASON_PREFIX
    aliased = {k.removeprefix(prefix) for k in reasons._REFUSAL_ALIASES}
    vm_side = {k.removeprefix(prefix) for k in reasons.NON_NODE_DRAIN_REASONS}
    assert all(k.startswith(prefix) for k in reasons._REFUSAL_ALIASES)
    assert all(k.startswith(prefix) for k in reasons.NON_NODE_DRAIN_REASONS)
    assert not (aliased & vm_side)
    assert causes == aliased | vm_side, (causes, aliased | vm_side)


def _literal_launch_outcomes() -> set[str]:
    """Every literal `emit["outcome"]` `launch_on_miner` can return — the
    string `launch._fail_placement` stores as `Placement.reason` — plus
    `_fail_placement`'s own defaults. Read from the source, like the
    drain-cause guard: a new `_terminal("...")` / `"outcome": "..."`
    literal shows up here without anyone remembering to register it."""
    from apps.orchestration.services import launch

    src = inspect.getsource(launch.launch_on_miner)
    found = set(re.findall(r'_terminal(?:_after_register)?\(\s*"([a-z-]+)"', src))
    for m in re.finditer(r'"outcome":\s*"([a-z-]+)"(?:\s+if\s+[\w.]+\s+else\s+"([a-z-]+)")?', src):
        found.update(g for g in m.groups() if g)
    # The measured-cmdline refusals `launch_on_miner` returns via
    # `_terminal(refusal[0], …)`: their `(outcome, message)` tuples.
    found.update(
        re.findall(
            r'return\s*\(?\s*"([a-z-]+)",',
            inspect.getsource(launch._measured_cmdline_refusal),
        )
    )
    module = inspect.getsource(launch)
    # `_fail_placement(placement, reason=out.emit.get("outcome", "<default>"))`
    found.update(re.findall(r'_fail_placement\([^\n]*?"outcome",\s*"([a-z-]+)"', module))
    # `reason=(reason or "<default>")[:256]` inside `_fail_placement`
    found.update(re.findall(r'reason or "([a-z-]+)"', inspect.getsource(launch._fail_placement)))
    return found


def test_every_launch_outcome_is_a_refusal_or_declared_vali_side() -> None:
    """Every literal outcome `launch_on_miner` can store on a placement is
    either a launch-time refusal (`LAUNCH_REFUSAL_OUTCOMES`) or explicitly
    declared a vali-side fault (`NON_NODE_LAUNCH_OUTCOMES`). A new outcome
    without a decision fails CI instead of shipping invisible (or, worse,
    visible under the wrong word)."""
    found = _literal_launch_outcomes()
    assert len(found) >= 20, found  # 17 terminals + accepted/rejected/preflight + default
    # the string the contract argues about most is a literal — and excluded
    assert "golden-base-unresolved" in found
    assert "golden-base-unresolved" in reasons.NON_NODE_LAUNCH_OUTCOMES
    success = {"miner-accepted"}
    refusal = set(reasons.LAUNCH_REFUSAL_OUTCOMES)
    vali_side = set(reasons.NON_NODE_LAUNCH_OUTCOMES)
    assert not (refusal & vali_side)
    unclassified = found - success - refusal - vali_side
    assert not unclassified, unclassified
    # The one mapped string that is NOT a `launch_on_miner` literal:
    # `dispatch-failed-after-register` is `launch_vm`'s `LaunchResult.outcome`
    # (`Vm.launch_abandoned_outcome`); the placement under it carries the last
    # attempt's own outcome (`miner-rejected` / `edge-*`). Mapped for the
    # contract, tracked here so the exception stays exactly one string.
    assert (refusal | vali_side) - found == {"dispatch-failed-after-register"}


@contextlib.contextmanager
def _warnings(monkeypatch: pytest.MonkeyPatch) -> Iterator[list[str]]:
    """Reset the once-per-cause memory and collect the module logger's
    WARNING messages (the `apps` loggers do not propagate to root, so
    `caplog` would see nothing — attach to the logger directly)."""
    monkeypatch.setattr(reasons, "_WARNED_UNKNOWN_DRAINS", set())
    out: list[str] = []

    class _Sink(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            out.append(record.getMessage())

    sink = _Sink(level=logging.WARNING)
    reasons.log.addHandler(sink)
    try:
        yield out
    finally:
        reasons.log.removeHandler(sink)


def test_unknown_drain_cause_is_unknown_and_warned_once(monkeypatch: pytest.MonkeyPatch) -> None:
    with _warnings(monkeypatch) as out:
        assert reasons.public_refusal_reason("drain:foo") == "unknown"
        assert reasons.public_refusal_reason("drain:foo") == "unknown"
        assert reasons.public_refusal_reason("drain:bar") == "unknown"
    assert len(out) == 2, out
    assert "'drain:foo'" in out[0] and "'drain:bar'" in out[1]
    assert "_REFUSAL_ALIASES" in out[0]


@pytest.mark.parametrize(
    "raw",
    [
        "drain:vm-terminal",
        "released:vm-destroyed",
        "vault-failure",
        "golden-base-unresolved",
        "seed",
        "",
        None,
    ],
)
def test_non_refusals_never_warn(raw: str | None, monkeypatch: pytest.MonkeyPatch) -> None:
    """The warning is about a STALE mapping of the scheduler's own drains.
    A VM-side drain and everything that is not a drain at all (a vali-side
    launch outcome included) are excluded at selection, not stale, and must
    not raise an alarm."""
    with _warnings(monkeypatch) as out:
        assert reasons.public_refusal_reason(raw) == "unknown"
    assert out == []


def test_launch_refusals_never_warn(monkeypatch: pytest.MonkeyPatch) -> None:
    with _warnings(monkeypatch) as out:
        for raw in sorted(reasons.LAUNCH_REFUSAL_OUTCOMES):
            assert reasons.public_refusal_reason(raw) in reasons.LAUNCH_REASONS
    assert out == []
