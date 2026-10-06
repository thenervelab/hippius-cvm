"""The public reason vocabulary — ONE module, three consumers.

- `apps.scheduler.service.dispatchability` emits the six registry gates;
- `apps.telemetry.release_service` emits the six host-attestor gates;
- `apps.operator` serializes both, plus `Placement.reason` mapped through
  `public_refusal_reason`.

Each value names the FIRST gate a node fails, in the order the scheduler
applies them. The upstream product API validates every string it receives
against this same list (its `SchedulableReason` / `RefusalReason`), so a
value added here must be added there in the same change.

Nothing else is ever serialized to an operator: an internal string that is
not in the vocabulary (a launch outcome or drain cause vali does not map, a
free-form `/fail` body) is reported as `unknown`. This module imports only
the stdlib so both `scheduler` and `telemetry` can depend on it.

WHICH failed placements count as a refusal at all is decided by PROVENANCE
first (`Placement.failure_source`, stamped by every write site), and only
then by the reason text. `Placement.failed_at` is stamped at EVERY
placement end; two sources are a judgement about the node:

- `scheduler_drain` — the scheduler's own §13 drains (`service.reeval_once`
  → `drain:<cause>`), minus the causes that judge the VM rather than the
  node (`NON_NODE_DRAIN_REASONS`);
- `launch` — `launch._fail_placement` storing `launch_on_miner`'s outcome.
  Selected only when the outcome is one in which the NODE refused, could
  not be reached or lost the VM (`LAUNCH_REFUSAL_OUTCOMES`). A launch that
  died on vali's side of the wire — Vault, ticket mint, KBS admin, the
  golden-base resolution, vali settings — is a control-plane fault
  (`NON_NODE_LAUNCH_OUTCOMES` / `NON_NODE_OUTCOME_PREFIXES`) and is NOT a
  refusal, however it ended for the tenant.

`release` (the VM was destroyed), `manual` (a root `/fail` body — whatever
it spells, even a launch outcome verbatim), `migration` and `legacy` (a
row that ended before provenance was recorded: unattributable, so refused
rather than guessed) are never surfaced.

`no-miner-in-region` is deliberately NOT here: it is a per-launch
`PlacementError` category (a 409 on `/place`, `replacement_error` on
`/fail`, the launch outcome), never a `Placement.reason` — the launch
returns before a row exists — so it is not a refusal any node made.
"""

from __future__ import annotations

import logging

log = logging.getLogger(__name__)

# ─── registry gates (`service.dispatchability`) ─────────────────────────

#: Locally quarantined by the operator (`MinerStatus.QUARANTINED`).
REASON_QUARANTINED = "quarantined"
#: Declared dead by a manual failover and not yet cleared by an operator
#: (`orchestration.FailoverQuarantine`).
REASON_FAILOVER_QUARANTINED = "failover-quarantined"
#: Any other non-`ACTIVE` local status.
REASON_NOT_ACTIVE = "not-active"
#: No `chain_node_id` — the identity is not bridged to the chain yet.
REASON_NOT_BRIDGED = "not-bridged"
#: No `netbird_ip` — vali cannot reach the host to dispatch a launch.
REASON_UNREACHABLE = "unreachable"
#: Last accepted heartbeat older than `miner_liveness_timeout_s()` (or none).
REASON_HEARTBEAT_STALE = "heartbeat-stale"
#: `platform_id` is a label, not an AMD CHIP_ID — the launch cannot be
#: pinned to the host's SNP identity.
REASON_PLATFORM_ID_INVALID = "platform-id-invalid"

# ─── host-attestor gates (`release_service.attestor_coverage_by_node`) ──

#: No release pinned yet — no host is on a desired measurement (fail-closed).
REASON_RELEASE_UNPINNED = "release-unpinned"
#: No `HostAttestor` row at all for this node.
REASON_ATTESTOR_MISSING = "attestor-missing"
#: Only `pending` rows — enrolled, never attested (a pending row is NOT coverage).
REASON_ATTESTOR_PENDING = "attestor-pending"
#: Only `expired` rows — the enrollment cert lapsed; a fresh cert must re-enroll.
REASON_CERT_EXPIRED = "cert-expired"
#: An `attested` row exists but on an OLD (non-desired) measurement.
REASON_MEASUREMENT_STALE = "measurement-stale"
#: An `attested` row on a desired measurement whose last beacon is outside
#: the liveness window (or that never beaconed).
REASON_ATTESTOR_STALE = "attestor-stale"

# ─── launch-time refusals (`launch._fail_placement`) ────────────────────
#
# Not gates: a placement WAS decided, then the launch on that node did not
# happen. Only ever a `recent_refusals[].reason`, never a
# `schedulable_reason`.

#: The node said no, or was not fit, at launch: the miner-agent rejected
#: the order, could not stage / verify the boot artefacts at preflight, or
#: the dispatch to it was misconfigured on the node side.
REASON_LAUNCH_REJECTED = "launch-rejected"
#: The node could not be reached at launch: the dispatch to the host
#: failed at the transport, timed out, or errored on the way.
REASON_LAUNCH_UNREACHABLE = "launch-unreachable"
#: The launch died on the node after it was registered to it.
REASON_LAUNCH_FAILED = "launch-failed"

#: Out-of-vocabulary — the only value that is neither a gate nor a launch
#: outcome.
REASON_UNKNOWN = "unknown"

#: What `schedulable_reason` may carry when a node is not schedulable.
SCHEDULABLE_REASONS: frozenset[str] = frozenset(
    {
        REASON_QUARANTINED,
        REASON_FAILOVER_QUARANTINED,
        REASON_NOT_ACTIVE,
        REASON_NOT_BRIDGED,
        REASON_UNREACHABLE,
        REASON_HEARTBEAT_STALE,
        REASON_PLATFORM_ID_INVALID,
        REASON_RELEASE_UNPINNED,
        REASON_ATTESTOR_MISSING,
        REASON_ATTESTOR_PENDING,
        REASON_CERT_EXPIRED,
        REASON_MEASUREMENT_STALE,
        REASON_ATTESTOR_STALE,
    }
)

#: The launch-time refusals — a `recent_refusals[].reason` only.
LAUNCH_REASONS: frozenset[str] = frozenset(
    {REASON_LAUNCH_REJECTED, REASON_LAUNCH_UNREACHABLE, REASON_LAUNCH_FAILED}
)

#: What a `recent_refusals[].reason` (and a `refusal_breakdown_30d` key)
#: may carry.
REFUSAL_REASONS: frozenset[str] = SCHEDULABLE_REASONS | LAUNCH_REASONS | {REASON_UNKNOWN}

# ─── which FAILED placements are refusals ───────────────────────────────

#: `Placement.reason` prefix of the scheduler's own §13 drains
#: (`service.reeval_once` writes `f"drain:{cause}"`, causes from
#: `service._drain_cause`). Documentation of the stored shape and the key
#: of the stale-alias warning below; the SELECTION is on
#: `failure_source = scheduler_drain`, not on this text.
DRAIN_REASON_PREFIX = "drain:"

#: Drains that judge the VM, not the node — excluded despite the source.
#: `vm-terminal`: the VM reached Destroyed / Decommissioning and its slot
#: is released retroactively (a destroy path skipped
#: `release_placements_for_vm`); the miner may be perfectly healthy.
NON_NODE_DRAIN_REASONS: frozenset[str] = frozenset({"drain:vm-terminal"})

# Internal `Placement.reason` values vali writes itself (`service._drain_cause`)
# that have an exact public equivalent. Everything else is `unknown`.
_REFUSAL_ALIASES: dict[str, str] = {
    "drain:miner-quarantined": REASON_QUARANTINED,
    "drain:miner-inactive": REASON_NOT_ACTIVE,
    "drain:miner-decommissioned": REASON_NOT_ACTIVE,
    "drain:miner-missing": REASON_NOT_ACTIVE,
    "drain:miner-stale": REASON_HEARTBEAT_STALE,
}

# Launch outcomes (`launch_on_miner` → `emit["outcome"]`, stored verbatim by
# `launch._fail_placement` with `failure_source = launch`) in which the NODE
# is the party that failed. EXACTLY the three-sided contract (vali, the
# product API, the dashboard) — a value added here must be added there in
# the same change. The keys are the exact stored strings; the selection in
# `apps.operator.service._refusals` is `failure_source = launch AND reason
# IN LAUNCH_REFUSAL_OUTCOMES`, so a launch outcome that is not a key here
# is never a refusal.
_LAUNCH_ALIASES: dict[str, str] = {
    # miner-agent answered the launch order with a non-2xx
    "miner-rejected": REASON_LAUNCH_REJECTED,
    # miner-agent could not stage / verify the boot artefacts
    "preflight-failure": REASON_LAUNCH_REJECTED,
    # `OrderDispatchMisconfigured`: the dispatch to this node could not be
    # formed (node-side per the contract)
    "misconfigured": REASON_LAUNCH_REJECTED,
    # `OrderDispatchUnavailable`: transport failure / timeout on the
    # dispatch to the host
    "edge-unreachable": REASON_LAUNCH_UNREACHABLE,
    # `OrderDispatchError`: the dispatch to the host errored
    "edge-error": REASON_LAUNCH_UNREACHABLE,
    # `_fail_placement`'s own default when an outcome has no `outcome`
    "launch-failed": REASON_LAUNCH_FAILED,
    # `LaunchResult.outcome` when the same-miner retries after the KBS
    # registration are exhausted (`Vm.launch_abandoned_outcome`); the
    # placement itself carries the last attempt's outcome. Mapped so the
    # public value is defined wherever this string is stored.
    "dispatch-failed-after-register": REASON_LAUNCH_FAILED,
}

#: The stored `Placement.reason` values that ARE launch-time refusals —
#: the operator selection set (for `failure_source = launch` rows).
LAUNCH_REFUSAL_OUTCOMES: frozenset[str] = frozenset(_LAUNCH_ALIASES)

#: Launch outcomes that are NOT refusals: control-plane faults — the
#: launch died on vali's side of the wire, the node never got to answer
#: (or its answer was not what failed). Exact strings `launch_on_miner`
#: can emit; listed so the drift guard can prove every literal outcome has
#: been classified one way or the other.
NON_NODE_LAUNCH_OUTCOMES: frozenset[str] = frozenset(
    {
        # vali settings / fail-closed posture, before any host is touched
        "launch-digest-not-configured",
        # the launch named another miner's CHIP_ID (explicit-miner paths)
        "platform-id-mismatch",
        "netbird-bad-userdata",
        "netbird-mint-failure",
        # customer-held keys: the measured cmdline does not carry exactly the
        # VM's pinned guardian binding, or an M1/M2 one would be truncated
        "customer-keys-cmdline-refused",
        # vali → Vault / lifecycle keygen
        "vault-failure",
        "lifecycle-keygen-failure",
        # vali's independent launch-digest recompute (C2). A mismatch is a
        # measurement-policy verdict — the host's OVMF or vali's pinned
        # one — not the node refusing the VM.
        "launch-digest-recompute-failure",
        "launch-digest-mismatch",
        # the caller supplied an explicit measurement that no longer matches
        # vali's recompute of the measured cmdline — a caller/config fault,
        # not the node refusing the VM.
        "explicit-measurement-stale",
        # vali built a measured cmdline longer than 2033 bytes (the kernel's
        # 2047-byte limit less OVMF's 14-byte `initrd=initrd ` prefix; it
        # would boot truncated below the measured length) — a
        # vali-side config fault, before any host is trusted.
        "cmdline-too-long",
        # vali → KBS
        "allowlist-pin-failure",
        # other pins held the §22 pin lock past its wait (vali-side queue;
        # retried, the miner is not excluded)
        "allowlist-pin-busy",
        "mint-failure",
        "kbs-admin-conflict",
        "kbs-admin-terminal",
        "kbs-admin-unavailable",
        "kbs-admin-error",
        # vali's own Vm row refused the register (decommissioning,
        # migrating, moved generation/host) — nothing reached the KBS
        "kbs-admin-vm-state-refused",
        # vali could not record a superseding register in its own ledger;
        # nothing was dispatched (a retry supersedes again)
        "supersede-mark-failed",
        # the control plane's own image resolution: the preflight answer
        # named no per-VM golden base vali would accept (P9/#16) — an image
        # fault on vali's side of the policy, not the node refusing
        "golden-base-unresolved",
        # the guest components floor (docs/design/guest-component-rollout.md):
        # vali refused to launch a set below the VM's required epoch before
        # anything was staged — vali's own policy, not the node
        "guest-epoch-below-required",
    }
)

#: Families of control-plane outcomes excluded by PREFIX, per the contract
#: (`kbs-admin-*`, `secret-fetch-failed*`, `source-ack-timeout*`). The last
#: two are `LaunchJob` / migration-job outcomes that never reach
#: `Placement.reason` today; declared so that if one ever does, it is
#: refused by construction and the contract is visible in one place.
NON_NODE_OUTCOME_PREFIXES: tuple[str, ...] = (
    "kbs-admin-",
    "secret-fetch-failed",
    "source-ack-timeout",
)


def is_control_plane_fault(raw: str | None) -> bool:
    """`True` for a launch outcome the contract excludes from refusals —
    an exact member of `NON_NODE_LAUNCH_OUTCOMES` or one of the excluded
    prefix families. Never `True` for a `LAUNCH_REFUSAL_OUTCOMES` member."""
    stored = raw or ""
    return stored in NON_NODE_LAUNCH_OUTCOMES or stored.startswith(NON_NODE_OUTCOME_PREFIXES)


# Drain causes already reported as stale (see `public_refusal_reason`) —
# one WARNING per cause per process. Bounded by the set of `drain:` strings
# vali's own code writes, so it cannot grow with traffic.
_WARNED_UNKNOWN_DRAINS: set[str] = set()


def public_refusal_reason(raw: str | None) -> str:
    """Map a stored `Placement.reason` onto the public vocabulary. Exact
    match only (no case folding, no stripping): a value that is not a gate
    and not a known alias is `unknown` — it never reaches an operator.

    A `drain:` cause with no alias is a stale vocabulary (a new cause was
    added to `_drain_cause` without a mapping here): still `unknown`, but
    logged ONCE per cause so the gap is visible instead of silent.
    """
    if raw in SCHEDULABLE_REASONS:
        return raw  # type: ignore[return-value]  # membership proves str
    stored = raw or ""
    public = _REFUSAL_ALIASES.get(stored) or _LAUNCH_ALIASES.get(stored)
    if public is not None:
        return public
    if (
        stored.startswith(DRAIN_REASON_PREFIX)
        and stored not in NON_NODE_DRAIN_REASONS
        and stored not in _WARNED_UNKNOWN_DRAINS
    ):
        _WARNED_UNKNOWN_DRAINS.add(stored)
        log.warning(
            "refusal vocabulary is stale: drain cause %r has no public alias "
            "(reported as %r) — add it to apps.scheduler.reasons._REFUSAL_ALIASES",
            stored,
            REASON_UNKNOWN,
        )
    return REASON_UNKNOWN
