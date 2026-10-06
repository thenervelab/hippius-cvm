"""§23 miner reward weight — derived from REAL hosting, not advertised
capacity.

The on-chain `EpochWeights[epoch][node_id]` the scheduler ranks by + the
reward distributes by must reflect what a miner *actually hosts* (the
tenant VMs bound to it), never the raw capacity it advertises — otherwise
a miner could advertise a huge fleet, host nothing, and still be paid.

vali is the trustless source of this signal: **vali placed the VMs**, so
it knows the exact flavor (cpu/ram/disk the tenant reserved) bound to each
miner from its own `Placement` records — no miner self-report. In
confidential compute the host cannot see *inside* a VM (it is encrypted),
so the only measurable AND economically correct metric is the **reserved
flavor capacity of the VMs a miner hosts**.

    weight(miner) = Σ  resource_units(flavor(vm))
                  vm ∈ bound placements on miner

`resource_units` is a $-denominated blend of cpu + ram + disk (operator-
tunable). A liveness factor (the SNP-attested KBS keepalive ratio) is a
planned refinement — today a placement only counts while `Bound`, and the
§13 re-eval drains a placement the moment its miner leaves `Active`, so a
dark miner stops accruing weight without it.

The result feeds `chain.submit_epoch_close` → `pallet-compute-scoring`'s
root-only `vali_submit_epoch_close`. This is the producer the chain was
missing (without it `EpochWeights` is empty ⇒ every miner scores 0).
"""

from __future__ import annotations

import logging

from django.conf import settings
from django.db.models import Max

from apps.orchestration.services import flavors

from .models import MinerCapacity, Placement, PlacementStatus, UsageAccrual

log = logging.getLogger("apps.scheduler.scoring")


def _coeff(name: str, default: float) -> float:
    return float(getattr(settings, name, default))


def resource_units(flavor_name: str) -> int:
    """The integer weight one VM of `flavor_name` contributes — a blend of
    its reserved cpu + ram + disk. Unknown flavor ⇒ 0 (a placement whose
    `resource_class` is not a catalogue flavor doesn't accrue weight).

    Coefficients are operator-tunable (a $-cost ratio); the `* SCALE`
    keeps the on-chain `u128` an integer without losing the fractional
    blend. Defaults: 1 unit / vCPU, 0.25 / GB-RAM, 0.005 / GB-disk,
    scaled ×1000.
    """
    try:
        size = flavors.resolve_flavor(flavor_name)
    except flavors.UnknownFlavor:
        return 0
    cpu_w = _coeff("VALI_SCORING_CPU_WEIGHT", 1.0)
    ram_w = _coeff("VALI_SCORING_RAM_WEIGHT", 0.25)
    disk_w = _coeff("VALI_SCORING_DISK_WEIGHT", 0.005)
    scale = _coeff("VALI_SCORING_SCALE", 1000.0)

    ram_gb = size.memory_mb / 1024.0
    # The miner hosts both the rootfs and the tenant data disk.
    disk_gb = size.data_disk_size_gb + size.luks_disk_size_gb
    blend = size.cpu_count * cpu_w + ram_gb * ram_w + disk_gb * disk_w
    return int(round(blend * scale))


def compute_epoch_weights() -> dict[str, int]:
    """Per-miner reward weight — `{miner_node_id (64-hex): weight_u128}`,
    the exact shape `vali_submit_epoch_close` takes.

    Two sources, selected by `VALI_EPOCH_WEIGHT_SOURCE`:

    - `snapshot` (v1 default) — Σ `resource_units` of the currently
      **bound** placements. A bound-but-DOWN VM still earns full weight.
    - `usage` — Σ `unit_seconds` from the attested `UsageAccrual` ledger
      for the current epoch: a VM earns only for the time it was proven UP
      (it emitted signed served-receipts). This is the uptime-integrated
      reward — flip to it once receipts are confirmed flowing live.

    Blackbox host-attestor reward MULTIPLIER (PR-11), behind
    `VALI_REWARD_REQUIRE_ATTESTOR` (DEFAULT FALSE ⇒ this returns the base
    weight BYTE-IDENTICAL to before): when armed, each miner's base weight
    is MULTIPLIED by its host-attestor liveness ratio (see
    `apply_attestor_liveness_multiplier`). Never additive — an idle-but-alive
    attestor keeps earning 0, a real-usage miner with a dead attestor drops
    to 0.

    Zombie withhold: a miner that is zombie-quarantined when the weights
    are computed (still relaying frames from a VM whose §24 crypto-erase
    already ran — `apps.lifecycle.zombie`) is DROPPED from this epoch's
    weights, whichever source is selected. Derived from fresh signals only:
    the next computation after the frames stop pays it normally again.
    """
    source = str(getattr(settings, "VALI_EPOCH_WEIGHT_SOURCE", "snapshot"))
    base = _usage_weights() if source == "usage" else _snapshot_weights()
    base = withhold_zombie_quarantined(base)
    # DEFAULT-OFF ⇒ return the base weights UNCHANGED (byte-identical to the
    # pre-PR-11 behaviour). The multiplier only applies once an operator
    # arms `VALI_REWARD_REQUIRE_ATTESTOR` at PR-13.
    if not bool(getattr(settings, "VALI_REWARD_REQUIRE_ATTESTOR", False)):
        return base
    return apply_attestor_liveness_multiplier(base)


def withhold_zombie_quarantined(base: dict[str, int]) -> dict[str, int]:
    """Drop every zombie-quarantined miner from `base`, loudly."""
    from apps.lifecycle.zombie import quarantined_node_ids

    quarantined = quarantined_node_ids()
    if not quarantined:
        return base
    kept = {n: w for n, w in base.items() if n.lower() not in quarantined}
    for node_id in sorted(set(base) - set(kept)):
        log.error(
            "scoring: WITHHOLDING reward weight %d from node %s — it is "
            "zombie-quarantined (still running a VM whose §24 crypto-erase "
            "already ran)",
            base[node_id],
            node_id[:16],
        )
    return kept


def apply_attestor_liveness_multiplier(base: dict[str, int]) -> dict[str, int]:
    """MULTIPLY each miner's `base` reward weight by its host-attestor
    liveness ratio ∈ [0, 1] — the blackbox host-attestor reward gate (PR-11).

    CRITICAL (SLA must-have #5): a MULTIPLIER, NEVER additive. Bare attestor
    liveness can only ever SCALE DOWN a weight the miner ALREADY earned from
    real tenant hosting; it can never mint reward on its own. Worked cases:

      - idle-but-alive attestor   → base 0 (no usage)   × ratio  = 0
      - real usage, dead attestor → base > 0            × 0      = 0
      - real usage, alive attestor→ base > 0            × ratio ⇒ base×ratio

    Fail-closed: a node absent from the liveness meter (no `attested` row, a
    `pending` row, a stale measurement, or a dead beacon) gets ratio 0 and is
    DROPPED (weight 0 ⇒ absent, matching the base's own drop-zeros contract).
    ATTESTED-only is enforced inside the meter (never consumes `pending`).
    """
    # Lazy import — the meter lives in the telemetry app; importing at module
    # load would couple scheduler↔telemetry at import time.
    from apps.telemetry.release_service import attestor_liveness_ratios

    ratios = attestor_liveness_ratios()
    out: dict[str, int] = {}
    for node_id, weight in base.items():
        ratio = ratios.get(node_id.lower(), 0.0)
        scaled = int(weight * ratio)
        if scaled > 0:
            out[node_id] = scaled
    return out


def _excluded_owners() -> frozenset[str]:
    """The VM owners whose hosting must NOT earn reward weight or a bill —
    OUR OWN infrastructure, not tenants.

    **Why this exists.** With `VALI_EPOCH_WEIGHT_SOURCE=usage` the ledger
    IS the reward. Without this filter an operator VM could hold a large
    share of the epoch's units: a single dead synthetic-monitor probe
    (destroyed days earlier) can keep carrying a large slice of the
    epoch's unit_seconds on its own, because a suspended closer never
    rolls the bucket over. Paying ourselves out of the miner
    reward pot is a straight dilution of every honest miner.

    **The discriminator is `Placement.owner`, not `UsageAccrual.lease_id`.**
    Both were candidates; owner wins on three counts, checked against the
    live rows rather than assumed:

    - It states the actual predicate. "Do not pay for VMs WE own" is a
      claim about ownership; a lease id is a billing-agreement label that
      merely happens to be prefixed by whichever harness minted it.
    - It does not couple reward policy to an f-string. The `synmon-` prefix
      is built in `apps/synthetic/e2e.py`; renaming it there would silently
      re-open the skim, and it would fail OPEN (we start paying ourselves
      again). `owner` comes from the launch spec, the same
      `VALI_SYNTHETIC_TENANT_ID` the synthetic reaper already keys its
      "never touch a real tenant" invariant on.
    - It covers MORE of the operator rows for LESS configuration. Operator
      lease ids come in several shapes (`synmon-*`, a one-off harness's
      own lease, an ordinary-looking lease id); a lease filter needs a
      separate pattern for each, while an ordinary-looking lease that
      carries `owner="synthetic-monitor"` is caught for free — a couple of
      configured owners cover every operator row.

    **Neither field is authenticated, and that is load-bearing.** `owner`
    is `spec.user_id` copied straight out of the launch body
    (`orchestration/services/launch.py`, `scheduler/views.py`); vali does
    not verify it. This is only tolerable under architecture A, where our
    own Django API sits in front of vali and holds the only vali
    credential — a tenant never gets a vali token and never sets this
    field. **If that ever stops being true, this becomes an attack:** a
    caller able to set `user_id` could name an excluded identity while
    running on a miner and zero that miner's reward for the epoch — a
    cheap, targeted grief with no cost to the attacker. Guard the day
    vali takes untrusted callers directly: at that point the excluded set
    must key off something vali itself stamps (e.g. an operator flag set
    by the launch path, not by the body).

    **Operator configuration, never a literal.** `VALI_REWARD_EXCLUDED_OWNERS`
    (chart: `rewardExcludedOwners`) is the list; the synthetic monitor's own
    tenant id is ALWAYS unioned in, so an operator editing that list to add
    a one-off rehearsal identity cannot accidentally drop the probe fleet
    back into the pot. An empty set (both unset) is a strict no-op — the
    default can never silently zero a real fleet.
    """
    configured = getattr(settings, "VALI_REWARD_EXCLUDED_OWNERS", ()) or ()
    if isinstance(configured, str):
        configured = [configured]
    owners = {str(owner).strip() for owner in configured}
    # The synthetic monitor's tenant is ours BY CONSTRUCTION — there is no
    # configuration in which we want to pay a miner for hosting our own
    # probes, so it is not removable via the list above.
    owners.add(str(getattr(settings, "VALI_SYNTHETIC_TENANT_ID", "") or "").strip())
    # `Placement.owner` is blank for legacy/unknown rows; an empty entry
    # would exclude every one of them.
    return frozenset(owner for owner in owners if owner)


def _excluded_vm_ids() -> frozenset[str]:
    """`vm_id`s that vali placed on behalf of an excluded owner.

    `UsageAccrual` carries no owner (only `lease_id` / `vm_id` /
    `miner_node_id`), so the ownership fact lives one join away on
    `Placement`. Any placement of a VM — Pending, Bound or Failed —
    identifies its owner, and a VM's owner never changes, so no status
    filter is applied.

    Fails OPEN by construction: a usage row whose VM has no `Placement`
    is counted. That is the conservative direction — the cost is that we
    might keep paying for one of our own rows, never that a tenant's
    miner silently loses an epoch of reward.
    """
    owners = _excluded_owners()
    if not owners:
        return frozenset()
    return frozenset(
        Placement.objects.filter(owner__in=owners)
        .values_list("vm__vm_id", flat=True)
        .distinct()
    )


def _billable_usage_rows(epoch: int) -> list[tuple[str, int]]:
    """`[(miner_node_id, unit_seconds)]` for `epoch`, operator-owned VMs
    DROPPED — the single read both the reward weight and the priced bill
    go through, so the two can never disagree about which usage counts.

    **The exclusion is applied HERE, at read time, and NOT at accrual.**
    `usage.accrue_usage_once` keeps writing every attested row, ours
    included. Three reasons: the ledger stays a complete, auditable record
    of what actually ran (we can still answer "how much did our own
    monitoring consume?"); the policy is reversible by editing config
    instead of unrecoverable data loss, so a mis-set owner list is a
    one-line fix rather than a month of destroyed billing history; and the
    accrual path is the security-critical one (receipt authentication) —
    adding reward policy to it widens exactly the code we least want to
    churn.
    """
    excluded = _excluded_vm_ids()
    rows = UsageAccrual.objects.filter(epoch=epoch).values_list(
        "miner_node_id", "vm_id", "unit_seconds"
    )
    kept: list[tuple[str, int]] = []
    dropped = 0
    dropped_units = 0
    for node_id, vm_id, unit_seconds in rows:
        if vm_id in excluded:
            dropped += 1
            dropped_units += int(unit_seconds)
            continue
        kept.append((node_id, int(unit_seconds)))
    if dropped:
        log.info(
            "scoring: epoch %d — excluded %d operator-owned usage row(s) "
            "(%d unit_seconds) owned by %s",
            epoch,
            dropped,
            dropped_units,
            sorted(_excluded_owners()),
        )
    return kept


def _snapshot_weights() -> dict[str, int]:
    """Instantaneous Σ resource_units of BOUND placements (a bound-but-down
    VM still counts). The §13 drain still keeps a DARK miner out; a miner
    that is up but quarantined or chain-stale keeps its placements while
    its VMs still run there (`reeval_once` holds them), so this source
    pays it until they migrate off. `usage` pays only attested uptime.

    Operator-owned placements are dropped here too (see
    [`_excluded_owners`]): the two weight sources must agree on whose VMs
    are payable, or flipping `VALI_EPOCH_WEIGHT_SOURCE` back to `snapshot`
    would quietly re-open the skim.
    """
    weights: dict[str, int] = {}
    query = Placement.objects.filter(status=PlacementStatus.BOUND.value)
    owners = _excluded_owners()
    if owners:
        query = query.exclude(owner__in=owners)
    rows = query.values_list("miner_node_id", "resource_class")
    for node_id, resource_class in rows:
        units = resource_units(resource_class)
        if units <= 0:
            continue
        weights[node_id] = weights.get(node_id, 0) + units
    return weights


def latest_usage_epoch() -> int | None:
    """The newest epoch with any attested usage — the newest bucket the
    ledger HOLDS. `None` when the ledger is empty (no receipts yet).

    ⚠️ NOT the epoch to bill or reward for — see [`billing_epoch`]. This
    answers "is there any attested usage at all", which is what the GC
    retention window and the "surface the bill?" gate need.
    """
    return UsageAccrual.objects.aggregate(m=Max("epoch"))["m"]


def billing_epoch() -> int | None:
    """The CHAIN epoch usage is currently accruing into — the DB-cached
    on-chain `CurrentEpoch` (`MinerCapacity.observed_epoch`), refreshed
    on every chain read. `None` when the cache is cold (fresh cluster).

    This is the epoch selector for reward + billing, and it is
    deliberately the SAME source `usage._current_epoch()` stamps rows
    with, so the producer and the consumer of a bucket agree by
    construction.

    **Why not `latest_usage_epoch()`** — that was the previous selector
    and it is a REWARD DUPLICATION bug. `max(epoch)` is a property of the
    LEDGER, not of the chain: when accrual stalls (a quiet fleet, a
    telemetry gap, every VM rebooting) the ledger stops rolling over
    while the chain epoch keeps advancing, so the SAME bucket is handed
    to every subsequent close and paid again each time.

    It is not hypothetical. In production the ledger once held exactly
    one row for an older epoch N and the closer logged the same
    `vali weights: 1 miner(s), total ...` on three consecutive closes —
    one bucket of proven uptime submitted as the weights of chain epochs
    N+4, N+5 and N+6.

    Keying on the chain epoch makes a stalled ledger fail CLOSED instead:
    the close reads the new epoch's bucket, finds it empty, and submits
    nothing. No proven uptime ⇒ no reward, which is the whole point of
    uptime-integrated rewards.
    """
    epoch = MinerCapacity.objects.aggregate(m=Max("observed_epoch"))["m"]
    epoch = int(epoch or 0)
    # `0` is the cold-cache sentinel, never a real billing epoch: emitting
    # weights from an unknown chain position could re-pay a closed epoch.
    return epoch if epoch > 0 else None


def _usage_weights() -> dict[str, int]:
    """Uptime-integrated Σ `unit_seconds` per miner for the chain epoch
    currently accruing ([`billing_epoch`] — NOT the newest ledger
    bucket; see that docstring for the duplication bug that was).

    Operator-owned VMs contribute ZERO (see [`_excluded_owners`]) — the
    reward pot pays miners for hosting TENANTS, not for hosting our own
    monitoring probes."""
    epoch = billing_epoch()
    if epoch is None:
        return {}
    weights: dict[str, int] = {}
    for node_id, unit_seconds in _billable_usage_rows(epoch):
        if unit_seconds <= 0:
            continue
        weights[node_id] = weights.get(node_id, 0) + int(unit_seconds)
    return weights


def compute_owed_micro_usd(price_by_node: dict[str, int]) -> dict[str, int]:
    """`{miner_node_id: owed_micro_usd}` for the current epoch — the
    PRICED bill (the direct answer to "how much we owe each miner"),
    computed from ATTESTED uptime only.

    `owed = Σ unit_seconds × MinerPrice / (period × SCALE)`, where
    `MinerPrice` is USD-micros per resource-unit per
    `VALI_BILLING_PRICE_PERIOD_S` seconds (default 3600 ⇒ a
    per-resource-unit-hour price). A miner with no on-chain price is
    omitted (no bill). A down VM contributed no `unit_seconds`, so it is
    not billed — fail-closed.

    **The `× SCALE` divisor is the fix for a three-orders-of-magnitude
    overbill.** `resource_units` multiplies its cpu/ram/disk blend by
    `VALI_SCORING_SCALE` (default 1000) — deliberately, because the
    on-chain `EpochWeights` is a `u128` and the blend is fractional, so
    the scale keeps a RANKING weight integral. `unit_seconds` inherits it.
    Pricing then used that scaled number directly against a price the
    miner announced per REAL resource-unit, so every bill came out ×1000.
    Live: a `small` VM (1.59 real units ⇒ 1590 scaled) at 5e6 µUSD billed
    ~7,950 USD/hour instead of ~7.95, and the epoch-weights readout showed
    1.09 M USD owed on a 3-miner testnet hosting one small VM.

    The scale is legitimate where it came from and wrong here: a ranking
    weight is not a dollar multiplier. Divide it back out at the exactly
    one place that converts units into money, and leave the weight path
    untouched — `_usage_weights` must keep emitting the scaled integer the
    chain expects.

    Billed for the chain epoch currently accruing ([`billing_epoch`]), the
    same selector the reward weights use — a bill and a reward that
    disagreed about WHICH epoch they describe would be worse than either.

    **Operator-owned VMs are excluded here too** (see [`_excluded_owners`]),
    for the same reason the epochs must match: this readout is the direct
    answer an operator gets to "how much do we owe each miner", and a
    large share of it could otherwise be the cost of our own monitoring. Two defensible
    positions existed — a miner really did burn CPU hosting our probe, so
    one could argue we owe for it — and this one is chosen because the
    readout's stated purpose is the miner payout, and a bill that says a
    different number than the weight it was derived from is a reconciliation
    trap. Consequence is contained either way: nothing COLLECTS this bill
    (its one caller is the read-only `EpochWeightsView`), so the change is
    observational until a payout path exists. If we later decide to
    reimburse our own probe hosting, that is a separate, explicit line —
    not an accident of the reward filter.
    """
    epoch = billing_epoch()
    if epoch is None:
        return {}
    period = int(getattr(settings, "VALI_BILLING_PRICE_PERIOD_S", 3600))
    if period <= 0:
        period = 3600
    # Same knob `resource_units` scaled BY, read back here so the two can
    # never drift: if an operator retunes the scale, the bill follows.
    scale = int(_coeff("VALI_SCORING_SCALE", 1000.0))
    if scale <= 0:
        scale = 1
    divisor = period * scale
    owed: dict[str, int] = {}
    for node_id, unit_seconds in _billable_usage_rows(epoch):
        price = price_by_node.get(node_id)
        if price is None or unit_seconds <= 0:
            continue
        owed[node_id] = owed.get(node_id, 0) + int(unit_seconds) * int(price) // divisor
    return owed
