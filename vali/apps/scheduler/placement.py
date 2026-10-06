"""The §23 placement decision — a pure, deterministic function.

Spec of record: ARCHITECTURE.md §23 (Scheduler) +
docs/design/marketplace-stake-slashing.md (selection composite).

[`decide_placement`] is deliberately a **pure function**: given the
on-chain snapshot + the current DB accounting, it returns the chosen
miner with **no I/O, no wall-clock, and no randomness**. Every input
is an explicit argument; the output is a deterministic function of
those arguments (§23: "Determinism still mandatory"). The view layer
does all the I/O (reads settings, the chain, the DB) and hands the
gathered facts here.

Four §23 constraints gate eligibility, all fail-closed:

  (a) **Admission bounded by proven capacity** — a miner is a
      candidate only while its active-placement load is strictly
      below its `capacity_slots`.
  (b) **Anti-affinity across families** — a miner already hosting a
      placement of the same `vm_family` is excluded.
  (c) **Fail-closed on stale epoch** — a miner whose score reflects
      an epoch more than `max_epoch_lag` behind chain is ineligible.
  (d) **Stake sufficiency** — a miner flagged stake-deficient (after a
      price dump it didn't top up) is excluded from NEW placements.
  (e) **Observed SNP start capability** — a miner vali has WATCHED fail
      to start a confidential guest REPEATEDLY (default: 3 consecutive
      in-window failures, no success in between) is excluded until it
      re-proves itself. Gates (a)–(d) all model a *quantity*; (e) models
      the binary precondition beneath them, because a host that cannot
      currently boot a CVM reports its CPU, RAM and slots as fully FREE
      — it has plenty, precisely because it is booting nothing. A
      SINGLE failure is deliberately NOT an exclusion (the underlying
      `sev_common_kvm_init … EBUSY` is measurably intermittent and
      self-recovering); it de-rates the host softly instead. See
      [`cvm_capability`] for where the evidence comes from, the measured
      base rate behind the threshold, and why a miner can neither claim
      capability it lacks nor deny a rival's.
  (f) **Detected region** — when the caller constrains the launch to a
      region, only a miner the geo-probe has MEASURED there (and, by
      default, verified — see `service.region_by_node`) is a candidate.
      Nothing declared by the miner ever enters this gate; a miner
      absent from the map is in no region at all.
  (g) **Concurrent boots per miner** — when the caller supplies it, a
      miner already booting `max_booting_per_node` guests (a launch being
      dispatched, or a guest with no in-guest signal yet since its current
      boot began) takes no further launch until one of them comes up. A
      first boot formats a LUKS2 + dm-integrity disk and is the most
      CPU/IO-hungry minute of a VM's life, and admission (a) only prices
      the RESERVED vCPU: a burst of launches would otherwise all fit, all
      land on the roomiest host and boot at once (2026-10-05: 13
      simultaneous boots on one host, load ~396, every guest stuck after
      its KEK release). Transient by nature, so it has its own error
      category and the launch path waits for a boot slot instead of
      failing. The operator may set a per-miner cap
      (`MinerCapacity.max_booting`) over the fleet value.
  (h) **Cordon** — an operator-cordoned miner (`MinerCapacity.cordoned_at`)
      takes no new placement from any caller. HARD, no fallback. It only
      closes the door: the VMs already there, their telemetry, recovery,
      power and same-host relaunches never pass through here, so nothing
      about them changes (unlike a `QUARANTINED` miner, which is drained).

Among the eligible, the winner is chosen by a **composite selection
score** — NOT by reward weight alone. Ranking by reward weight is a
cold-start / rich-get-richer trap: a brand-new miner has weight 0, so
it would never be selected, so it would never host, so its weight
would stay 0 forever. The composite separates *reward* (who gets paid,
∝ hosting) from *selection* (who gets the next VM): it gives a newcomer
a bootstrap **grace**, spreads load by **free capacity**, folds in the
miner's **price** and **stake**, and lets reward-**merit** break ties
among trusted miners WITHOUT dominating. A **concentration cap** bounds
how much any one miner hosts, so a single miner going dark can't take a
large correlated slice of the fleet down.

The merit + price terms are **conditioned on the reward signal being
alive**. A runtime upgrade that drops `pallet-compute-scoring` leaves
its storage prefix answering reads, so the snapshot's `quality` values
survive as a fossil of the last epoch close — permanently frozen, and
therefore drifting further from reality with every hour of hosting that
can no longer be scored. When `ChainSnapshot.pallet_live` is False the
ranking refuses to read merit or grant price credit off those values;
see the fossil guard in [`decide_placement`].

Only miners in on-chain `Active` status are ever considered.
"""

from __future__ import annotations

import json
import logging
import re
from collections.abc import Mapping
from dataclasses import dataclass, field

from .chain import ChainSnapshot

log = logging.getLogger("apps.scheduler.placement")

# On-chain `MinerStatus` label that gates scheduling. Mirrors the
# `read-miner-status` output + `MinerStatusMirror.ACTIVE`.
MINER_ACTIVE = "active"

# A region is an ISO 3166-1 alpha-2 country code (`FR`). Defined HERE, in
# the pure module, so the launch intake (`orchestration.launch_jobs`), the
# feasibility view and the gate below all accept exactly the same shape;
# a caller's `fra` / `France` is rejected at the edge instead of silently
# matching nothing and surfacing as a fleet-wide "no miner in region".
REGION_RE = re.compile(r"^[A-Za-z]{2}$")

# The `PlacementError` category raised when gate (g) — concurrent boots per
# miner — is what emptied the candidate set. Transient: the launch path
# waits for a boot slot on it instead of failing the job.
MINERS_BOOTING = "miners-booting"

# The two `cvm_capability` verdicts this module acts on. Re-declared as
# plain literals rather than imported so this module stays free of the
# ORM-touching one and remains importable as a pure function with no
# Django settings/DB in scope. `test_cvm_capability` asserts the two
# definitions can never drift apart.
_CVM_PROVEN = "proven"
_CVM_DEGRADED = "degraded"
_CVM_INCAPABLE = "incapable"


@dataclass(frozen=True)
class ResourceFit:
    """Capacity v2's answer for ONE VM of `resource_class` (see
    `service.resource_fit`): which hosts it fits in real units, and how
    empty each host is (`capacity.free_fraction`).

    - `enforce`  True ⇒ gate (a) is the v2 fit (a node absent from
                 `fits_by_node` is refused — fail closed) and the ranking's
                 free term is `free_fraction`. False ⇒ the v1 slot gate
                 decides and every disagreement is LOGGED (the shadow run
                 that proves v2 before it is switched on).
    - `shadow_log`  False silences the shadow line (feasibility asks the
                 scheduler five times per board — the launch path is the
                 one worth logging).
    """

    resource_class: str
    fits_by_node: Mapping[str, bool]
    free_fraction_by_node: Mapping[str, float]
    enforce: bool = False
    shadow_log: bool = True
    #: The DATA-disk gate (`VALI_SCHEDULER_DISK_GATE`), independent of the
    #: admission model: `off` ignores disk; `record` admits but logs every
    #: CHOSEN node `enforce` would have refused; `enforce` refuses. The map
    #: holds, per node, the reason `enforce` would refuse (`""` = admits);
    #: a node absent from it has no mirror row and is refused by gate (a)
    #: anyway.
    disk_mode: str = "off"
    disk_gb: int = 0
    disk_refusal_by_node: Mapping[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class PlacementError(Exception):
    """No miner satisfied the §23 constraints.

    Carries a stable `category` so the view maps it to a 409 with a
    machine-readable code. NOT an internal error — the chain read
    succeeded; there is simply nowhere eligible to place right now.
    """

    message: str
    category: str

    def __str__(self) -> str:
        return f"[{self.category}] {self.message}"


@dataclass(frozen=True)
class SelectionWeights:
    """Weights for the composite selection score. Tuned so a 0-weight
    newcomer is viable (cold-start) and reward-merit never dominates.

    Read from settings at the I/O boundary via [`from_settings`]; passed
    in explicitly so [`decide_placement`] stays pure.
    """

    # Reputation-first: merit (proven reward weight) is the dominant
    # differentiator (> grace), price is only a minor tiebreak, and it is
    # GATED on skin-in-the-game in `_score` so a zero-reputation newcomer
    # can never win by dumping its price (anti-Sybil-undercut).
    grace: float = 0.25  # newcomer bootstrap — still breaks the cold-start trap
    free: float = 0.20  # load-balance — spread to emptier miners
    merit: float = 0.30  # proven reward weight — DOMINANT (reputation leads)
    price: float = 0.05  # cheaper bids break ties — minor, gated on skin-in-game
    stake: float = 0.20  # skin-in-the-game (when stake is known)
    # Observed SNP start capability: a host vali has WATCHED boot a
    # confidential guest recently outranks one it has never watched.
    # Deliberately set EQUAL to `grace` so the two cancel exactly for the
    # pair that matters — a proven incumbent vs a never-placed newcomer —
    # leaving free capacity and merit to decide. Any larger value would
    # re-introduce the cold-start trap this module exists to avoid
    # (capability is only provable BY being placed, so an unproven miner
    # that can never outrank a proven one can never become proven);
    # any smaller and demonstrated capability would lose to noise.
    proven: float = 0.25
    # Anti-affinity, as a PREFERENCE. Every same-family VM already on a
    # host subtracts this much, so an empty host always outranks a loaded
    # one and the fleet spreads on its own. It is deliberately the largest
    # single term: spreading a tenant across hosts is what limits the blast
    # radius of one host dying, and it should lose only when there is no
    # alternative left.
    spread: float = 0.35

    @classmethod
    def from_settings(cls) -> SelectionWeights:
        from django.conf import settings

        def g(name: str, default: float) -> float:
            return float(getattr(settings, name, default))

        return cls(
            grace=g("VALI_SELECT_W_GRACE", cls.grace),
            free=g("VALI_SELECT_W_FREE", cls.free),
            merit=g("VALI_SELECT_W_MERIT", cls.merit),
            price=g("VALI_SELECT_W_PRICE", cls.price),
            stake=g("VALI_SELECT_W_STAKE", cls.stake),
            proven=g("VALI_SELECT_W_PROVEN", cls.proven),
        )


@dataclass(frozen=True)
class Candidate:
    """An eligible miner + the signals the ranking sorts on.

    `quality`/`free_slots` are the original §23 signals; the rest carry
    the composite inputs (all defaulted, so a miner with only the core
    facts known still constructs — and the function degrades gracefully
    to load-balance + grace until the chain reader exposes stake/price).
    """

    node_id: str
    quality: int
    free_slots: int
    capacity: int = 1
    load: int = 0
    is_newcomer: bool = False
    price: int | None = None
    stake_term: float = 0.0
    # How many ACTIVE placements of the requesting family this host already
    # carries. 0 is the spread-preserving case; higher values are allowed
    # but ranked down — see `_score` and the anti-affinity note in
    # `decide_placement`.
    family_load: int = 0
    # Skin-in-the-game: the miner has PROVEN itself (reward weight > 0) or
    # has POSITIVELY posted sufficient stake. Gates the price term — an
    # unproven, un-staked newcomer gets NO price advantage, so it cannot
    # win placements purely by undercutting (anti-Sybil-undercut).
    has_skin: bool = False
    # vali has OBSERVED a confidential guest start on this host recently
    # (`cvm_capability.PROVEN`). Defaults False so a caller that does not
    # supply the ledger ranks exactly as before — absence of evidence is
    # scored as absence of evidence, never as evidence.
    cvm_proven: bool = False
    # Capacity v2 load-balance term (0..1), set only when resource
    # admission is ENFORCED; `None` ⇒ the v1 `free_slots / capacity` ratio.
    free_fraction: float | None = None


def _score(
    c: Candidate, *, max_quality: int, max_price: int, weights: SelectionWeights
) -> float:
    """The composite selection score (higher = better). Pure."""
    # Newcomer grace: an unproven miner (no reward weight yet) gets a
    # bootstrap boost so it can win its first placements and start
    # earning real weight — this is what breaks the cold-start spiral.
    grace = 1.0 if c.is_newcomer else 0.0
    # Anti-affinity as a gradient, not a wall. A host already carrying N
    # VMs of this family scores N × `spread` lower, so placement fills the
    # empty hosts first and only doubles up when nothing empty is left.
    #
    # This USED to be a hard exclude (`if node in family_miners: continue`),
    # which silently capped a tenant at ONE VM PER MINER: three miners meant
    # three concurrent VMs, and 500 VMs would have meant 500 miners. The
    # intent — spread a tenant's VMs so one dead host cannot take them all —
    # is preserved here, and the hard bound now lives in
    # `max_family_per_node`, which is a capacity decision rather than an
    # accident of the ranking.
    spread_penalty = c.family_load * weights.spread
    # Free-capacity ratio (0..1): emptier miners preferred (load-balance);
    # a near-full high-merit miner naturally stops winning.
    if c.free_fraction is not None:
        free = c.free_fraction
    else:
        free = (c.free_slots / c.capacity) if c.capacity > 0 else 0.0
    # Merit: normalized reward weight (0..1). Bounded by `weights.merit`
    # so it breaks ties among trusted miners but never starves newcomers.
    merit = (c.quality / max_quality) if max_quality > 0 else 0.0
    # Price: cheaper is better, normalized across the candidate set. GATED
    # on skin-in-the-game — a miner with no proven merit and no posted
    # stake gets ZERO price credit, so undercutting alone never wins a
    # placement (it must first EARN reputation, then price breaks ties).
    # Only contributes once miners actually publish prices.
    if c.price is not None and max_price > 0 and c.has_skin:
        price = 1.0 - (c.price / max_price)
    else:
        price = 0.0
    # Stake: skin-in-the-game, 0..1. Present once the reader exposes it.
    stake = c.stake_term
    # Observed SNP start capability. This is the SOFT half of gate (e):
    # `INCAPABLE` was already dropped from the candidate set, so what is
    # left here is "recently seen to boot a CVM" vs "never seen to". The
    # bonus is what keeps UNKNOWN from silently meaning "assumed capable"
    # — an unproven host is admissible, but it never outranks an
    # otherwise-equal host that has actually demonstrated the thing.
    proven = 1.0 if c.cvm_proven else 0.0
    return (
        weights.grace * grace
        + weights.free * free
        + weights.merit * merit
        + weights.price * price
        + weights.stake * stake
        + weights.proven * proven
        - spread_penalty
    )


def decide_placement(
    *,
    snapshot: ChainSnapshot,
    capacity_by_node: dict[str, int],
    load_by_node: dict[str, int],
    family_load_by_node: dict[str, int],
    max_epoch_lag: int,
    max_family_per_node: int | None = None,
    excluded: frozenset[str] = frozenset(),
    dispatchable: frozenset[str] | None = None,
    weights: SelectionWeights | None = None,
    max_host_share: float = 1.0,
    stake_sufficient_by_node: dict[str, bool] | None = None,
    price_by_node: dict[str, int] | None = None,
    recent_failures_by_node: dict[str, int] | None = None,
    max_recent_failures: int = 0,
    owner_load_by_node: dict[str, int] | None = None,
    max_owner_placements_per_miner: int = 0,
    cvm_capability_by_node: dict[str, str] | None = None,
    region: str = "",
    region_by_node: Mapping[str, str] | None = None,
    pinned: frozenset[str] | None = None,
    zombie_quarantined: frozenset[str] | None = None,
    resource_fit: ResourceFit | None = None,
    booting_by_node: Mapping[str, int] | None = None,
    max_booting_per_node: int = 0,
    max_booting_by_node: Mapping[str, int] | None = None,
    cordoned: Mapping[str, str] | None = None,
) -> str:
    """Return the `node_id` of the miner the VM should be placed on.

    Core arguments (the original §23 inputs):

    - `snapshot`         the authoritative on-chain read. Its
                         `pallet_live` field decides whether the miners'
                         `quality` is merit or a fossil (see the fossil
                         guard below); `False` neutralises the merit and
                         price terms fleet-wide.
    - `capacity_by_node` `{node_id: capacity_slots}` (MinerCapacity).
    - `load_by_node`     `{node_id: active placement count}`.
    - `family_load_by_node` `{node_id: active placements of THIS family}`.
    - `max_family_per_node` hard ceiling per host, or `None` for no cap
                         (the ranking still spreads).
    - `max_epoch_lag`    stale-epoch threshold.
    - `excluded`         miners to skip outright (re-placement).
    - `dispatchable`     when not `None`, the set of node_ids vali can
                         actually reach + attest (complete + fresh local
                         `MinerIdentity`); any candidate outside it is
                         dropped. `None` disables the gate (legacy/tests).

    Composite-selection arguments (defaulted → inert; wired from
    settings/chain at the boundary):

    - `weights`          composite score weights (None ⇒ defaults).
    - `max_host_share`   concentration cap: a miner already hosting
                         `≥ max_host_share` of all active placements is
                         deprioritised (soft — never fails a placement).
                         `1.0` ⇒ no cap.
    - `stake_sufficient_by_node`  `{node_id: bool}`; a `False` excludes
                         the miner from new placements (default: assume
                         sufficient until the reader exposes stake).
    - `price_by_node`    `{node_id: price}` for the price term.
    - `recent_failures_by_node`  `{node_id: recent launch-failure count}`
                         for the soft circuit-breaker.
    - `max_recent_failures`  a miner with `≥` this many recent launch
                         failures is routed around (soft — never fails a
                         placement). `0` ⇒ disabled.
    - `owner_load_by_node`  `{node_id: count of THIS owner's active
                         placements}` — the per-owner sub-budget input
                         (audit M-per-tenant-cap).
    - `max_owner_placements_per_miner`  a miner where this owner already
                         holds `≥` this many placements is deprioritised
                         (soft — never fails a placement; falls back to the
                         full set if the cap would leave nobody, so an
                         owner is SPREAD across miners by default but is
                         never blocked when the fleet is full). `0` ⇒
                         disabled.
    - `cvm_capability_by_node`  `{node_id: proven|degraded|incapable|
                         unknown}` from
                         `cvm_capability.capability_by_node()` — the
                         OBSERVED SEV-SNP start-capability ledger. Three
                         effects, in decreasing severity:
                           `"incapable"` (a STREAK of observed start
                             failures) is HARD-excluded with no fallback:
                             for a §25 migration, picking it quiesces and
                             fences the source for nothing, which is
                             strictly worse than "no destination";
                           `"degraded"` (ONE recent observed failure,
                             the intermittent case) is de-prioritised
                             SOFTLY, with a fallback to the full set;
                           `"proven"` gets the `weights.proven` bonus.
                         Anything else — an explicit `"unknown"`, or a
                         node absent from the map — is eligible but
                         unproven: NOT excluded (that would empty a fresh
                         fleet and be self-sealing, since capability is
                         only provable by being placed) and NOT assumed
                         capable (it earns no bonus). `None` ⇒ no gate,
                         no de-rate, no bonus (legacy/tests).
    - `region`           gate (f): an ISO 3166-1 alpha-2 country code the
                         VM must land in (case-insensitive; `""` ⇒ no
                         gate, which is every legacy caller). HARD, no
                         fallback: a tenant who asked for `FR` is never
                         silently placed in `DE`.
    - `region_by_node`   `{node_id: country_code}` from
                         `service.region_by_node()` — the regions the
                         geo-probe has MEASURED (verified only, by
                         default). Fail-closed: a node ABSENT from the map
                         is in NO region, so a fleet the probe has not
                         reached yet places nothing under a region
                         constraint rather than placing anywhere. `None`
                         with a non-empty `region` is that same empty map.

    - `pinned`           when not `None`, the ONLY node_ids the VM may land
                         on — the miner(s) whose registered `platform_id`
                         the launch named (`service.pin_arguments`). HARD,
                         no fallback: the launch ticket binds the VCEK of
                         that chip, and vali's launch-digest recompute
                         (C2) uses its CPU family, so any other host fails
                         late. An empty set places nothing. `None` ⇒ no pin.

    - `zombie_quarantined`  lower-case node_ids currently relaying frames
                         from a VM whose §24 crypto-erase already ran
                         (`apps.lifecycle.zombie.quarantined_node_ids`):
                         the miner is still running a VM it was told to
                         kill. HARD, no fallback — derived from FRESH
                         signals only, so it lifts on its own once the
                         frames stop or the destroy is confirmed. `None` ⇒
                         no gate.

    - `resource_fit`     capacity v2 (see [`ResourceFit`]). `None` ⇒ v1
                         only (legacy/tests). Enforced ⇒ gate (a) asks
                         "does THIS flavor fit in vCPU, RAM and VM count",
                         not "is a slot free".

    - `booting_by_node`  gate (g): `{node_id: guests booting there now}`
                         (`service.booting_by_node`).
    - `max_booting_per_node`  a miner with `≥` this many booting guests is
                         skipped. HARD, no fallback — the point is to stop
                         a burst from booting on one host at once. `0` ⇒
                         no gate (every caller but the launch path).
    - `max_booting_by_node`  per-node override of `max_booting_per_node`
                         (`MinerCapacity.max_booting`); a node in it is
                         capped at its own value even when the fleet value
                         is `0`. Only read alongside `booting_by_node`.
    - `cordoned`         gate (h): `{lower-case node_id: reason}` of the
                         operator-cordoned miners
                         (`service.cordoned_node_ids`). HARD, no fallback.
                         `None` ⇒ no gate.

    Raises [`PlacementError`]: `miners-booting` when gate (g) removed every
    candidate that passed all the others (retry shortly);
    `no-miner-in-region` when candidates reached gate (f) and it removed
    every one of them (the fleet is reachable, just not there); otherwise
    `no-eligible-miner`.
    """
    weights = weights or SelectionWeights()
    stake_ok = stake_sufficient_by_node or {}
    prices = price_by_node or {}
    cvm_capability = cvm_capability_by_node or {}
    region = region.strip().upper()
    regions = region_by_node or {}

    # ── Is the reward signal ALIVE? (fossil guard) ───────────────────
    # A runtime upgrade that DROPS `pallet-compute-scoring` does not
    # delete its storage, and the reader derives its keys from the
    # pallet NAME over raw storage — so the orphaned prefix keeps
    # answering with the pallet's LAST-WRITTEN bytes forever and every
    # read looks healthy. `ChainSnapshot.pallet_live` is the only field
    # that can tell the difference (see `chain.read_miner_status`).
    #
    # When it is False, `miner.quality` is NOT merit. It is a photograph
    # of who happened to be ahead at the final epoch close: it can never
    # change again (no close can run), and hosting performed since the
    # freeze earns nothing — so the ranking it induces drifts away from
    # reality monotonically and never self-heals. Measured on testnet
    # 2026-08-11, the fossil is already INVERTED: the miner hosting the
    # only real tenant reads quality=0, while the miner whose entire
    # history is the validator's own synthetic probes reads
    # quality=100170 (the figure frozen at the 2026-08-03 close).
    #
    # `getattr(..., True)` is the same version-skew safety
    # `chain._coerce_snapshot` applies: an older reader emits no such
    # field, and a skew must never change today's behaviour.
    merit_is_live = bool(getattr(snapshot, "pallet_live", True))

    eligible: list[Candidate] = []
    # gate (a) verdicts per node, v1 vs v2 — the shadow run's evidence.
    shadow: dict[str, tuple[bool, bool]] = {}
    # How many candidates gate (e) removed. Reported in the
    # `no-eligible-miner` message: a fleet that is empty BECAUSE every
    # host has been observed failing to start a confidential guest looks
    # identical, from the error string alone, to a fleet that is out of
    # capacity or epoch-stale — and those call for opposite responses.
    cvm_incapable_skipped = 0
    # How many candidates reached gate (f), and how many it removed. The
    # two together decide the error category: `no-miner-in-region` is
    # claimed ONLY when the region gate is what emptied the set, so a
    # caller never retries a region that was never the problem.
    region_seen = 0
    region_skipped = 0
    zombie_skipped = 0
    disk_skipped = 0
    booting = booting_by_node or {}
    # Gate (g)'s removals, `{node_id: booting count}` — logged, and named
    # in the `miners-booting` error.
    booting_skipped: dict[str, int] = {}
    booting_caps = max_booting_by_node or {}
    # Gate (h)'s removals, `{node_id: reason}` — logged and counted.
    cordon_skipped: dict[str, str] = {}
    for miner in snapshot.miners:
        if miner.node_id in excluded:
            continue
        if zombie_quarantined and miner.node_id.lower() in zombie_quarantined:
            zombie_skipped += 1
            continue
        # (h) operator cordon — no new work, whoever asks.
        if cordoned and miner.node_id.lower() in cordoned:
            cordon_skipped[miner.node_id] = cordoned[miner.node_id.lower()]
            continue
        if pinned is not None and miner.node_id not in pinned:
            continue
        # Defense-in-depth liveness/completeness gate. The chain's `Active`
        # set is authoritative, but on mainnet it is kept honest by the §23
        # attested keepalive while on testnet that enforcement is absent —
        # so an on-chain `Active` node can be a phantom (no local identity),
        # unreachable (no NetBird IP), un-attestable (placeholder CHIP_ID),
        # or dark (stopped heart-beating). When the caller supplies the set
        # of genuinely dispatchable node_ids (a complete + fresh local
        # `MinerIdentity` — see `service.dispatchable_node_ids`), a node
        # outside it is never a candidate. `None` ⇒ no gate (legacy/tests).
        # This makes placement behave identically on testnet and mainnet:
        # vali never dispatches to a miner it cannot actually reach + attest.
        if dispatchable is not None and miner.node_id not in dispatchable:
            continue
        # (f) detected region — HARD, fail-closed. Placed right after the
        # dispatchability gate so `region_seen` counts miners vali could
        # actually launch onto: "no miner in region" must mean the
        # reachable fleet has none there, not that the fleet is dark.
        # `regions.get(...) != region` deliberately treats an absent node
        # like a mismatched one — the map holds what the probe MEASURED
        # (and verified), and a miner it has not measured has no region.
        if region:
            region_seen += 1
            if regions.get(miner.node_id) != region:
                region_skipped += 1
                continue
        # Only on-chain Active miners are ever schedulable (§23).
        if miner.status != MINER_ACTIVE:
            continue
        # (c) fail-closed on stale epoch.
        if snapshot.current_epoch - miner.data_epoch > max_epoch_lag:
            continue
        # (b) anti-affinity — a CAP, not a wall.
        #
        # Was `if node in family_miners: continue`, a hard exclude that
        # silently capped a tenant at one VM per miner: three miners meant
        # three concurrent VMs, and 500 VMs would have needed 500 miners.
        # Spreading is still what we want, so it now lives in the RANKING
        # (`weights.spread`), which fills empty hosts first and doubles up
        # only when nothing empty is left. What remains here is a real
        # ceiling an operator can reason about.
        fam_load = family_load_by_node.get(miner.node_id, 0)
        if max_family_per_node is not None and fam_load >= max_family_per_node:
            continue
        # (d) stake sufficiency — a deficient miner takes no new VMs.
        if not stake_ok.get(miner.node_id, True):
            continue
        # (e) OBSERVED SNP start capability — fail closed on a host vali
        # has REPEATEDLY watched fail to start a confidential guest.
        # Gates (a)–(d) all ask "how much can this host take?", and every
        # one of them answers "plenty" for a host that currently cannot
        # boot a CVM — its CPU and RAM read entirely free precisely
        # BECAUSE it is booting nothing. Only an observation of a start
        # can distinguish those two.
        #
        # This is the HARD half, and it is reached ONLY from a STREAK
        # (`cvm_capability.INCAPABLE` = N consecutive in-window failures
        # with no success in between). A SINGLE failure lands on
        # `DEGRADED` and is handled softly below, because the underlying
        # `sev_common_kvm_init … EBUSY` is measurably intermittent and
        # self-recovering: excluding on one would pull healthy hosts out
        # of the fleet for a fault they clear unaided. Note the
        # value-equality check — an UNKNOWN, DEGRADED or absent node
        # falls through here and stays ELIGIBLE.
        if cvm_capability.get(miner.node_id) == _CVM_INCAPABLE:
            cvm_incapable_skipped += 1
            continue
        # (a') the DATA-disk dimension — under either admission model, and
        # ahead of (a) so a disk refusal is counted as one (v2's own fit
        # also includes disk while the gate is enforced). Enforced, a flavor
        # whose disk does not fit is refused here instead of by the miner
        # (507 `insufficient-disk`) after vali committed to the host.
        if (
            resource_fit is not None
            and resource_fit.disk_mode == "enforce"
            and resource_fit.disk_refusal_by_node.get(miner.node_id, "")
        ):
            disk_skipped += 1
            continue
        # (a) admission bounded by proven capacity.
        capacity = capacity_by_node.get(miner.node_id)
        load = load_by_node.get(miner.node_id, 0)
        free_slots = (capacity - load) if capacity is not None else 0
        v1_ok = capacity is not None and free_slots > 0
        v2_ok = resource_fit is not None and resource_fit.fits_by_node.get(miner.node_id, False)
        if resource_fit is not None:
            shadow[miner.node_id] = (v1_ok, v2_ok)
        if resource_fit is not None and resource_fit.enforce:
            # v2: the flavor must fit. A node vali has no budget for is
            # absent from the map ⇒ refused (fail closed).
            if not v2_ok:
                continue
        elif not v1_ok:
            # v1: no mirror row ⇒ unknown capacity ⇒ fail closed; else a
            # free slot is required.
            continue
        # (g) concurrent boots — LAST, so a node counted here passed every
        # other gate: when this empties the set, waiting is the answer.
        n_booting = booting.get(miner.node_id, 0)
        boot_cap = booting_caps.get(miner.node_id, max_booting_per_node)
        if (miner.node_id in booting_caps or boot_cap > 0) and n_booting >= boot_cap:
            booting_skipped[miner.node_id] = n_booting
            continue

        # Merit under a dead pallet: ZERO, uniformly. There is no live
        # reward signal, so no miner may convert a frozen number into an
        # advantage — in EITHER direction. Zeroing (rather than keeping a
        # shared non-zero constant) is the same total order — a constant
        # merit term cancels out of the ranking — but it refuses to hand
        # out reputation nobody can currently earn, and it keeps the
        # `Candidate` honest: quality 0 means "unproven", which is exactly
        # true of every miner while the chain cannot score anyone.
        quality = miner.quality if merit_is_live else 0
        eligible.append(
            Candidate(
                node_id=miner.node_id,
                quality=quality,
                free_slots=free_slots,
                capacity=capacity if capacity is not None else 0,
                load=load,
                # Unproven (no reward weight yet) ⇒ newcomer grace. Under
                # a dead pallet this is true of EVERYONE, so grace becomes
                # a constant added to every score and stops discriminating
                # — the cold-start boost has nothing to bootstrap against
                # when nobody can earn weight. That is the correct
                # degenerate case, not a bug: the term is kept (truthful —
                # no miner is proven) and simply cancels out, leaving free
                # capacity + node_id to decide.
                is_newcomer=quality <= 0,
                price=prices.get(miner.node_id),
                family_load=fam_load,
                stake_term=0.0,
                # Skin-in-the-game gate for the price term: proven merit
                # (quality>0) OR an EXPLICIT stake-sufficient flag. Note the
                # `is True` — the exclusion gate above defaults unknown
                # stake to "sufficient" (don't exclude), but a price BONUS
                # must never rest on assumed stake, only on a positive
                # signal. Until a stake reader exists this is purely
                # quality>0, which is exactly the anti-undercut property.
                #
                # A dead pallet fails that gate for EVERY miner: merit is
                # a fossil, and stake lives on the same dead pallet, so
                # neither can be verified. `stake_ok` cannot rescue it —
                # the rule above (an ASSUMED signal never buys a price
                # bonus) applies with more force to an UNVERIFIABLE one.
                # Cost, stated plainly: while the pallet is dead the price
                # term is inert fleet-wide, so cheaper bids do not rank up
                # and the marketplace stops rewarding price. That costs
                # almost nothing real — `service.price_by_node` reads the
                # prices out of this same fossil snapshot, so they are
                # frozen too — and it preserves the property that actually
                # matters: nobody wins a placement by undercutting alone.
                has_skin=(
                    merit_is_live
                    and (miner.quality > 0 or stake_ok.get(miner.node_id) is True)
                ),
                # `is` the PROVEN literal, not "not incapable": the bonus
                # must rest on a POSITIVE observation. Unknown gets zero.
                cvm_proven=cvm_capability.get(miner.node_id) == _CVM_PROVEN,
                free_fraction=(
                    resource_fit.free_fraction_by_node.get(miner.node_id, 0.0)
                    if resource_fit is not None and resource_fit.enforce
                    else None
                ),
            )
        )

    if cordon_skipped:
        log.info(
            "cordon: skipped %s",
            ", ".join(
                f"{nid} ({why or 'no reason'})" for nid, why in sorted(cordon_skipped.items())
            ),
        )
    booted = ", ".join(
        f"{nid}={n}/{booting_caps.get(nid, max_booting_per_node)}"
        for nid, n in sorted(booting_skipped.items())
    )
    if booting_skipped:
        log.info("boot cap: skipped %s (booting/cap)", booted)
    if not eligible:
        _log_shadow(resource_fit, shadow, chosen=None)
        if booting_skipped:
            raise PlacementError(
                "every eligible miner is already at its concurrent-boot cap "
                f"(booting/cap: {booted}); retry once one of them is up",
                MINERS_BOOTING,
            )
        cvm_note = (
            f" ({cvm_incapable_skipped} candidate(s) removed by the OBSERVED "
            "SNP-start-capability gate: vali watched them fail to start a "
            "confidential guest — see MinerCapacity.cvm_* / "
            "GET /v1/scheduler/capacity)"
            if cvm_incapable_skipped
            else ""
        )
        if region and region_seen and region_skipped == region_seen:
            # Every reachable candidate was removed BY the region gate:
            # the fleet is fine, it is simply not where the tenant asked.
            raise PlacementError(
                f"no dispatchable miner is detected in region {region!r} "
                f"({region_skipped} reachable candidate(s) are elsewhere or "
                "not yet verified there — see GET /v1/operator/regions)",
                "no-miner-in-region",
            )
        region_note = (
            f" (constrained to region {region!r}: {region_skipped} of "
            f"{region_seen} reachable candidate(s) removed by the region gate)"
            if region
            else ""
        )
        zombie_note = (
            f" ({zombie_skipped} candidate(s) zombie-quarantined: still running "
            "a VM whose §24 crypto-erase already ran)"
            if zombie_skipped
            else ""
        )
        pin_note = (
            " (pinned by platform_id to "
            f"{len(pinned)} registered miner(s), none of them placeable now)"
            if pinned is not None
            else ""
        )
        disk_note = (
            f" ({disk_skipped} candidate(s) removed by the data-disk gate: "
            f"no room for {resource_fit.disk_gb if resource_fit else 0} GiB)"
            if disk_skipped
            else ""
        )
        cordon_note = (
            f" ({len(cordon_skipped)} candidate(s) cordoned by the operator)"
            if cordon_skipped
            else ""
        )
        raise PlacementError(
            "no miner satisfies the §23 dispatchability (reachable + "
            "attestable + live) / admission / anti-affinity / "
            "epoch-freshness / stake / observed-SNP-start-capability "
            f"constraints{cvm_note}{region_note}{pin_note}{zombie_note}{disk_note}"
            f"{cordon_note}",
            "no-eligible-miner",
        )

    # Circuit-breaker (soft): a miner with too many RECENT launch failures
    # is likely broken (down, vsock-CID-wedged, out of disk, …) — route
    # around it so a launch-job retry does not keep hammering a dead miner
    # (a launch that dispatch-fails after the KBS register can't re-place,
    # so hammering a broken miner wastes the whole job). Soft: fall back to
    # the full set if this would leave nobody — a shaky miner still beats
    # no placement. Ordered BEFORE the concentration cap so a broken miner
    # is avoided even when it is under the host-share cap.
    failures = recent_failures_by_node or {}
    if max_recent_failures > 0:
        healthy = [
            c for c in eligible if failures.get(c.node_id, 0) < max_recent_failures
        ]
        if healthy:
            eligible = healthy

    # Observed-capability de-rate (soft) — the SOFT half of gate (e). A
    # host with a RECENT observed CVM-start failure that has not yet
    # become a streak is `DEGRADED`: prefer anyone else, but never fail a
    # placement for it (fall back to the full set if this leaves nobody).
    #
    # Soft is the whole point. The failure this models is intermittent and
    # self-recovering — measured on the live fleet as isolated events with
    # a successful start on the very next attempt — so a hard exclusion
    # would repeatedly remove healthy hosts for a fault they clear
    # themselves. Preference costs nothing when an alternative exists and
    # costs nothing when it does not; it simply stops us walking straight
    # back onto the host that just failed. The penalty decays on its own
    # (see `cvm_capability.fail_window_s`) and is cleared instantly by the
    # next observed success.
    degraded_free = [
        c for c in eligible if cvm_capability.get(c.node_id) != _CVM_DEGRADED
    ]
    if degraded_free:
        eligible = degraded_free

    # Concentration cap (soft): prefer miners under the host-share cap so
    # no single miner accumulates a large correlated blast radius — but
    # NEVER fail a placement for it; fall back to the full set if the cap
    # would leave nobody. Only meaningful once enough VMs exist.
    total_active = sum(load_by_node.values())
    if total_active > 0 and max_host_share < 1.0:
        capped = [c for c in eligible if c.load < max_host_share * total_active]
        if capped:
            eligible = capped

    # Per-owner sub-budget (soft, audit M-per-tenant-cap): prefer miners
    # where THIS owner is under its per-miner cap, so one owner's VMs
    # spread across miners (bounded noisy-neighbour + correlated blast
    # radius) instead of piling onto one — but NEVER fail a placement for
    # it; fall back to the full set if the cap would leave nobody (a full
    # fleet still beats no placement — the host-aggregate `capacity_slots`
    # remains the hard admission bound).
    owner_load = owner_load_by_node or {}
    if max_owner_placements_per_miner > 0 and owner_load:
        under_cap = [
            c
            for c in eligible
            if owner_load.get(c.node_id, 0) < max_owner_placements_per_miner
        ]
        if under_cap:
            eligible = under_cap

    max_quality = max((c.quality for c in eligible), default=0)
    max_price = max((c.price for c in eligible if c.price is not None), default=0)

    # Deterministic ranking — a TOTAL order, no ties left to chance:
    #   1. highest composite score,
    #   2. then lowest node_id (final, stable tie-break).
    # No randomness, no clock — identical inputs ⇒ identical output.
    scores = {
        c.node_id: _score(
            c, max_quality=max_quality, max_price=max_price, weights=weights
        )
        for c in eligible
    }
    eligible.sort(key=lambda c: (-scores[c.node_id], c.node_id))
    _log_shadow(resource_fit, shadow, chosen=eligible[0].node_id)
    _log_disk_record(resource_fit, chosen=eligible[0].node_id)
    return eligible[0].node_id


def _log_disk_record(resource_fit: ResourceFit | None, *, chosen: str) -> None:
    """`record` mode: the chosen node is one `enforce` would have refused
    on disk — log it (structured, stable event name) and admit anyway."""
    if resource_fit is None or resource_fit.disk_mode != "record" or not resource_fit.shadow_log:
        return
    reason = resource_fit.disk_refusal_by_node.get(chosen, "")
    if reason:
        log_disk_would_reject(
            node_id=chosen,
            resource_class=resource_fit.resource_class,
            disk_gb=resource_fit.disk_gb,
            reason=reason,
            context="placement",
        )


def log_disk_would_reject(
    *, node_id: str, resource_class: str, disk_gb: int, reason: str, context: str
) -> None:
    """The `record`-mode evidence: one structured WARNING per decision
    `enforce` would have refused, under the stable event name
    `disk_gate_would_reject` (count it in the log pipeline — the same
    log-derived shape the capacity-v2 shadow run was judged by)."""
    log.warning(
        "disk-gate: %s",
        json.dumps(
            {
                "event": "disk_gate_would_reject",
                "mode": "record",
                "node_id": node_id,
                "resource_class": resource_class,
                "disk_gb": disk_gb,
                "reason": reason,
                "context": context,
            },
            sort_keys=True,
        ),
    )


def _log_shadow(
    resource_fit: ResourceFit | None,
    shadow: Mapping[str, tuple[bool, bool]],
    *,
    chosen: str | None,
) -> None:
    """One INFO line per decision while v2 runs in shadow: what gate (a)
    said under v1 and under v2 for every node that reached it, and the
    choice. Silent when v2 is enforced (it decided) or not supplied."""
    if resource_fit is None or resource_fit.enforce or not resource_fit.shadow_log:
        return
    disagree = sorted(nid for nid, (v1, v2) in shadow.items() if v1 != v2)
    log.info(
        "capacity-v2 shadow: %s",
        json.dumps(
            {
                "resource_class": resource_fit.resource_class,
                "chosen": chosen,
                "chosen_fits_v2": (
                    None if chosen is None else resource_fit.fits_by_node.get(chosen, False)
                ),
                "v1_admits": sorted(nid for nid, (v1, _) in shadow.items() if v1),
                "v2_admits": sorted(nid for nid, (_, v2) in shadow.items() if v2),
                "disagree": disagree,
            },
            sort_keys=True,
        ),
    )
