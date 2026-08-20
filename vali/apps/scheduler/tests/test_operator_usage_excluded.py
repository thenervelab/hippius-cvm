"""Operator-owned VMs earn NO reward weight and NO bill.

With `VALI_EPOCH_WEIGHT_SOURCE=usage` the `UsageAccrual` ledger IS the
on-chain reward weight. Measured live on 2026-08-11 (chain epoch 2702),
OUR OWN VMs held 30.6 % of the entire pot — 404,343,360 of 1,322,247,180
unit_seconds — and a single synthetic-monitor probe that had not existed
for five days (`synmon-debian-1785751760`) carried 30 % of it alone,
because a suspended closer never rolls the bucket over. Every unit we
hold is diluted straight out of an honest miner's reward.

The discriminator is `Placement.owner` (the launch spec's `user_id`),
configured via `VALI_REWARD_EXCLUDED_OWNERS`. These tests pin the
properties that make that safe:

  - an operator-owned VM contributes ZERO;
  - a tenant VM is untouched, to the unit;
  - the three live operator shapes are ALL covered, not just `synmon-`;
  - an empty excluded set is a strict no-op (the default can never
    silently zero a real fleet);
  - the set comes from SETTINGS, not from a hardcoded name or a lease
    prefix;
  - the ledger rows survive — the exclusion is at read time.
"""

from __future__ import annotations

import pytest
import yaml
from django.test import override_settings

from apps.scheduler import scoring
from apps.scheduler.models import PlacementStatus, UsageAccrual

from .factories import make_placement, make_vm, node_id, observe_chain_epoch
from .test_uptime_liveness_chart import CONFIGMAP_TPL, REPO_ROOT, VALUES

pytestmark = pytest.mark.django_db

SETTINGS_PY = REPO_ROOT / "vali" / "vali" / "settings.py"


# The two identities the live fleet actually uses. `synthetic-monitor` is
# `VALI_SYNTHETIC_TENANT_ID`; `kbsrehearse` is a one-off operator harness.
SYNTH = "synthetic-monitor"
REHEARSE = "kbsrehearse"

# The regime under test: usage-sourced weights, with the live excluded set.
_LIVE = override_settings(
    VALI_EPOCH_WEIGHT_SOURCE="usage",
    VALI_SYNTHETIC_TENANT_ID=SYNTH,
    VALI_REWARD_EXCLUDED_OWNERS=[REHEARSE],
)


def _own(
    vm_id: str,
    node: str,
    *,
    owner: str,
    epoch: int,
    unit_seconds: int,
    lease_id: str = "",
    status: str = PlacementStatus.BOUND.value,
) -> None:
    """A VM owned by `owner`, placed on `node`, with an accrual row —
    exactly the shape the live ledger has."""
    vm = make_vm(vm_id=vm_id, lease_id=lease_id or f"{vm_id}-lease")
    make_placement(vm, node, status=status, owner=owner, resource_class="small")
    UsageAccrual.objects.create(
        epoch=epoch,
        miner_node_id=node,
        vm_id=vm_id,
        resource_class="small",
        lease_id=lease_id or f"{vm_id}-lease",
        unit_seconds=unit_seconds,
        billable_seconds=unit_seconds,
    )


# ─── the core claims ─────────────────────────────────────────────────


@_LIVE
def test_an_operator_owned_vm_contributes_zero_weight() -> None:
    """CLAIM: our own VM moves not one unit of the pot.

    Zero, not "less" — a miner hosting only operator VMs drops out of the
    weights entirely (weight 0 ⇒ absent, matching the drop-zeros contract
    the rest of `compute_epoch_weights` already keeps).
    """
    observe_chain_epoch(2702)
    _own("synmon-debian-1785751760", node_id(1), owner=SYNTH, epoch=2702,
         unit_seconds=400_974_150, lease_id="synmon-synmon-debian-1785751760")

    assert scoring.compute_epoch_weights() == {}


@_LIVE
def test_a_tenant_vm_is_unaffected_to_the_unit() -> None:
    """CLAIM: the filter takes nothing from a real tenant.

    The live tenant row, verbatim: 917,329,830 unit_seconds on
    `0123456789ab`, owner `<OPERATOR>`. It must survive byte-identical.
    """
    observe_chain_epoch(2702)
    _own("realtenant-ubuntu-1", node_id(7), owner="operator-1", epoch=2702,
         unit_seconds=917_329_830, lease_id="realtenant-ubuntu-1-lease")

    assert scoring.compute_epoch_weights() == {node_id(7): 917_329_830}


@_LIVE
def test_all_three_live_operator_shapes_are_covered_not_just_synmon() -> None:
    """CLAIM: `synmon-` is not the whole of "ours".

    The epoch-2702 ledger holds THREE operator lease shapes — `synmon-*`
    (31 rows, owner `synthetic-monitor`), `kbsrehearse-1` (owner
    `kbsrehearse`) and `stampproof-1-lease` (owner `synthetic-monitor`).
    A `synmon-` prefix filter would have left 6,681,180 units of our own
    usage in the pot AND kept the probe's host miner paid; owner-keying
    zeroes all three.
    """
    observe_chain_epoch(2702)
    ours = node_id(2)
    _own("synmon-debian-1785751760", ours, owner=SYNTH, epoch=2702,
         unit_seconds=400_974_150, lease_id="synmon-synmon-debian-1785751760")
    _own("kbsrehearse-vm", ours, owner=REHEARSE, epoch=2702,
         unit_seconds=4_580_790, lease_id="kbsrehearse-1")
    _own("stampproof-vm", ours, owner=SYNTH, epoch=2702,
         unit_seconds=2_100_390, lease_id="stampproof-1-lease")

    assert scoring.compute_epoch_weights() == {}


@_LIVE
def test_the_live_pot_recomputed_leaves_only_the_tenant() -> None:
    """CLAIM: end-to-end on the live numbers — the whole point of the fix.

    Three miners, epoch 2702, as measured. Before: 1,322,247,180 total of
    which 30.6 % is ours. After: the tenant's miner keeps its exact
    weight and the two operator-only miners vanish.
    """
    observe_chain_epoch(2702)
    tenant, mixed, probes = node_id(0x2826), node_id(0x3F6E), node_id(0xE050)

    _own("realtenant-ubuntu-1", tenant, owner="operator-1", epoch=2702,
         unit_seconds=911_222_640, lease_id="realtenant-ubuntu-1-lease")
    _own("synmon-mixed", mixed, owner=SYNTH, epoch=2702,
         unit_seconds=403_764_600, lease_id="synmon-synmon-debian-1785751760")
    _own("kbsrehearse-vm", mixed, owner=REHEARSE, epoch=2702,
         unit_seconds=4_580_790, lease_id="kbsrehearse-1")
    _own("stampproof-vm", mixed, owner=SYNTH, epoch=2702,
         unit_seconds=2_100_390, lease_id="stampproof-1-lease")
    _own("synmon-fedora", probes, owner=SYNTH, epoch=2702, unit_seconds=578_760)

    weights = scoring.compute_epoch_weights()
    assert weights == {tenant: 911_222_640}
    assert sum(weights.values()) == 911_222_640


# ─── the default must never zero a real fleet ────────────────────────


@override_settings(
    VALI_EPOCH_WEIGHT_SOURCE="usage",
    VALI_SYNTHETIC_TENANT_ID="",
    VALI_REWARD_EXCLUDED_OWNERS=[],
)
def test_an_empty_excluded_set_changes_nothing() -> None:
    """CLAIM: with nothing configured, the weights are exactly the
    pre-fix ones.

    This is the blast-radius bound. A filter whose EMPTY case dropped
    rows — an inverted predicate, a blank owner sneaking into the set —
    would zero an entire honest fleet at the first deploy. Every row
    below is one an unconfigured vali must still pay.
    """
    observe_chain_epoch(2702)
    _own("synmon-debian", node_id(1), owner=SYNTH, epoch=2702, unit_seconds=400_974_150)
    _own("kbsrehearse-vm", node_id(1), owner=REHEARSE, epoch=2702, unit_seconds=4_580_790)
    _own("tenant-vm", node_id(2), owner="operator-1", epoch=2702, unit_seconds=917_329_830)
    _own("legacy-vm", node_id(3), owner="", epoch=2702, unit_seconds=1_234)

    assert scoring.compute_epoch_weights() == {
        node_id(1): 405_554_940,
        node_id(2): 917_329_830,
        node_id(3): 1_234,
    }


@_LIVE
def test_a_blank_owner_is_never_excluded() -> None:
    """CLAIM: legacy rows keep earning.

    36 live placements carry `owner=""` (pre-#587 launches). An empty
    string reaching the excluded set — a stray `""` in the env list, or
    an unset `VALI_SYNTHETIC_TENANT_ID` being added blindly — would wipe
    every one of them.
    """
    observe_chain_epoch(2702)
    _own("legacy-vm", node_id(3), owner="", epoch=2702, unit_seconds=1_234)

    assert "" not in scoring._excluded_owners()
    assert scoring.compute_epoch_weights() == {node_id(3): 1_234}


@override_settings(
    VALI_EPOCH_WEIGHT_SOURCE="usage",
    VALI_SYNTHETIC_TENANT_ID="  ",
    VALI_REWARD_EXCLUDED_OWNERS=["", "   "],
)
def test_whitespace_only_configuration_excludes_nobody() -> None:
    """CLAIM: a blank-ish config is a no-op, not a fleet-wide zero.

    `VALI_REWARD_EXCLUDED_OWNERS=" "` is a plausible env-var typo. It
    must not become an owner that matches nothing — or, worse, survive
    into a `__in` clause alongside a strip() that never ran.
    """
    observe_chain_epoch(2702)
    _own("tenant-vm", node_id(2), owner="operator-1", epoch=2702, unit_seconds=500)

    assert scoring._excluded_owners() == frozenset()
    assert scoring.compute_epoch_weights() == {node_id(2): 500}


# ─── the set is CONFIGURATION, and the discriminator is OWNERSHIP ────


@override_settings(
    VALI_EPOCH_WEIGHT_SOURCE="usage",
    VALI_SYNTHETIC_TENANT_ID="",
    VALI_REWARD_EXCLUDED_OWNERS=["acme-ops"],
)
def test_the_excluded_set_comes_from_settings_not_a_literal() -> None:
    """CLAIM: an operator names the excluded identities; the code does
    not know any by heart.

    An owner nobody hardcoded (`acme-ops`) is excluded, and — with the
    synthetic tenant deliberately unset — `synthetic-monitor` is NOT.
    Kills every mutant that pattern-matches a baked-in "synmon" /
    "synthetic" string instead of reading the setting.
    """
    observe_chain_epoch(2702)
    _own("acme-vm", node_id(1), owner="acme-ops", epoch=2702, unit_seconds=999)
    _own("synmon-vm", node_id(2), owner=SYNTH, epoch=2702,
         unit_seconds=400, lease_id="synmon-synmon-debian-1")

    assert scoring._excluded_owners() == frozenset({"acme-ops"})
    assert scoring.compute_epoch_weights() == {node_id(2): 400}


@override_settings(
    VALI_EPOCH_WEIGHT_SOURCE="usage",
    VALI_SYNTHETIC_TENANT_ID=SYNTH,
    VALI_REWARD_EXCLUDED_OWNERS=[REHEARSE],
)
def test_the_synthetic_tenant_is_excluded_even_when_absent_from_the_list() -> None:
    """CLAIM: editing the list cannot re-open the 30 % skim.

    The chart's `rewardExcludedOwners` holds only `kbsrehearse`. If the
    synthetic tenant were merely another list entry, an operator adding a
    one-off identity and rewriting the list would silently put the probe
    fleet back in the pot. It is unioned in from
    `VALI_SYNTHETIC_TENANT_ID` instead — the same knob the synthetic
    reaper keys its "never touch a real tenant" invariant on.
    """
    assert scoring._excluded_owners() == frozenset({SYNTH, REHEARSE})

    observe_chain_epoch(2702)
    _own("synmon-vm", node_id(1), owner=SYNTH, epoch=2702, unit_seconds=400)
    assert scoring.compute_epoch_weights() == {}


@_LIVE
def test_a_tenant_lease_that_merely_looks_operator_owned_still_earns() -> None:
    """CLAIM: the discriminator is OWNERSHIP, not a lease naming
    convention.

    The rejected candidate was `UsageAccrual.lease_id`, whose `synmon-`
    prefix is an f-string in `apps/synthetic/e2e.py`. Keying on it would
    make an unrelated tenant who names a lease `synmon-prod` forfeit its
    miner's reward — and would fail OPEN (back to paying ourselves) the
    day someone renames that f-string.
    """
    observe_chain_epoch(2702)
    _own("tenant-vm", node_id(4), owner="operator-1", epoch=2702,
         unit_seconds=5_000, lease_id="synmon-prod-workload")

    assert scoring.compute_epoch_weights() == {node_id(4): 5_000}


@_LIVE
def test_an_operator_vm_is_excluded_whatever_its_lease_is_called() -> None:
    """CLAIM: the converse — ours is ours even with a tenant-shaped
    lease. `stampproof-1-lease` is exactly this case live: an operator VM
    with no `synmon` anywhere in its lease id."""
    observe_chain_epoch(2702)
    _own("stampproof-vm", node_id(5), owner=SYNTH, epoch=2702,
         unit_seconds=2_100_390, lease_id="a-perfectly-ordinary-lease")

    assert scoring.compute_epoch_weights() == {}


@_LIVE
def test_only_the_operator_share_is_removed_from_a_mixed_miner() -> None:
    """CLAIM: the filter is per-VM, not per-miner.

    A miner hosting both a tenant and one of our probes keeps EXACTLY its
    tenant share. Kills a mutant that drops the whole node once any of
    its rows is excluded.
    """
    observe_chain_epoch(2702)
    mixed = node_id(6)
    _own("tenant-vm", mixed, owner="operator-1", epoch=2702, unit_seconds=1_000_000)
    _own("synmon-vm", mixed, owner=SYNTH, epoch=2702, unit_seconds=400_974_150)

    assert scoring.compute_epoch_weights() == {mixed: 1_000_000}


@_LIVE
def test_exclusion_holds_for_a_vm_whose_placement_failed() -> None:
    """CLAIM: ownership is a property of the VM, not of a live placement.

    The live probes are all destroyed; their placements are Failed (§13
    drain) or superseded. A status-filtered join would have excluded
    none of them — which is precisely the 30 % that is in the pot today.
    """
    observe_chain_epoch(2702)
    _own("synmon-dead", node_id(1), owner=SYNTH, epoch=2702,
         unit_seconds=400_974_150, status=PlacementStatus.FAILED.value)

    assert scoring.compute_epoch_weights() == {}


# ─── the OTHER two readers ───────────────────────────────────────────


@_LIVE
def test_the_bill_excludes_operator_usage_too() -> None:
    """CLAIM: the priced readout and the reward weight agree on WHOSE
    usage counts.

    A bill computed over a different row set than the weight it derives
    from is a reconciliation trap — the same reason both already share an
    epoch selector. Nothing collects this bill yet (its one caller is the
    read-only `EpochWeightsView`), so this is observational today and
    exactly the moment to fix it.
    """
    observe_chain_epoch(2702)
    _own("tenant-vm", node_id(1), owner="operator-1", epoch=2702, unit_seconds=3_600_000)
    _own("synmon-vm", node_id(2), owner=SYNTH, epoch=2702, unit_seconds=3_600_000)

    owed = scoring.compute_owed_micro_usd({node_id(1): 1_000_000, node_id(2): 1_000_000})
    assert owed == {node_id(1): 1_000_000}


@override_settings(
    VALI_EPOCH_WEIGHT_SOURCE="snapshot",
    VALI_SYNTHETIC_TENANT_ID=SYNTH,
    VALI_REWARD_EXCLUDED_OWNERS=[REHEARSE],
)
def test_the_snapshot_source_excludes_operator_placements_too() -> None:
    """CLAIM: reverting `VALI_EPOCH_WEIGHT_SOURCE` to `snapshot` does not
    re-open the skim.

    `snapshot` is the compiled default and the documented fallback if the
    liveness gate never lands. A fix applied to only one of the two
    sources would be undone by a one-word config change.
    """
    make_placement(make_vm("tenant-vm"), node_id(1),
                   status=PlacementStatus.BOUND.value, owner="operator-1",
                   resource_class="small")
    make_placement(make_vm("synmon-vm"), node_id(2),
                   status=PlacementStatus.BOUND.value, owner=SYNTH,
                   resource_class="small")
    make_placement(make_vm("rehearse-vm"), node_id(3),
                   status=PlacementStatus.BOUND.value, owner=REHEARSE,
                   resource_class="small")

    assert scoring.compute_epoch_weights() == {node_id(1): 1590}


@_LIVE
def test_the_ledger_rows_survive_the_exclusion() -> None:
    """CLAIM: excluded at READ time — no data is destroyed.

    Keeping the rows means the policy is reversible by config (a
    mis-configured owner list is a one-line fix, not a month of lost
    billing history) and the ledger stays a complete audit record of what
    actually ran, including what our own monitoring consumed.
    """
    observe_chain_epoch(2702)
    _own("synmon-vm", node_id(1), owner=SYNTH, epoch=2702, unit_seconds=400_974_150)

    assert scoring.compute_epoch_weights() == {}
    row = UsageAccrual.objects.get(vm_id="synmon-vm")
    assert row.unit_seconds == 400_974_150


@_LIVE
def test_a_usage_row_with_no_placement_still_earns() -> None:
    """CLAIM: the join fails OPEN.

    `UsageAccrual` carries no owner, so ownership is one join away. A VM
    with no `Placement` row has no ownership evidence — and the safe
    answer there is to PAY. The cost of failing open is that we might
    keep one of our own rows in the pot; the cost of failing closed
    would be an honest miner losing an epoch to a missing join row.
    """
    observe_chain_epoch(2702)
    UsageAccrual.objects.create(
        epoch=2702, miner_node_id=node_id(1), vm_id="orphan-vm",
        resource_class="small", unit_seconds=4_242, billable_seconds=4_242,
    )
    assert scoring.compute_epoch_weights() == {node_id(1): 4_242}


# ─── chart ⇄ code agreement ──────────────────────────────────────────


def test_the_chart_ships_the_operator_owners_it_needs() -> None:
    """CLAIM: the deployed ConfigMap actually carries the excluded set.

    A settings default that the chart never renders is a fix that never
    ships. `kbsrehearse` is the live operator identity that is NOT the
    synthetic tenant, so the chart must name it.
    """
    values = yaml.safe_load(VALUES.read_text())
    assert REHEARSE in values["rewardExcludedOwners"]
    assert CONFIGMAP_TPL.read_text().count("VALI_REWARD_EXCLUDED_OWNERS") == 1
    assert ".Values.rewardExcludedOwners" in CONFIGMAP_TPL.read_text()


def test_the_setting_exists_so_the_rendered_key_is_not_inert() -> None:
    """CLAIM: the env var the ConfigMap renders is actually READ.

    Found by mutation: DELETING the `VALI_REWARD_EXCLUDED_OWNERS` line
    from `settings.py` left every behavioural test above green — they all
    `override_settings`, so none of them touches the real module — while
    the deployed key became inert and `kbsrehearse` would have gone on
    earning. This is the only test that reads the unoverridden setting,
    and it also pins that the value comes from the ENVIRONMENT rather
    than being a module-level constant a chart could never change.
    """
    from django.conf import settings as django_settings

    assert isinstance(django_settings.VALI_REWARD_EXCLUDED_OWNERS, list)

    source = (SETTINGS_PY).read_text()
    assert '_env_list("VALI_REWARD_EXCLUDED_OWNERS", [])' in source, (
        "the setting must be parsed from the env with an EMPTY default"
    )


def test_the_chart_does_not_restate_the_synthetic_tenant() -> None:
    """CLAIM: the chart relies on the union, not on a duplicate entry.

    Listing `synthetic-monitor` here would make it look removable — and
    a future operator rewriting the list would then silently restore the
    30 % skim.
    """
    values = yaml.safe_load(VALUES.read_text())
    assert SYNTH not in values["rewardExcludedOwners"]
