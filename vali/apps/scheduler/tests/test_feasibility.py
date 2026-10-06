"""Can we place this flavor BEFORE we sell it?

The headline case is `4xlarge` (32 vCPU / 128 GiB) against
125 GB / 24-core hosts. It exceeds the hardware on BOTH
dimensions, so no amount of waiting or decommissioning makes it
placeable — and vali's own scheduler cannot see that, because capacity
is counted in reference-flavor SLOTS and one placement costs one slot
whatever its size.

That is the whole reason this module exists, and it is what these tests
defend: `never` must be reachable, must be distinct from `not-now`, and
must not be produced by a merely-full fleet.
"""

from __future__ import annotations

import pytest
from django.test import override_settings
from django.utils import timezone

from apps.scheduler import chain, feasibility
from apps.scheduler.models import MinerCapacity, MinerStatusMirror, PlacementStatus

from .factories import (
    make_dispatchable_identity,
    make_miner,
    make_placement,
    make_snapshot,
    make_vm,
    node_id,
    observe_chain_epoch,
)

# A representative mid-size host.
REAL_MINER_MEMORY_MB = 125_000
REAL_MINER_CPUS = 24


def _host(seed: int, *, memory_mb: int, cpus: int) -> MinerCapacity:
    """A dispatchable miner of a given size, mirrored + identity-backed."""
    make_dispatchable_identity(seed)
    return MinerCapacity.objects.create(
        miner_node_id=node_id(seed),
        status=MinerStatusMirror.ACTIVE,
        capacity_slots=64,
        observed_epoch=10,
        data_epoch=10,
        refreshed_at=timezone.now(),
        total_memory_mb=memory_mb,
        total_cpus=cpus,
    )


def _pin_chain(monkeypatch, *seeds: int) -> None:
    """Pin the chain read to a snapshot naming exactly `seeds` as Active.

    The chain is the one boundary this suite stubs; everything below it —
    the mirror, the gates, the fit arithmetic — is the real code.
    """
    snapshot = make_snapshot(10, [make_miner(s) for s in seeds])
    monkeypatch.setattr(chain, "read_miner_status", lambda: snapshot)


@pytest.fixture
def real_fleet(db, monkeypatch):  # noqa: ANN001, ANN201 — pytest fixture
    """Three identical mid-size miners."""
    observe_chain_epoch(10)
    for seed in (1, 2, 3):
        _host(seed, memory_mb=REAL_MINER_MEMORY_MB, cpus=REAL_MINER_CPUS)
    _pin_chain(monkeypatch, 1, 2, 3)


class TestTheFlavorMustPhysicallyFit:
    @override_settings(VALI_SCHEDULER_MAX_FLAVOR="4xlarge")
    def test_4xlarge_is_never_on_the_real_fleet(self, real_fleet) -> None:  # noqa: ANN001
        """THE case. 128 GiB / 32 vCPU exceeds a 125 GB / 24-core host on
        BOTH dimensions, so this is not a capacity problem that clears.
        (Offered here so the HARDWARE answer is what is under test.)"""
        result = feasibility.assess("4xlarge")
        assert result.verdict == "never"
        assert result.reason == "flavor-exceeds-every-host"
        assert result.fits_any_host is False
        assert result.headroom == 0
        # And it must say WHY, per host — an unexplained refusal is the
        # `no-eligible-miner` problem this endpoint exists to replace.
        assert all(h.shortfall for h in result.hosts)
        assert any("memory" in h.shortfall for h in result.hosts)
        assert any("cpu" in h.shortfall for h in result.hosts)

    def test_small_is_sellable_on_the_same_fleet(self, real_fleet) -> None:  # noqa: ANN001
        """The other side of the same gate: the grid's lower half is fine,
        so `never` is not simply what an empty ledger returns."""
        result = feasibility.assess("small")
        assert result.verdict == "yes"
        assert result.placeable_now is True
        assert result.headroom > 0

    def test_headroom_is_bounded_by_the_TIGHTER_dimension(
        self, real_fleet
    ) -> None:  # noqa: ANN001
        """A 24-core host takes 24 `small` on CPU but ~29 on RAM. The
        answer must be the smaller — the miner gates both, and reporting
        the looser one oversells by five VMs per host."""
        result = feasibility.assess("small")
        # 3 hosts × min((125000-4096)//4096, (24-2)//1) = 3 × min(29, 22)
        assert result.headroom == 3 * 22


class TestNotNowIsNotNever:
    def test_a_full_fleet_is_not_now(self, real_fleet) -> None:  # noqa: ANN001
        """A fleet with no room left must stay RETRYABLE. Collapsing it
        into `never` would permanently unsell a flavor the hardware can
        run, which is the mirror-image error of overselling."""
        # Fill every host with `2xlarge` (64 GiB / 16 vCPU): one fits,
        # a second does not (16+16 > 22 free vCPU).
        for seed in (1, 2, 3):
            make_placement(
                make_vm(f"vm-{seed}"),
                node_id(seed),
                status=PlacementStatus.BOUND.value,
                resource_class="2xlarge",
            )
        result = feasibility.assess("2xlarge")
        assert result.verdict == "not-now"
        assert result.reason == "fleet-full"
        # The hardware is still big enough — that is precisely why this is
        # not `never`. This assertion is the one that caught the original
        # bug: `never` had been judged against FREE resources, so any full
        # fleet permanently unsold a flavor it runs perfectly well.
        assert result.fits_any_host is True
        assert all(h.big_enough for h in result.hosts)
        assert result.headroom == 0

    def test_no_dispatchable_miner_is_not_now(self, db, monkeypatch) -> None:  # noqa: ANN001
        """An empty/unreachable fleet says `not-now`: vali cannot conclude
        the hardware is too small when it cannot see any hardware."""
        observe_chain_epoch(10)
        _pin_chain(monkeypatch)
        result = feasibility.assess("small")
        assert result.verdict == "not-now"
        assert result.reason == "no-dispatchable-miner"


class TestItRefusesToGuess:
    def test_a_host_with_no_trusted_anchor_never_counts_as_a_fit(
        self, db, monkeypatch
    ) -> None:  # noqa: ANN001
        """`total_memory_mb=None` means vali does not know the host's
        size. That must read as "no", never as "yes" — an unknown host
        must not be the reason a customer was promised a VM."""
        observe_chain_epoch(10)
        _host(1, memory_mb=None, cpus=None)
        _pin_chain(monkeypatch, 1)
        result = feasibility.assess("small")
        assert result.fits_any_host is False
        assert result.hosts[0].shortfall == "no-trusted-anchor"
        assert result.hosts[0].size_unknown is True
        assert result.hosts[0].free_memory_mb is None
        # …and unknown must NOT become `never`. An earlier version, facing
        # miners whose `total_memory_mb` was None (no operator anchor
        # seeded yet), answered `never` for the ENTIRE catalogue — it declared
        # every flavor permanently unsellable from missing data alone.
        # `never` has to be earned from knowledge.
        assert result.verdict == "not-now"
        assert result.reason == "host-size-unknown"

    def test_a_fleet_with_no_anchors_at_all_never_says_never(
        self, db, monkeypatch
    ) -> None:  # noqa: ANN001
        """Three reachable miners, none with a hardware anchor. Nothing may
        be `never`."""
        observe_chain_epoch(10)
        for seed in (1, 2, 3):
            _host(seed, memory_mb=None, cpus=None)
        _pin_chain(monkeypatch, 1, 2, 3)
        board = feasibility.assess_catalogue()
        assert len(board) == 6  # no cap by default: the whole grid is offered
        assert [f.verdict for f in board] == ["not-now"] * len(board)
        assert {f.reason for f in board} == {"host-size-unknown"}

    def test_the_disk_dimension_is_declared_unchecked(self, real_fleet) -> None:  # noqa: ANN001
        """vali has no mirror of host free disk (the heartbeat reports
        memory and CPU only), so the answer must SAY it did not evaluate
        disk rather than implying full coverage."""
        assert feasibility.assess("small").disk_checked is False

    def test_an_unknown_flavor_raises_rather_than_answering_no(
        self, real_fleet
    ) -> None:  # noqa: ANN001
        """A typo is a caller error. Flattening it into "cannot place"
        would make a sellable flavor look unsellable."""
        from apps.orchestration.services.flavors import UnknownFlavor

        with pytest.raises(UnknownFlavor):
            feasibility.assess("enormous")


class TestItAsksTheRealScheduler:
    def test_the_catalogue_board_covers_every_flavor(self, real_fleet) -> None:  # noqa: ANN001
        from apps.orchestration.services import flavors

        board = feasibility.assess_catalogue()
        assert [f.flavor for f in board] == list(flavors.FLAVOR_NAMES)

    def test_assess_writes_nothing(self, real_fleet) -> None:  # noqa: ANN001
        """Asking whether a VM could be placed must never place one."""
        from apps.lifecycle.models import Vm
        from apps.scheduler.models import Placement

        before = (Vm.objects.count(), Placement.objects.count())
        feasibility.assess_catalogue()
        assert (Vm.objects.count(), Placement.objects.count()) == before


class TestTheEndpoint:
    """`GET /v1/scheduler/feasibility` — the surface the backend calls."""

    def test_unauthenticated_is_rejected(self, real_fleet) -> None:  # noqa: ANN001
        from django.urls import reverse
        from rest_framework import status
        from rest_framework.test import APIClient

        resp = APIClient().get(reverse("scheduler_feasibility"))
        assert resp.status_code in (
            status.HTTP_401_UNAUTHORIZED,
            status.HTTP_403_FORBIDDEN,
        )

    def test_the_board_answers_every_flavor(
        self, real_fleet, authed_client
    ) -> None:  # noqa: ANN001
        from django.urls import reverse

        resp = authed_client.get(reverse("scheduler_feasibility"))
        assert resp.status_code == 200
        board = {f["flavor"]: f for f in resp.json()["flavors"]}
        assert board["small"]["verdict"] == "yes"
        # Offered (no cap), but no host of this fleet can hold it.
        assert board["4xlarge"]["verdict"] == "never"
        assert board["4xlarge"]["reason"] == "flavor-exceeds-every-host"

    def test_one_flavor_can_be_asked_for(
        self, real_fleet, authed_client
    ) -> None:  # noqa: ANN001
        from django.urls import reverse

        resp = authed_client.get(
            reverse("scheduler_feasibility"), {"flavor": "4xlarge"}
        )
        assert resp.status_code == 200
        assert [f["flavor"] for f in resp.json()["flavors"]] == ["4xlarge"]

    def test_an_unknown_flavor_is_400_not_a_negative_answer(
        self, real_fleet, authed_client
    ) -> None:  # noqa: ANN001
        """A typo must not read as "we cannot place it" — that would take a
        sellable flavor off the shelf for a spelling mistake."""
        from django.urls import reverse

        resp = authed_client.get(
            reverse("scheduler_feasibility"), {"flavor": "enormous"}
        )
        assert resp.status_code == 400


# ─── ?region= — the same question for ONE country ────────────────────


def _locate(seed: int, country: str, verdict: str = "verified") -> None:
    from apps.miners.models import MinerIdentity, MinerLocation

    MinerLocation.objects.create(
        miner=MinerIdentity.objects.get(chain_node_id=node_id(seed)),
        connection_ip="146.10.20.30",
        country_code=country,
        verdict=verdict,
        observed_at=timezone.now(),
    )


class TestRegion:
    def test_hosts_and_headroom_are_restricted_to_the_region(self, db, monkeypatch) -> None:  # noqa: ANN001
        """Three FR hosts and one DE host: the DE answer must count ONE
        host, not four — otherwise the headroom sells FR capacity as DE."""
        observe_chain_epoch(10)
        for seed in (1, 2, 3, 4):
            _host(seed, memory_mb=REAL_MINER_MEMORY_MB, cpus=REAL_MINER_CPUS)
            _locate(seed, "FR" if seed < 4 else "DE")
        _pin_chain(monkeypatch, 1, 2, 3, 4)
        de = feasibility.assess("small", region="DE")
        assert de.verdict == "yes"
        assert [h.node_id for h in de.hosts] == [node_id(4)]
        assert de.headroom == 22
        assert de.region == "DE"
        fr = feasibility.assess("small", region="fr")
        assert fr.region == "FR"
        assert fr.headroom == 3 * 22
        # Unconstrained still sees the whole fleet — the gate is inert.
        assert feasibility.assess("small").headroom == 4 * 22
        assert feasibility.assess("small").region == ""

    def test_no_location_data_at_all_is_region_unknown(self, real_fleet) -> None:  # noqa: ANN001
        """The probe has not run: nobody knows where the fleet is. That is
        missing data, and missing data must never unsell — `not-now`."""
        result = feasibility.assess("small", region="FR")
        assert result.verdict == "not-now"
        assert result.reason == "region-unknown"
        assert result.hosts == []

    def test_a_located_fleet_with_nobody_there_is_never(self, real_fleet) -> None:  # noqa: ANN001
        """The fleet IS located, all of it in FR. Asking for DE cannot be
        fixed by waiting: do not sell."""
        for seed in (1, 2, 3):
            _locate(seed, "FR")
        result = feasibility.assess("small", region="DE")
        assert result.verdict == "never"
        assert result.reason == "no-miner-in-region"
        assert result.fits_any_host is False
        assert result.placeable_now is False

    def test_a_partially_located_fleet_never_says_never(self, real_fleet) -> None:  # noqa: ANN001
        """One miner located in DE, two the probe has not reached. That is
        no evidence about FR — `never` from it would unsell a country the
        unlocated miners may well be in."""
        _locate(1, "DE")
        result = feasibility.assess("small", region="FR")
        assert result.verdict == "not-now"
        assert result.reason == "region-unknown"

    def test_a_stale_location_does_not_count(self, real_fleet, settings) -> None:  # noqa: ANN001
        """Three miners verified in FR, but the probe stopped hours ago.
        Nothing is credibly located any more: not `yes`, not `never` —
        the picture is stale, so `region-unknown` until it runs again."""
        from datetime import timedelta

        from apps.miners.models import MinerLocation

        settings.VALI_GEO_MAX_AGE_S = 3600
        for seed in (1, 2, 3):
            _locate(seed, "FR")
        MinerLocation.objects.update(observed_at=timezone.now() - timedelta(hours=3))
        result = feasibility.assess("small", region="FR")
        assert result.verdict == "not-now"
        assert result.reason == "region-unknown"
        assert result.hosts == []

    def test_miners_there_but_unverified_is_region_unverified(self, real_fleet) -> None:  # noqa: ANN001
        """Detected in FR, not yet proven (latency missing, peer stale…).
        Retryable — the next probe cycle can flip it — so `not-now`."""
        _locate(1, "FR", "unverified")
        _locate(2, "FR", "mismatch")
        _locate(3, "DE")
        result = feasibility.assess("small", region="FR")
        assert result.verdict == "not-now"
        assert result.reason == "region-unverified"

    def test_unverified_counts_when_the_operator_turns_verification_off(
        self, real_fleet, settings
    ) -> None:  # noqa: ANN001
        settings.VALI_GEO_REQUIRE_VERIFIED = False
        _locate(1, "FR", "unverified")
        result = feasibility.assess("small", region="FR")
        assert result.verdict == "yes"
        assert [h.node_id for h in result.hosts] == [node_id(1)]

    def test_verified_but_undispatchable_is_not_now(self, db, monkeypatch) -> None:  # noqa: ANN001
        """A miner proven to be in FR whose heartbeat went stale: it is in
        the region, but nothing can launch onto it right now."""
        from datetime import timedelta

        from apps.miners.models import MinerIdentity

        observe_chain_epoch(10)
        _host(1, memory_mb=REAL_MINER_MEMORY_MB, cpus=REAL_MINER_CPUS)
        _locate(1, "FR")
        MinerIdentity.objects.filter(chain_node_id=node_id(1)).update(
            last_seen_at=timezone.now() - timedelta(days=1)
        )
        _pin_chain(monkeypatch, 1)
        result = feasibility.assess("small", region="FR")
        assert result.verdict == "not-now"
        assert result.reason == "no-dispatchable-miner"

    def test_the_catalogue_board_carries_the_region(self, real_fleet) -> None:  # noqa: ANN001
        for seed in (1, 2, 3):
            _locate(seed, "FR")
        board = feasibility.assess_catalogue(region="fr")
        assert {f.region for f in board} == {"FR"}
        assert all(
            f.verdict == "never" and f.reason == "no-miner-in-region"
            for f in feasibility.assess_catalogue(region="DE")
            if f.reason != "flavor-not-offered"
        )

    def test_http_region_param_and_echo(self, real_fleet, authed_client) -> None:  # noqa: ANN001
        from django.urls import reverse

        for seed in (1, 2, 3):
            _locate(seed, "FR")
        resp = authed_client.get(
            reverse("scheduler_feasibility"), {"flavor": "small", "region": "fr"}
        )
        assert resp.status_code == 200
        row = resp.json()["flavors"][0]
        assert row["region"] == "FR"
        assert row["verdict"] == "yes"
        resp = authed_client.get(
            reverse("scheduler_feasibility"), {"flavor": "small", "region": "DE"}
        )
        assert resp.json()["flavors"][0]["reason"] == "no-miner-in-region"

    @pytest.mark.parametrize("bad", ["FRA", "F1", "France", "F"])
    def test_http_malformed_region_is_400(self, real_fleet, authed_client, bad) -> None:  # noqa: ANN001
        """A typo must not read as `never` — that would take a whole country
        off the shelf for a spelling mistake."""
        from django.urls import reverse

        resp = authed_client.get(reverse("scheduler_feasibility"), {"region": bad})
        assert resp.status_code == 400, bad
        assert resp.json()["category"] == "invalid"


class TestTheOfferedMaximum:
    """`VALI_SCHEDULER_MAX_FLAVOR` caps what is SOLD, independently of what
    the hardware could hold. Unset (the default) there is NO cap: 4xlarge
    is sold wherever it fits — today the NL miner (64 threads, 256 GB)."""

    @pytest.fixture
    def big_fleet(self, db, monkeypatch):  # noqa: ANN001, ANN201
        observe_chain_epoch(10)
        _host(1, memory_mb=256180, cpus=64)
        _pin_chain(monkeypatch, 1)

    def test_4xlarge_is_offered_by_default_where_it_fits(self, big_fleet) -> None:  # noqa: ANN001
        assert feasibility.assess("4xlarge").verdict == "yes"

    @override_settings(VALI_SCHEDULER_MAX_FLAVOR="")
    def test_an_empty_cap_is_no_cap(self, big_fleet) -> None:  # noqa: ANN001
        assert feasibility.assess("4xlarge").verdict == "yes"

    def test_4xlarge_is_not_offered_by_default_where_it_does_not_fit(
        self, real_fleet
    ) -> None:  # noqa: ANN001
        # Truthful per fleet: the default does not sell it where no host holds it.
        assert feasibility.assess("4xlarge").reason == "flavor-exceeds-every-host"

    @override_settings(VALI_SCHEDULER_MAX_FLAVOR="2xlarge")
    def test_a_2xlarge_cap_withdraws_4xlarge_even_where_it_fits(
        self, big_fleet
    ) -> None:  # noqa: ANN001
        result = feasibility.assess("4xlarge")
        assert (result.verdict, result.reason) == ("never", "flavor-not-offered")
        assert result.placeable_now is False and result.headroom == 0

    def test_2xlarge_the_largest_offered_is_answered_on_the_hardware(
        self, big_fleet
    ) -> None:  # noqa: ANN001
        assert feasibility.assess("2xlarge").verdict == "yes"

    @override_settings(VALI_SCHEDULER_MAX_FLAVOR="4xlarge")
    def test_raising_the_cap_offers_it(self, big_fleet) -> None:  # noqa: ANN001
        assert feasibility.assess("4xlarge").verdict == "yes"

    @override_settings(VALI_SCHEDULER_MAX_FLAVOR="large")
    def test_lowering_the_cap_withdraws_the_sizes_above(self, big_fleet) -> None:  # noqa: ANN001
        verdicts = {f.flavor: (f.verdict, f.reason) for f in feasibility.assess_catalogue()}
        assert verdicts["large"][0] == "yes"
        assert verdicts["xlarge"] == ("never", "flavor-not-offered")
        assert verdicts["2xlarge"] == ("never", "flavor-not-offered")

    @override_settings(VALI_SCHEDULER_MAX_FLAVOR="2xlarge")
    def test_the_not_offered_answer_reads_no_chain(self, db, monkeypatch) -> None:  # noqa: ANN001
        def boom():  # noqa: ANN202
            raise AssertionError("read the chain for a flavor that is not for sale")

        monkeypatch.setattr(chain, "read_miner_status", boom)
        assert feasibility.assess("4xlarge").reason == "flavor-not-offered"

    @override_settings(VALI_SCHEDULER_MAX_FLAVOR="huge")
    def test_a_misconfigured_cap_fails_loudly(self, big_fleet) -> None:  # noqa: ANN001
        from django.core.exceptions import ImproperlyConfigured

        with pytest.raises(ImproperlyConfigured, match="not a flavor"):
            feasibility.assess("small")
