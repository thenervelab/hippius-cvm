"""`vali_geo_probe --once` against stubbed sources: what it writes, what it
refuses to overwrite, and when it re-asks GeoIP."""

from __future__ import annotations

from datetime import timedelta

import pytest
from django.core.management import call_command
from django.utils import timezone

from apps.lifecycle.models import VmState
from apps.miners import geo
from apps.miners.management.commands import vali_geo_probe as cmd
from apps.miners.models import LocationVerdict, MinerLocation
from apps.orchestration.effects import EffectUnavailable
from apps.scheduler.tests.factories import make_dispatchable_identity, make_vm

pytestmark = pytest.mark.django_db

PARIS = geo.GeoRecord(
    country_code="FR", latitude=48.8582, longitude=2.3387, asn=64500, as_holder="EXAMPLE-AS"
)


def _peers(now, **over):
    seen = (now - timedelta(seconds=20)).strftime("%Y-%m-%dT%H:%M:%S.000000000Z")
    p = {
        "name": "miner-a-host",
        "ip": "100.64.0.1",
        "connection_ip": "146.10.20.30",
        "country_code": "FR",
        "connected": True,
        "last_seen": seen,
    }
    p.update(over)
    return [p]


@pytest.fixture(autouse=True)
def _geo_settings(settings):
    settings.VALI_GEO_VANTAGE_NAME = "cp-1"
    settings.VALI_GEO_VANTAGE_LAT = 50.63
    settings.VALI_GEO_VANTAGE_LON = 3.07
    settings.VALI_GEO_SLACK_KM = 300.0
    settings.VALI_SYNTHETIC_PUSHGATEWAY_URL = ""


@pytest.fixture
def stubs(monkeypatch):
    """Stub the three network sources; each test steers them."""
    now = timezone.now()
    calls = {"geo": 0, "rtt": 0}
    state = {"peers": _peers(now), "geo": PARIS, "rtt": 4.2}

    def fetch():
        if isinstance(state["peers"], Exception):
            raise state["peers"]
        return state["peers"]

    def lookup(ip):
        calls["geo"] += 1
        return state["geo"]

    def rtt(host, port=9700, *, samples=5, timeout_s=3.0):
        calls["rtt"] += 1
        return state["rtt"]

    monkeypatch.setattr(geo, "fetch_netbird_peers", fetch)
    monkeypatch.setattr(geo, "ripestat_geo", lookup)
    monkeypatch.setattr(geo, "tcp_connect_rtt_ms", rtt)
    state["calls"] = calls
    state["now"] = now
    return state


def test_once_writes_a_verified_row_from_the_three_sources(stubs) -> None:
    miner = make_dispatchable_identity(1)  # netbird_ip 100.64.0.1
    call_command("vali_geo_probe", "--once")
    row = MinerLocation.objects.get(miner=miner)
    assert row.verdict == LocationVerdict.VERIFIED
    assert row.country_code == "FR" and row.region == "FR"
    assert row.connection_ip == "146.10.20.30"
    assert row.asn == 64500 and row.as_holder == "EXAMPLE-AS"
    assert row.rtt_ms == pytest.approx(4.2)
    assert row.rtt_vantage == "cp-1"
    assert row.verdict_reasons == []
    assert row.evidence_json["peer"]["connection_ip"] == "146.10.20.30"
    assert row.netbird_last_seen_at is not None


def test_a_netbird_outage_skips_the_cycle_and_keeps_the_old_row(stubs) -> None:
    miner = make_dispatchable_identity(1)
    cmd.probe_once(stubs["now"])
    assert MinerLocation.objects.get(miner=miner).verdict == LocationVerdict.VERIFIED
    stubs["peers"] = EffectUnavailable("netbird:list-peers: peer unreachable")
    report = cmd.probe_once(stubs["now"] + timedelta(minutes=10))
    assert report.skipped and report.probed == 0
    row = MinerLocation.objects.get(miner=miner)
    assert row.verdict == LocationVerdict.VERIFIED  # not downgraded to unknown by a blink


def test_geoip_is_cached_while_the_ip_is_unchanged_and_fresh(stubs) -> None:
    make_dispatchable_identity(1)
    cmd.probe_once(stubs["now"])
    cmd.probe_once(stubs["now"] + timedelta(minutes=10))
    assert stubs["calls"]["geo"] == 1  # second cycle reused the row
    assert stubs["calls"]["rtt"] == 2  # RTT is re-measured every cycle
    # a changed egress IP forces a fresh lookup
    stubs["peers"] = _peers(stubs["now"] + timedelta(minutes=20), connection_ip="146.10.20.31")
    cmd.probe_once(stubs["now"] + timedelta(minutes=20))
    assert stubs["calls"]["geo"] == 2


def test_geoip_is_refreshed_after_the_ttl(stubs, settings) -> None:
    """The TTL is measured from when RIPEstat ANSWERED (`geo_refreshed_at`),
    not from `observed_at`, which every cycle rewrites — otherwise a
    10-minute loop would never let a 24 h TTL expire."""
    settings.VALI_GEO_GEOIP_TTL_S = 60
    miner = make_dispatchable_identity(1)
    cmd.probe_once(stubs["now"])
    first = MinerLocation.objects.get(miner=miner).geo_refreshed_at
    assert first == stubs["now"]
    stubs["peers"] = _peers(stubs["now"] + timedelta(seconds=30))
    cmd.probe_once(stubs["now"] + timedelta(seconds=30))
    assert stubs["calls"]["geo"] == 1  # within TTL: cached, timestamp kept
    assert MinerLocation.objects.get(miner=miner).geo_refreshed_at == first
    stubs["peers"] = _peers(stubs["now"] + timedelta(minutes=5))
    cmd.probe_once(stubs["now"] + timedelta(minutes=5))
    assert stubs["calls"]["geo"] == 2
    assert MinerLocation.objects.get(miner=miner).geo_refreshed_at == stubs["now"] + timedelta(
        minutes=5
    )


def test_a_failed_geoip_lookup_is_retried_next_cycle_not_cached(stubs) -> None:
    miner = make_dispatchable_identity(1)
    stubs["geo"] = None  # RIPEstat has nothing for this IP
    cmd.probe_once(stubs["now"])
    row = MinerLocation.objects.get(miner=miner)
    assert row.verdict == LocationVerdict.UNKNOWN
    assert row.country_code == "FR"  # NetBird's opinion is recorded…
    assert row.geo_refreshed_at is None  # …but never treated as an answer
    stubs["geo"] = PARIS
    stubs["peers"] = _peers(stubs["now"] + timedelta(minutes=10))
    cmd.probe_once(stubs["now"] + timedelta(minutes=10))
    assert stubs["calls"]["geo"] == 2
    assert MinerLocation.objects.get(miner=miner).verdict == LocationVerdict.VERIFIED


def test_one_miner_raising_does_not_starve_the_rest(stubs, monkeypatch) -> None:
    make_dispatchable_identity(1)
    ok = make_dispatchable_identity(2)
    stubs["peers"] = _peers(stubs["now"]) + _peers(stubs["now"], ip="100.64.0.2")
    real = geo.assess

    def boom(**kw):
        if kw["peer"] and kw["peer"].get("ip") == "100.64.0.1":
            raise RuntimeError("synthetic failure")
        return real(**kw)

    monkeypatch.setattr(geo, "assess", boom)
    report = cmd.probe_once(stubs["now"])
    assert report.probed == 2
    assert MinerLocation.objects.get(miner=ok).verdict == LocationVerdict.VERIFIED
    assert not MinerLocation.objects.filter(miner_id="miner-01").exists()


def test_a_miner_without_a_netbird_ip_is_written_unknown(stubs) -> None:
    from apps.miners.models import MinerIdentity, MinerStatus

    m = MinerIdentity.objects.create(
        miner_id="miner-noip",
        pubkey_hex="ff" * 32,
        platform_id="ee" * 16,
        netbird_ip=None,
        status=MinerStatus.ACTIVE,
    )
    cmd.probe_once(stubs["now"])
    row = MinerLocation.objects.get(miner=m)
    assert row.verdict == LocationVerdict.UNKNOWN
    assert row.verdict_reasons == [geo.R_NO_PEER]
    assert stubs["calls"]["rtt"] == 0


def test_placeable_locations_ages_rows_out(stubs, settings) -> None:
    settings.VALI_GEO_MAX_AGE_S = 3600
    miner = make_dispatchable_identity(1)
    cmd.probe_once(stubs["now"])
    assert list(geo.placeable_locations(now=stubs["now"])) == [
        MinerLocation.objects.get(miner=miner)
    ]
    assert list(geo.placeable_locations(now=stubs["now"] + timedelta(hours=2))) == []


def test_a_tenant_cvm_egressing_elsewhere_flips_the_host_to_mismatch(stubs) -> None:
    miner = make_dispatchable_identity(1)
    vm = make_vm("vm-x", "lease-x")
    vm.state = VmState.ACTIVE
    vm.host = miner.miner_id
    vm.save(update_fields=["state", "host"])
    seen = (stubs["now"] - timedelta(seconds=5)).strftime("%Y-%m-%dT%H:%M:%SZ")
    stubs["peers"] = _peers(stubs["now"]) + [
        {
            "name": "hippius-tenant-vm-x",
            "ip": "100.64.9.9",
            "connection_ip": "185.1.1.1",
            "last_seen": seen,
        }
    ]
    cmd.probe_once(stubs["now"])
    row = MinerLocation.objects.get(miner=miner)
    assert row.verdict == LocationVerdict.MISMATCH
    assert row.verdict_reasons == [geo.R_GUEST_MISMATCH]
    assert row.guest_egress_ips == ["185.1.1.1"]


def test_a_far_exit_is_recorded_but_unverified(stubs) -> None:
    miner = make_dispatchable_identity(1)
    stubs["geo"] = geo.GeoRecord(country_code="JP", latitude=35.68, longitude=139.69)
    stubs["peers"] = _peers(stubs["now"], country_code="JP")
    cmd.probe_once(stubs["now"])
    row = MinerLocation.objects.get(miner=miner)
    assert row.country_code == "JP"
    assert row.verdict == LocationVerdict.UNVERIFIED
    assert row.verdict_reasons == [geo.R_LATENCY]


def test_a_miner_without_a_peer_is_unknown_and_geoip_is_not_asked(stubs) -> None:
    miner = make_dispatchable_identity(7)  # netbird_ip 100.64.0.7 — no peer in the stub
    cmd.probe_once(stubs["now"])
    row = MinerLocation.objects.get(miner=miner)
    assert row.verdict == LocationVerdict.UNKNOWN
    assert row.verdict_reasons == [geo.R_NO_PEER]
    assert stubs["calls"] == {"geo": 0, "rtt": 0}


def test_report_lists_verdict_changes_only(stubs) -> None:
    make_dispatchable_identity(1)
    first = cmd.probe_once(stubs["now"])
    second = cmd.probe_once(stubs["now"] + timedelta(minutes=10))
    assert [c[2] for c in first.changed] == [LocationVerdict.VERIFIED]
    assert second.changed == [] and second.probed == 1


def test_non_finite_or_negative_settings_fall_back_to_defaults(stubs, settings) -> None:
    """`km_per_ms=nan` would make every comparison False and every miner
    `verified`. The knobs are validated on read."""
    settings.VALI_GEO_KM_PER_MS = float("nan")
    settings.VALI_GEO_RTT_PATH_FACTOR = float("inf")
    settings.VALI_GEO_RTT_EXTRA_MS = -5.0
    settings.VALI_GEO_SLACK_KM = 0.0  # zero is a legitimate slack
    miner = make_dispatchable_identity(1)
    stubs["rtt"] = 100.0  # 240 km claim, transatlantic RTT
    cmd.probe_once(stubs["now"])
    row = MinerLocation.objects.get(miner=miner)
    assert row.verdict == LocationVerdict.UNVERIFIED
    assert row.verdict_reasons == [geo.R_RTT_TOO_HIGH]


def test_invalid_vantage_coordinates_fail_closed(stubs, settings) -> None:
    settings.VALI_GEO_VANTAGE_LAT = 999.0
    miner = make_dispatchable_identity(1)
    cmd.probe_once(stubs["now"])
    row = MinerLocation.objects.get(miner=miner)
    assert row.verdict == LocationVerdict.UNVERIFIED
    assert geo.R_RTT_TOO_HIGH in row.verdict_reasons or geo.R_LATENCY in row.verdict_reasons


MELBOURNE = geo.GeoRecord(
    country_code="AU",
    city="Melbourne",
    latitude=-37.8136,
    longitude=144.9631,
    asn=64500,
    as_holder="EXAMPLE-AS Example",
)


def test_rtt_arbitration_stores_the_arbitrated_country_verified(stubs) -> None:
    """NetBird CA, RIPEstat Melbourne, 293 ms from the
    vantage ⇒ stored AU, verified, the arbitration visible."""
    miner = make_dispatchable_identity(1)
    stubs["geo"] = MELBOURNE
    stubs["peers"] = _peers(stubs["now"], connection_ip="49.10.20.1", country_code="CA")
    stubs["rtt"] = 293.0
    cmd.probe_once(stubs["now"])
    row = MinerLocation.objects.get(miner=miner)
    assert row.verdict == LocationVerdict.VERIFIED
    assert row.region == "AU" and row.city == "Melbourne"
    assert row.verdict_reasons == [geo.R_RTT_ARBITRATED]
    assert list(geo.placeable_locations(now=stubs["now"])) == [row]
    # The cached RIPEstat answer replays next cycle and still arbitrates.
    cmd.probe_once(stubs["now"] + timedelta(minutes=10))
    assert stubs["calls"]["geo"] == 1
    assert MinerLocation.objects.get(miner=miner).verdict == LocationVerdict.VERIFIED


def test_a_netbird_arbitration_win_stores_its_country_without_ripestat_place(stubs) -> None:
    """Only NetBird's FR fits 8 ms: FR is stored (unverified), Melbourne's
    city/coordinates are not, and RIPEstat is asked again next cycle —
    the row no longer holds its answer."""
    miner = make_dispatchable_identity(1)
    stubs["geo"] = MELBOURNE
    stubs["rtt"] = 8.0
    cmd.probe_once(stubs["now"])
    row = MinerLocation.objects.get(miner=miner)
    assert row.verdict == LocationVerdict.UNVERIFIED
    assert row.region == "FR"
    assert row.verdict_reasons == [geo.R_ARBITRATED_COUNTRY_ONLY]
    assert (row.city, row.latitude, row.longitude) == ("", None, None)
    assert row.evidence_json["geo_country_code"] == "AU"
    assert row.geo_refreshed_at is None
    cmd.probe_once(stubs["now"] + timedelta(minutes=10))
    assert stubs["calls"]["geo"] == 2


def test_an_unresolved_disagreement_keeps_storing_ripestat(stubs) -> None:
    miner = make_dispatchable_identity(1)
    stubs["peers"] = _peers(stubs["now"], country_code="DE")
    cmd.probe_once(stubs["now"])
    row = MinerLocation.objects.get(miner=miner)
    assert row.verdict == LocationVerdict.MISMATCH
    assert row.verdict_reasons == [geo.R_SOURCE_DISAGREE]
    assert row.region == "FR" and row.city == ""  # PARIS carries no city
