"""The location verdict is a pure function of measured evidence — this is
its matrix. No network, no DB."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from apps.miners import geo
from apps.miners.models import LocationVerdict

NOW = datetime(2026, 9, 21, 20, 0, tzinfo=UTC)
#: A control-plane vantage in northern France (Lille).
VANTAGE = geo.Vantage(name="cp-1", latitude=50.63, longitude=3.07)
#: A country-level GeoLite point — Paris, ~205 km from the vantage.
PARIS = geo.GeoRecord(
    country_code="FR", latitude=48.8582, longitude=2.3387, asn=64500, as_holder="EXAMPLE-AS"
)
TOKYO = geo.GeoRecord(country_code="JP", latitude=35.68, longitude=139.69, asn=2516)


def _peer(**over):
    base = {
        "name": "miner-c",
        "ip": "100.64.243.4",
        "connection_ip": "146.10.20.30",
        "country_code": "FR",
        "connected": True,
        "last_seen": (NOW - timedelta(seconds=30)).strftime("%Y-%m-%dT%H:%M:%S.123456789Z"),
    }
    base.update(over)
    return base


def _assess(**over):
    kwargs = dict(
        peer=_peer(),
        geo=PARIS,
        rtt_ms=4.0,
        guest_egress_ips=[],
        vantage=VANTAGE,
        now=NOW,
        km_per_ms=100.0,
        slack_km=300.0,
        peer_stale_s=900.0,
    )
    kwargs.update(over)
    return geo.assess(**kwargs)


def test_a_nearby_miner_with_consistent_evidence_is_verified() -> None:
    v = _assess()
    assert v.verdict == LocationVerdict.VERIFIED
    assert v.reasons == []


def test_a_far_exit_cannot_hide_behind_a_short_rtt() -> None:
    """The load-bearing check: a Tokyo exit is ~9 500 km from the vantage,
    which needs ≥ 95 ms of RTT. 4 ms is physically impossible ⇒ the IP
    is not where the packets are answered from."""
    v = _assess(geo=TOKYO, peer=_peer(country_code="JP"))
    assert v.verdict == LocationVerdict.UNVERIFIED
    assert v.reasons == [geo.R_LATENCY]


def test_a_far_exit_with_a_matching_long_rtt_is_verified() -> None:
    v = _assess(geo=TOKYO, peer=_peer(country_code="JP"), rtt_ms=240.0)
    assert v.verdict == LocationVerdict.VERIFIED


def test_a_near_claim_answering_from_far_away_is_refused() -> None:
    """The VPN case: a host on another continent tunnels through a French
    exit. The IP geolocates ~205 km away — but every packet still crosses
    the ocean, so the RTT is ~100 ms where ~205 km warrants ≤ 36 ms
    (2.5 × 2.0 ms + 30 ms, rounded up). Slower than the claim permits ⇒ not verified."""
    v = _assess(rtt_ms=100.0)
    assert v.verdict == LocationVerdict.UNVERIFIED
    assert v.reasons == [geo.R_RTT_TOO_HIGH]


def test_a_relayed_but_plausible_rtt_still_verifies_nearby() -> None:
    # ~205 km ⇒ budget ~35 ms; a TURN-relayed 30 ms path is within it.
    assert _assess(rtt_ms=30.0).verdict == LocationVerdict.VERIFIED


def test_nan_coordinates_cannot_verify() -> None:
    nan = float("nan")
    v = _assess(geo=geo.GeoRecord(country_code="FR", latitude=nan, longitude=nan))
    assert v.verdict == LocationVerdict.UNVERIFIED
    assert geo.R_LATENCY in v.reasons


def test_nan_or_negative_rtt_is_unavailable() -> None:
    assert _assess(rtt_ms=float("nan")).reasons == [geo.R_RTT_UNAVAILABLE]
    assert _assess(rtt_ms=-1.0).reasons == [geo.R_RTT_UNAVAILABLE]


def test_no_rtt_sample_is_unverified_not_verified() -> None:
    v = _assess(rtt_ms=None)
    assert v.verdict == LocationVerdict.UNVERIFIED
    assert v.reasons == [geo.R_RTT_UNAVAILABLE]


def test_geo_without_coordinates_cannot_be_bounded() -> None:
    v = _assess(geo=geo.GeoRecord(country_code="FR"))
    assert v.verdict == LocationVerdict.UNVERIFIED
    assert geo.R_LATENCY in v.reasons


def test_a_tenant_cvm_egressing_elsewhere_is_a_mismatch() -> None:
    """The attested guest says its traffic comes out of a different public
    IP than the host's own peer — guest traffic is being tunnelled."""
    v = _assess(guest_egress_ips=["146.10.20.30", "185.10.10.10"])
    assert v.verdict == LocationVerdict.MISMATCH
    assert v.reasons == [geo.R_GUEST_MISMATCH]


def test_tenant_cvms_on_the_same_egress_do_not_disturb_verified() -> None:
    v = _assess(guest_egress_ips=["146.10.20.30"])
    assert v.verdict == LocationVerdict.VERIFIED


def test_geoip_sources_disagreeing_is_a_mismatch() -> None:
    v = _assess(peer=_peer(country_code="DE"))
    assert v.verdict == LocationVerdict.MISMATCH
    assert v.reasons == [geo.R_SOURCE_DISAGREE]


def test_mismatch_wins_over_missing_checks() -> None:
    v = _assess(peer=_peer(country_code="DE"), rtt_ms=None)
    assert v.verdict == LocationVerdict.MISMATCH


def test_a_disconnected_peer_with_an_old_last_seen_is_unverified() -> None:
    old = (NOW - timedelta(hours=3)).strftime("%Y-%m-%dT%H:%M:%SZ")
    v = _assess(peer=_peer(last_seen=old, connected=False))
    assert v.verdict == LocationVerdict.UNVERIFIED
    assert v.reasons == [geo.R_PEER_STALE]


def test_a_connected_peer_is_fresh_whatever_last_seen_says() -> None:
    """NetBird's `last_seen` is the last (re)connection time, not a
    heartbeat: a miner connected for a week carries a week-old value."""
    old = (NOW - timedelta(days=7)).strftime("%Y-%m-%dT%H:%M:%SZ")
    v = _assess(peer=_peer(last_seen=old, connected=True))
    assert v.verdict == LocationVerdict.VERIFIED


def test_a_recently_disconnected_peer_is_still_fresh() -> None:
    recent = (NOW - timedelta(minutes=2)).strftime("%Y-%m-%dT%H:%M:%SZ")
    v = _assess(peer=_peer(last_seen=recent, connected=False))
    assert v.verdict == LocationVerdict.VERIFIED


def test_no_peer_is_unknown() -> None:
    v = _assess(peer=None)
    assert v.verdict == LocationVerdict.UNKNOWN
    assert v.reasons == [geo.R_NO_PEER]


@pytest.mark.parametrize("ip", ["100.64.1.2", "10.0.0.1", "127.0.0.1", "", None, "garbage"])
def test_a_non_public_connection_ip_is_unknown(ip) -> None:
    v = _assess(peer=_peer(connection_ip=ip))
    assert v.verdict == LocationVerdict.UNKNOWN
    assert v.reasons == [geo.R_NO_PUBLIC_IP]


def test_geo_lookup_failure_is_unknown() -> None:
    v = _assess(geo=None)
    assert v.verdict == LocationVerdict.UNKNOWN
    assert v.reasons == [geo.R_GEO_FAILED]


def test_haversine_lille_paris_is_about_205_km() -> None:
    assert 195 < geo.haversine_km(50.63, 3.07, 48.8582, 2.3387) < 215


def test_netbird_nanosecond_timestamps_parse() -> None:
    parsed = geo.parse_netbird_ts("2026-09-21T20:07:59.812376277Z")
    assert parsed == datetime(2026, 9, 21, 20, 7, 59, 812376, tzinfo=UTC)
    assert geo.parse_netbird_ts("nope") is None
    assert geo.parse_netbird_ts(None) is None


def test_public_ip_predicate() -> None:
    assert geo.is_public_ip("146.10.20.30")
    assert geo.is_public_ip("2001:41d0::1")
    assert not geo.is_public_ip("100.64.0.1")  # CGNAT — the NetBird overlay itself
    assert not geo.is_public_ip("192.168.1.1")
    assert not geo.is_public_ip("::1")
    assert not geo.is_public_ip("ff0e::1")  # global-scope multicast
    assert not geo.is_public_ip("::ffff:100.64.0.1")  # IPv4-mapped CGNAT
    assert not geo.is_public_ip("fec0::1")  # deprecated site-local


def test_tenant_peers_are_grouped_by_host_and_recency() -> None:
    peers = [
        _peer(name="hippius-tenant-vm-a", connection_ip="146.10.20.30"),
        _peer(name="hippius-tenant-vm-b", connection_ip="185.1.1.1"),
        _peer(
            name="hippius-tenant-vm-old",
            connection_ip="9.9.9.9",
            connected=False,
            last_seen=(NOW - timedelta(days=2)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        ),
        _peer(
            name="hippius-tenant-vm-longlived",
            connection_ip="185.1.1.1",
            connected=True,
            last_seen=(NOW - timedelta(days=9)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        ),
        _peer(name="hippius-tenant-vm-cgnat", connection_ip="100.64.5.5"),
        _peer(name="not-a-tenant", connection_ip="8.8.8.8"),
    ]
    hosts = {
        "vm-a": "miner-c",
        "vm-b": "miner-c",
        "vm-old": "miner-c",
        "vm-cgnat": "miner-c",
        "vm-longlived": "miner-c",
    }
    out = geo.tenant_peers_by_host(peers, hosts, now=NOW, stale_after_s=900)
    assert out == {"miner-c": ["146.10.20.30", "185.1.1.1"]}


def test_miner_peer_is_matched_on_overlay_ip_preferring_connected() -> None:
    peers = [
        _peer(ip="100.64.243.4", connected=False, connection_ip="1.1.1.1"),
        _peer(ip="100.64.243.4", connected=True, connection_ip="2.2.2.2"),
        _peer(ip="100.64.9.9"),
    ]
    assert geo.match_miner_peer(peers, "100.64.243.4")["connection_ip"] == "2.2.2.2"
    assert geo.match_miner_peer(peers, "100.64.0.1") is None
    assert geo.match_miner_peer(peers, None) is None


def test_a_registered_peer_id_wins_over_the_overlay_ip() -> None:
    peers = [
        _peer(id="peer-A", ip="100.64.243.4", connection_ip="1.1.1.1"),
        _peer(id="peer-B", ip="100.64.9.9", connection_ip="2.2.2.2"),
    ]
    assert geo.match_miner_peer(peers, "100.64.243.4", "peer-B")["connection_ip"] == "2.2.2.2"
    # an id nobody has falls back to the ip match
    assert geo.match_miner_peer(peers, "100.64.243.4", "peer-Z")["connection_ip"] == "1.1.1.1"
