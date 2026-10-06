"""RTT arbitration between disagreeing GeoIP sources, the country-extent
table it relies on, and RIPEstat's ASN fallback. No network."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from apps.miners import geo
from apps.miners.models import LocationVerdict
from apps.orchestration.effects import EffectError, EffectUnavailable

NOW = datetime(2026, 9, 26, 12, 0, tzinfo=UTC)
#: A control-plane vantage in northern France (Lille).
VANTAGE = geo.Vantage(name="cp-1", latitude=50.63, longitude=3.07)
#: A RIPEstat maxmind-geo-lite answer placing 49.10.20.1 in Melbourne.
MELBOURNE = geo.GeoRecord(
    country_code="AU", city="Melbourne", latitude=-37.8136, longitude=144.9631, asn=64500
)
ASHBURN = geo.GeoRecord(country_code="US", city="Ashburn", latitude=39.04, longitude=-77.49)


def _peer(**over):
    base = {
        "name": "miner-e",
        "ip": "100.64.10.5",
        "connection_ip": "49.10.20.1",
        "country_code": "CA",
        "connected": True,
        "last_seen": (NOW - timedelta(days=2)).strftime("%Y-%m-%dT%H:%M:%S.123456789Z"),
    }
    base.update(over)
    return base


def _assess(**over):
    kwargs = dict(
        peer=_peer(),
        geo=MELBOURNE,
        rtt_ms=293.0,
        guest_egress_ips=[],
        vantage=VANTAGE,
        now=NOW,
        km_per_ms=100.0,
        slack_km=300.0,
        peer_stale_s=900.0,
    )
    kwargs.update(over)
    return geo.assess(**kwargs)


# ─── the motivating case ────────────────────────────────────────────────────


def test_netbird_ca_vs_ripestat_melbourne_at_293ms_verifies_au() -> None:
    """NetBird's GeoLite says CA (the range is registered to a Canadian
    entity), RIPEstat says Melbourne. Canada is at most ~8 500 km from the
    vantage; 293 ms needs >= 10 520 km under bound (b). Only Melbourne
    fits => verified AU, and the arbitration shows."""
    v = _assess()
    assert v.verdict == LocationVerdict.VERIFIED
    assert v.reasons == [geo.R_RTT_ARBITRATED]
    assert v.country_code == "AU"


def test_the_arbitrated_winner_still_faces_every_check() -> None:
    """Arbitration only picks the candidate; a disconnected, stale peer
    still keeps it unverified (and the note stays for the operator)."""
    old = (NOW - timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M:%SZ")
    v = _assess(peer=_peer(connected=False, last_seen=old))
    assert v.verdict == LocationVerdict.UNVERIFIED
    assert v.reasons == [geo.R_PEER_STALE, geo.R_RTT_ARBITRATED]
    assert v.country_code == "AU"


def test_ca_vs_us_at_90ms_stays_a_mismatch() -> None:
    """Both North American candidates fit 90 ms from the vantage — the RTT
    cannot tell them apart => the disagreement stands."""
    v = _assess(geo=ASHBURN, rtt_ms=90.0)
    assert v.verdict == LocationVerdict.MISMATCH
    assert v.reasons == [geo.R_SOURCE_DISAGREE]
    assert v.country_code == ""


def test_both_candidates_consistent_is_a_mismatch() -> None:
    """DE vs a Paris point at 6 ms: both fit."""
    paris = geo.GeoRecord(country_code="FR", latitude=48.8582, longitude=2.3387)
    v = _assess(peer=_peer(country_code="DE"), geo=paris, rtt_ms=6.0)
    assert v.verdict == LocationVerdict.MISMATCH
    assert v.reasons == [geo.R_SOURCE_DISAGREE]


def test_neither_candidate_consistent_is_a_mismatch() -> None:
    """CA vs Melbourne at 5 ms: both are too far for bound (a)."""
    v = _assess(rtt_ms=5.0)
    assert v.verdict == LocationVerdict.MISMATCH
    assert v.reasons == [geo.R_SOURCE_DISAGREE]


def test_a_country_missing_from_the_table_cannot_be_arbitrated() -> None:
    """NetBird names a country with no disc (FJ): it cannot be ruled out,
    so Melbourne fitting alone proves nothing => fail closed."""
    assert "FJ" not in geo.COUNTRY_DISCS
    v = _assess(peer=_peer(country_code="FJ"))
    assert v.verdict == LocationVerdict.MISMATCH
    assert v.reasons == [geo.R_SOURCE_DISAGREE]


def test_a_coordinate_less_ripestat_country_missing_from_the_table_cannot_be_arbitrated() -> None:
    v = _assess(geo=geo.GeoRecord(country_code="FJ"))
    assert v.verdict == LocationVerdict.MISMATCH
    assert v.reasons == [geo.R_SOURCE_DISAGREE]


@pytest.mark.parametrize("rtt", [None, float("nan"), -1.0])
def test_no_usable_rtt_cannot_arbitrate(rtt) -> None:
    v = _assess(rtt_ms=rtt)
    assert v.verdict == LocationVerdict.MISMATCH
    assert v.reasons == [geo.R_SOURCE_DISAGREE]


def test_a_guest_egress_mismatch_still_wins_over_arbitration() -> None:
    v = _assess(guest_egress_ips=["49.10.20.1", "203.0.113.50"])
    assert v.verdict == LocationVerdict.MISMATCH
    assert v.reasons == [geo.R_SOURCE_DISAGREE, geo.R_GUEST_MISMATCH]
    assert v.country_code == ""


def test_a_guest_egress_mismatch_wins_when_sources_agree_too() -> None:
    v = _assess(peer=_peer(country_code="AU"), guest_egress_ips=["203.0.113.50"])
    assert v.verdict == LocationVerdict.MISMATCH
    assert v.reasons == [geo.R_GUEST_MISMATCH]


def test_netbird_winning_is_stored_but_never_verified() -> None:
    """NetBird says FR, RIPEstat says Melbourne, the RTT is 8 ms: only France
    fits. France is only a disc here (no coordinates), so it is kept as
    the country but never verified."""
    v = _assess(peer=_peer(country_code="FR"), rtt_ms=8.0)
    assert v.verdict == LocationVerdict.UNVERIFIED
    assert v.reasons == [geo.R_ARBITRATED_COUNTRY_ONLY]
    assert v.country_code == "FR"


def test_KNOWN_RESIDUAL_inflated_rtt_lets_the_farther_ripestat_answer_win() -> None:
    """KNOWN RESIDUAL, NOT A GUARANTEE (docs/design/miner-geolocation.md §4).

    A miner can only ADD latency (delayed SYN-ACKs). Same IP, NetBird says
    FR, RIPEstat says Melbourne: at its honest 8 ms France wins (unverified);
    inflated past France's (b) floor, Melbourne wins and VERIFIES as AU. A
    single vantage cannot tell a real 293 ms from a padded one. This test
    pins today's behaviour so a second-vantage fix has to change it on
    purpose — flip it to assert the attack fails, don't delete it."""
    honest = _assess(peer=_peer(country_code="FR"), rtt_ms=8.0)
    assert (honest.verdict, honest.country_code) == (LocationVerdict.UNVERIFIED, "FR")
    padded = _assess(peer=_peer(country_code="FR"), rtt_ms=293.0)
    assert (padded.verdict, padded.country_code) == (LocationVerdict.VERIFIED, "AU")
    assert padded.reasons == [geo.R_RTT_ARBITRATED]


def test_a_stale_netbird_winner_says_so_too() -> None:
    old = (NOW - timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M:%SZ")
    v = _assess(peer=_peer(country_code="FR", connected=False, last_seen=old), rtt_ms=8.0)
    assert v.verdict == LocationVerdict.UNVERIFIED
    assert v.reasons == [geo.R_ARBITRATED_COUNTRY_ONLY, geo.R_PEER_STALE]


def test_a_coordinate_less_ripestat_winner_is_not_verified() -> None:
    v = _assess(geo=geo.GeoRecord(country_code="AU"))
    assert v.verdict == LocationVerdict.UNVERIFIED
    assert v.reasons == [geo.R_ARBITRATED_COUNTRY_ONLY]
    assert v.country_code == "AU"


def test_ripestat_candidate_is_judged_on_its_coordinates_not_its_country() -> None:
    """At 480 ms Melbourne's own budget (~448 ms) is blown, although the far
    edge of Australia's disc would still admit it. The coordinate check is
    the one used => RIPEstat inconsistent, Canada inconsistent => mismatch."""
    lo, hi = geo.country_distance_range_km("AU", VANTAGE)
    b = geo._RttBounds(rtt=480.0, km_per_ms=100.0, slack_km=300.0, path_factor=2.5, extra_ms=30.0)
    assert b.admits_range(lo, hi)  # the disc alone would have let it through
    assert _assess(rtt_ms=480.0).verdict == LocationVerdict.MISMATCH


def test_agreeing_sources_carry_no_arbitration_marker() -> None:
    v = _assess(peer=_peer(country_code="AU"))
    assert v.verdict == LocationVerdict.VERIFIED
    assert v.reasons == []
    assert v.country_code == ""


def test_an_empty_netbird_country_is_not_a_disagreement() -> None:
    v = _assess(peer=_peer(country_code=""))
    assert v.verdict == LocationVerdict.VERIFIED
    assert v.reasons == []


# ─── the building blocks ──────────────────────────────────────────────


def test_admits_range_is_the_two_bounds_on_an_interval() -> None:
    b = geo._RttBounds(rtt=293.0, km_per_ms=100.0, slack_km=300.0, path_factor=2.5, extra_ms=30.0)
    # floor = (293 - 30) * 100 / 2.5 = 10 520 km; ceiling = 293 * 100 + 300 = 29 600 km
    assert not b.admits_range(0.0, 10_519.0)
    assert b.admits_range(0.0, 10_520.0)
    assert b.admits_range(29_600.0, 40_000.0)
    assert not b.admits_range(29_601.0, 40_000.0)


def test_admits_range_agrees_with_the_point_check() -> None:
    b = geo._RttBounds(rtt=90.0, km_per_ms=100.0, slack_km=300.0, path_factor=2.5, extra_ms=30.0)
    for d in (0.0, 1_000.0, 2_399.0, 2_400.0, 6_000.0, 9_300.0, 9_301.0, 15_000.0):
        assert b.admits_range(d, d) == (b.reasons_at(d) == []), d


def test_country_range() -> None:
    assert geo.country_distance_range_km("ZZ", VANTAGE) is None
    lo, hi = geo.country_distance_range_km("ca", VANTAGE)
    assert 0 <= lo < hi < 10_520  # Canada can never answer in 293 ms from the vantage
    lo, _ = geo.country_distance_range_km("FR", VANTAGE)
    assert lo == 0.0  # the vantage is inside France's disc


# ─── the table ────────────────────────────────────────────────────────

#: The extreme / outlying points each disc was derived from (minimax centre,
#: radius = 1.1 x max distance + 100 km, rounded up to 50 km). Every one must
#: sit inside its country's disc.
EXTREME_POINTS: dict[str, list[tuple[float, float]]] = {
    "FR": [(51.05, 2.37), (43.78, 7.5), (42.44, 3.17), (43.36, -1.78), (48.41, -4.79),
           (41.39, 9.16), (48.97, 8.23)],
    "DE": [(55.05, 8.42), (47.27, 10.18), (51.15, 15.04), (51.05, 5.87), (54.0, 14.2),
           (48.57, 13.45), (47.6, 7.6)],
    "NL": [(53.47, 6.84), (50.75, 5.95), (51.37, 3.36), (53.1, 4.75), (52.3, 7.05)],
    "BE": [(51.5, 4.8), (49.5, 5.8), (51.09, 2.55), (50.3, 6.4)],
    "LU": [(50.18, 6.03), (49.45, 6.37), (49.8, 5.73)],
    # GB outliers: North Rona
    "GB": [(60.86, -0.88), (50.07, -5.71), (52.48, 1.76), (49.9, -6.4), (54.4, -8.2),
           (57.8, -8.6), (51.1, 1.4),
           (59.1, -4.4)],
    "IE": [(55.38, -7.37), (51.45, -9.8), (53.35, -6.0), (53.4, -10.2), (52.2, -6.3)],
    "ES": [(43.79, -7.69), (42.32, 3.32), (36.0, -5.6), (27.64, -18.16), (29.2, -13.4),
           (39.9, 4.3), (35.29, -2.94), (40.4, -3.7)],
    # PT outliers: Selvagens
    "PT": [(42.15, -8.2), (37.0, -8.9), (39.4, -31.3), (32.6, -16.9), (41.5, -6.2),
           (30.14, -15.87)],
    "IT": [(47.09, 12.18), (35.5, 12.6), (40.1, 18.52), (45.8, 6.8), (36.8, 11.9),
           (40.0, 8.4), (45.6, 13.8)],
    "CH": [(47.8, 8.6), (45.8, 9.0), (46.1, 6.0), (46.6, 10.5)],
    "AT": [(49.0, 15.0), (46.4, 14.5), (47.3, 9.5), (48.0, 17.2)],
    "PL": [(54.84, 18.3), (49.0, 22.8), (52.4, 14.1), (54.4, 23.5), (50.2, 24.1),
           (49.4, 19.0)],
    "CZ": [(51.05, 14.3), (48.55, 14.3), (50.25, 12.1), (49.6, 18.85)],
    "SK": [(49.6, 19.4), (47.73, 18.0), (48.4, 17.0), (49.1, 22.56)],
    "HU": [(48.58, 22.1), (45.74, 18.4), (46.9, 16.1), (48.3, 20.0)],
    "RO": [(48.26, 26.7), (43.62, 25.4), (46.0, 20.26), (45.16, 29.7)],
    "BG": [(44.2, 22.7), (41.24, 25.3), (42.5, 22.4), (43.0, 28.6)],
    "GR": [(41.75, 26.3), (34.8, 24.1), (39.8, 19.4), (36.15, 29.6), (40.7, 21.0)],
    "SE": [(69.06, 20.55), (55.34, 13.36), (59.0, 11.2), (65.8, 24.15), (57.9, 19.2)],
    # NO outliers: Svalbard + Jan Mayen (ISO SJ, but GeoLite may label them NO)
    "NO": [(71.18, 25.7), (58.0, 7.0), (69.9, 31.1), (59.0, 5.0), (62.0, 4.8),
           (81.0, 20.3), (80.1, 32.5), (74.4, 19.0), (76.5, 16.5), (71.0, -8.5)],
    "FI": [(70.09, 27.9), (59.8, 22.9), (60.1, 19.5), (62.9, 31.58), (68.5, 20.6)],
    "DK": [(57.75, 10.6), (54.56, 11.2), (55.1, 15.2), (55.6, 8.07)],
    "EE": [(59.7, 26.5), (57.5, 27.35), (58.0, 21.8), (59.4, 28.2)],
    "LV": [(58.08, 25.2), (55.67, 26.6), (56.8, 21.0), (56.4, 28.2)],
    "LT": [(56.45, 24.3), (53.9, 24.0), (55.7, 21.0), (55.2, 26.8)],
    "SI": [(46.88, 16.1), (45.42, 15.0), (46.2, 13.4), (45.5, 13.6)],
    "HR": [(46.55, 16.3), (42.4, 18.5), (45.2, 13.5), (45.2, 19.4), (42.7, 16.9)],
    "RS": [(46.19, 19.9), (42.23, 22.0), (44.9, 18.9), (44.2, 23.0)],
    "UA": [(52.37, 33.2), (44.39, 33.8), (48.4, 22.1), (49.2, 40.2), (45.3, 29.7)],
    "TR": [(42.1, 35.2), (35.8, 36.0), (40.1, 25.7), (39.6, 44.8), (37.0, 44.8)],
    # IS outliers: Grimsey, Surtsey
    "IS": [(66.5, -16.0), (63.4, -18.9), (65.5, -24.5), (65.0, -13.5),
           (66.55, -18.0), (63.3, -20.6)],
    # US outliers: Attu, Kure Atoll
    "US": [(44.8, -66.95), (24.5, -81.8), (32.5, -117.1), (48.4, -124.7), (21.3, -157.9),
           (18.9, -155.7), (22.2, -159.7), (61.2, -149.9), (71.3, -156.8), (51.9, -176.6),
           (55.3, -131.6), (49.0, -95.2),
           (52.9, 172.9), (28.39, -178.29)],
    "CA": [(82.5, -62.3), (47.56, -52.7), (48.4, -123.4), (69.6, -141.0), (41.9, -82.5),
           (69.1, -105.0), (60.7, -135.0), (53.2, -132.5), (45.5, -73.6)],
    # MX outliers: Revillagigedo, Guadalupe
    "MX": [(32.7, -117.1), (14.5, -92.2), (21.5, -86.7), (25.9, -97.5), (22.9, -109.9),
           (31.3, -108.2),
           (18.8, -110.95), (29.0, -118.3)],
    # AU outliers: Macquarie Island
    "AU": [(-10.7, 142.5), (-43.6, 146.8), (-26.2, 113.2), (-28.6, 153.6), (-35.0, 117.9),
           (-12.4, 130.8), (-31.55, 159.08), (-33.87, 151.2),
           (-54.62, 158.86)],
    # NZ outliers: Kermadec, Campbell, Auckland Is.
    "NZ": [(-34.4, 172.7), (-46.6, 168.3), (-47.1, 167.9), (-44.0, -176.5), (-41.3, 174.8),
           (-29.27, -177.92), (-52.55, 169.15), (-50.7, 166.1)],
    # JP outliers: Minami-Torishima, Okinotorishima
    "JP": [(45.52, 141.9), (24.45, 122.9), (26.2, 127.7), (43.3, 145.8), (27.1, 142.2),
           (33.6, 130.4), (35.68, 139.7),
           (24.28, 153.98), (20.42, 136.08)],
    # KR outliers: Dokdo
    "KR": [(38.6, 128.3), (33.2, 126.3), (37.9, 124.7), (37.5, 130.9), (35.1, 129.1),
           (37.24, 131.87)],
    "SG": [(1.47, 103.8), (1.2, 103.6), (1.4, 104.1), (1.26, 103.82)],
    "HK": [(22.56, 114.1), (22.15, 114.0), (22.2, 114.4), (22.4, 113.83)],
    "TW": [(25.3, 121.5), (21.9, 120.85), (22.0, 121.6), (24.4, 118.3), (26.2, 120.0),
           (23.5, 119.5)],
    "IN": [(35.7, 77.1), (8.08, 77.55), (23.7, 68.2), (28.0, 97.4), (6.75, 93.8),
           (10.5, 72.6)],
    # ID outliers: Miangas
    "ID": [(5.9, 95.3), (-9.1, 141.0), (-11.0, 122.9), (4.3, 117.0), (-0.9, 131.2),
           (-2.5, 140.7), (-6.2, 106.8),
           (5.56, 126.58)],
    "MY": [(1.3, 103.5), (6.7, 100.2), (7.4, 116.8), (4.2, 118.6), (1.6, 110.3),
           (3.14, 101.7)],
    "TH": [(20.46, 99.9), (5.6, 101.1), (12.6, 102.4), (15.2, 105.6), (16.0, 98.5),
           (7.8, 98.3)],
    "VN": [(23.4, 105.3), (8.6, 104.7), (10.3, 103.9), (12.3, 109.2), (22.4, 102.2)],
    "PH": [(21.1, 121.9), (4.6, 119.5), (8.4, 117.2), (6.9, 126.6), (18.6, 120.8)],
    "CN": [(53.56, 123.3), (18.2, 109.5), (39.4, 73.5), (48.4, 134.9), (49.2, 87.8),
           (28.3, 85.9), (22.0, 100.0)],
    # BR outliers: Trindade, St Peter and St Paul
    "BR": [(5.27, -60.2), (-33.75, -53.4), (-7.15, -34.8), (-7.5, -73.9), (-3.85, -32.4),
           (-23.55, -46.6),
           (-20.5, -29.3), (0.92, -29.35)],
    "AR": [(-21.8, -66.2), (-55.05, -66.5), (-26.2, -53.6), (-38.0, -71.3), (-54.8, -68.3),
           (-34.6, -58.4)],
    # CL outliers: Diego Ramirez, Salas y Gomez
    "CL": [(-17.5, -69.5), (-55.98, -67.27), (-27.1, -109.4), (-33.6, -78.8),
           (-33.45, -70.65),
           (-56.5, -68.7), (-26.47, -105.36)],
    # CO outliers: Malpelo
    "CO": [(12.46, -71.7), (-4.2, -69.9), (12.58, -81.7), (4.0, -77.5), (6.2, -67.5),
           (4.0, -81.6)],
    "PE": [(-0.04, -75.2), (-18.35, -70.4), (-4.7, -81.3), (-12.5, -68.7)],
    "ZA": [(-22.1, 29.8), (-34.8, 20.0), (-28.6, 16.5), (-26.9, 32.9), (-46.9, 37.7)],
    "AE": [(26.1, 56.2), (22.6, 55.1), (24.0, 51.6), (25.3, 55.4)],
    "IL": [(33.3, 35.6), (29.5, 34.9), (31.2, 34.3), (32.0, 34.8)],
    # RU outliers: Wrangel
    "RU": [(81.8, 59.0), (41.2, 47.8), (54.4, 19.6), (66.1, -169.7), (43.4, 146.9),
           (42.3, 130.7), (69.9, 31.1), (44.4, 33.8), (55.75, 37.6),
           (71.2, -179.5)],
}  # fmt: skip

#: Cities NOT used in the derivation.
KNOWN_CITIES: list[tuple[str, float, float]] = [
    ("AU", -37.81, 144.96),  # Melbourne
    ("AU", -31.95, 115.86),  # Perth
    ("AU", -42.88, 147.33),  # Hobart
    ("CA", 45.50, -73.57),  # Montreal
    ("CA", 43.65, -79.38),  # Toronto
    ("CA", 49.28, -123.12),  # Vancouver
    ("US", 39.04, -77.49),  # Ashburn
    ("US", 37.39, -121.96),  # Santa Clara
    ("US", 21.31, -157.86),  # Honolulu
    ("US", 61.22, -149.90),  # Anchorage
    ("FR", 51.03, 2.38),  # Dunkirk
    ("FR", 48.86, 2.35),  # Paris
    ("FR", 47.75, 7.34),  # Mulhouse
    ("FR", 50.63, 3.06),  # Lille
    ("DE", 50.11, 8.68),  # Frankfurt
    ("DE", 52.52, 13.40),  # Berlin
    ("GB", 51.51, -0.13),  # London
    ("NL", 52.37, 4.90),  # Amsterdam
    ("PL", 52.23, 21.01),  # Warsaw
    ("ES", 28.12, -15.43),  # Las Palmas
    ("PT", 37.74, -25.67),  # Ponta Delgada
    ("SG", 1.29, 103.85),  # Singapore
    ("JP", 35.68, 139.69),  # Tokyo
    ("JP", 26.21, 127.68),  # Naha
    ("IN", 19.08, 72.88),  # Mumbai
    ("BR", -23.55, -46.63),  # São Paulo
    ("CL", -33.45, -70.67),  # Santiago
    ("ZA", -26.20, 28.05),  # Johannesburg
]


def test_every_extreme_point_lies_inside_its_country_disc() -> None:
    assert set(EXTREME_POINTS) == set(geo.COUNTRY_DISCS)
    for cc, points in EXTREME_POINTS.items():
        lat, lon, radius = geo.COUNTRY_DISCS[cc]
        for p in points:
            assert geo.haversine_km(lat, lon, *p) <= radius, (cc, p)


@pytest.mark.parametrize(("cc", "lat", "lon"), KNOWN_CITIES)
def test_known_cities_fall_inside_their_country_range(cc, lat, lon) -> None:
    c_lat, c_lon, radius = geo.COUNTRY_DISCS[cc]
    assert geo.haversine_km(c_lat, c_lon, lat, lon) <= radius
    lo, hi = geo.country_distance_range_km(cc, VANTAGE)
    assert lo <= geo.haversine_km(VANTAGE.latitude, VANTAGE.longitude, lat, lon) <= hi


def test_the_table_covers_where_miners_realistically_are() -> None:
    expected = {
        *("FR", "DE", "NL", "GB", "IE", "ES", "IT", "PL", "SE", "FI", "CH"),
        *("US", "CA", "MX", "BR", "AR", "CL"),
        *("AU", "NZ", "JP", "KR", "SG", "HK", "IN", "ZA", "AE"),
    }
    assert expected <= set(geo.COUNTRY_DISCS)
    for cc, (lat, lon, radius) in geo.COUNTRY_DISCS.items():
        assert len(cc) == 2 and cc.isupper()
        assert geo.valid_coordinates(lat, lon) is not None
        assert 0 < radius <= 5_500  # RU and the US (Hawaii to Attu) are the widest


# ─── RIPEstat ASN fallback ────────────────────────────────────────────

#: Shaped like real RIPEstat answers (2026-09-26), with documentation values.
_GEOLITE = {
    "data": {
        "located_resources": [
            {
                "resource": "49.10.20.1/32",
                "locations": [
                    {
                        "country": "AU",
                        "city": "Melbourne",
                        "resources": ["49.10.16.0/20"],
                        "latitude": -37.8136,
                        "longitude": 144.9631,
                        "covered_percentage": 100.0,
                    }
                ],
            }
        ]
    }
}
_PREFIX_OVERVIEW = {
    "data": {
        "resource": "49.10.0.0/16",
        "announced": True,
        "asns": [{"asn": 64500, "holder": "EXAMPLE-AS Example"}],
    }
}


@pytest.fixture
def ripestat(monkeypatch):
    """Answer `_http_json` by RIPEstat data-call name; record the calls."""
    answers: dict[str, object] = {"maxmind-geo-lite": _GEOLITE}
    calls: list[str] = []

    def fake(url, *, label, headers=None):
        name = url.split("/data/", 1)[1].split("/", 1)[0]
        calls.append(name)
        answer = answers.get(name)
        if isinstance(answer, Exception):
            raise answer
        if answer is None:
            raise AssertionError(f"unexpected RIPEstat call {name}")
        return answer

    monkeypatch.setattr(geo, "_http_json", fake)
    return answers, calls


def test_network_info_without_asn_falls_back_to_prefix_overview(ripestat) -> None:
    answers, calls = ripestat
    answers["network-info"] = {"data": {"asns": [], "prefix": ""}}
    answers["prefix-overview"] = _PREFIX_OVERVIEW
    rec = geo.ripestat_geo("49.10.20.1")
    assert rec is not None
    assert (rec.country_code, rec.city) == ("AU", "Melbourne")
    assert rec.asn == 64500
    assert rec.as_holder == "EXAMPLE-AS Example"
    assert rec.as_prefix == "49.10.0.0/16"
    assert calls == ["maxmind-geo-lite", "network-info", "prefix-overview"]


def test_a_failed_network_info_also_falls_back(ripestat) -> None:
    answers, _ = ripestat
    answers["network-info"] = EffectError("ripestat:asn: HTTP 500")
    answers["prefix-overview"] = _PREFIX_OVERVIEW
    rec = geo.ripestat_geo("49.10.20.1")
    assert rec is not None and rec.asn == 64500 and rec.as_holder == "EXAMPLE-AS Example"


def test_network_info_with_an_asn_uses_as_overview_for_the_holder(ripestat) -> None:
    answers, calls = ripestat
    answers["network-info"] = {"data": {"asns": ["64500"], "prefix": "49.10.0.0/16"}}
    answers["as-overview"] = {"data": {"holder": "EXAMPLE-AS Example"}}
    rec = geo.ripestat_geo("49.10.20.1")
    assert rec is not None
    assert (rec.asn, rec.as_prefix, rec.as_holder) == (64500, "49.10.0.0/16", "EXAMPLE-AS Example")
    assert "prefix-overview" not in calls


def test_every_asn_source_failing_keeps_the_location(ripestat) -> None:
    answers, _ = ripestat
    answers["network-info"] = {"data": {"asns": ["not-a-number"]}}
    answers["prefix-overview"] = EffectUnavailable("ripestat:prefix-overview: timeout")
    rec = geo.ripestat_geo("49.10.20.1")
    assert rec is not None and rec.country_code == "AU"
    assert rec.asn is None and rec.as_holder == ""


def test_a_malformed_prefix_overview_degrades_to_no_asn(ripestat) -> None:
    answers, _ = ripestat
    answers["network-info"] = {"data": {"asns": []}}
    answers["prefix-overview"] = {"data": {"resource": "49.10.0.0/16", "asns": ["64500"]}}
    rec = geo.ripestat_geo("49.10.20.1")
    assert rec is not None and rec.asn is None and rec.as_holder == ""
    assert rec.as_prefix == "49.10.0.0/16"
