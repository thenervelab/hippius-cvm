"""Miner geolocation — the evidence sources and the verdict.

Nothing here is declared by a miner. Four inputs, each measured by a
party the miner does not control:

1. **Where its traffic comes out.** The NetBird management server records,
   for every peer, the public `connection_ip` it connects FROM and a
   GeoLite `country_code` for it. vali reads the peer list
   (`GET /api/peers`) and matches the miner's peer by its registered peer
   id or its overlay `ip` — the same `MinerIdentity.netbird_ip` every order
   is dispatched to.
2. **What the internet says about that IP.** RIPEstat (public, key-free)
   gives the GeoLite city/country + coordinates, the announcing ASN, its
   prefix and holder. A second GeoIP opinion on the same IP (same MaxMind
   lineage — a sanity check, not an independent witness).
3. **How far away it physically is.** A TCP connect from the probe pod to
   `netbird_ip:9700` is timed. Light in fibre covers roughly 100 km per
   millisecond of round-trip, which bounds the location BOTH ways: the IP
   cannot geolocate farther than the RTT could cover (faster than light),
   and a location claimed NEAR the vantage must answer with a NEAR
   round-trip — a host on another continent tunnelling through a nearby
   VPN exit still has to carry every packet to where it really is. A
   tunnel can only ADD latency; it cannot remove it.
4. **Where its tenants come out.** Every tenant CVM is a NetBird peer too,
   from inside the attested guest. Its `connection_ip` is the host's NAT
   egress as the GUEST experiences it. It must equal the host's own
   `connection_ip`; if the host tunnels guest traffic elsewhere, they differ.

`assess()` folds those into a `LocationVerdict` — pure, so the matrix is
unit-tested without a network. The HTTP helpers follow the house style
(`apps.orchestration.effects._http`: stdlib urllib, label in errors, URL
never logged, `EffectUnavailable` only on transport failure).
"""

from __future__ import annotations

import ipaddress
import json
import logging
import math
import socket
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from django.conf import settings

from apps.orchestration.effects import EffectError, EffectUnavailable

from .models import LocationVerdict

log = logging.getLogger("apps.miners.geo")

#: The miner-agent orders listener — the port every order is dispatched to,
#: so a connect to it proves the SAME path the control plane uses.
MINER_ORDERS_PORT = 9700
#: NetBird names a tenant VM's peer after its per-VM setup key
#: (`effects.mint_netbird_setup_key`) — the stable association anchor.
TENANT_PEER_PREFIX = "hippius-tenant-"

# Verdict reason codes (stable — surfaced on the operator API).
R_NO_PEER = "no-netbird-peer"
R_NO_PUBLIC_IP = "no-public-connection-ip"
R_GEO_FAILED = "geo-lookup-failed"
R_SOURCE_DISAGREE = "geo-source-disagree"
R_GUEST_MISMATCH = "guest-egress-mismatch"
R_PEER_STALE = "peer-stale"
R_RTT_UNAVAILABLE = "rtt-unavailable"
#: The IP geolocates FARTHER than the RTT permits — impossible (faster than light).
R_LATENCY = "latency-inconsistent"
#: The RTT is far LONGER than the claimed location warrants — the packets are
#: answered from somewhere else (a tunnel to a nearby exit, a relay).
R_RTT_TOO_HIGH = "rtt-exceeds-claimed-distance"
#: The two GeoIP sources disagreed and the RTT settled it in favour of the
#: RIPEstat record (the one with coordinates), which then passed every
#: check. INFORMATIONAL — it never downgrades a verdict (`NOTE_REASONS`).
R_RTT_ARBITRATED = "geo-rtt-arbitrated"
#: The sources disagreed and the RTT settled it in favour of the NetBird
#: country — which carries no coordinates, only a country-sized disc, so it
#: cannot be bounded tightly enough to verify.
R_ARBITRATED_COUNTRY_ONLY = "geo-rtt-arbitrated-country-only"
#: Reason codes that explain a verdict without lowering it.
NOTE_REASONS = frozenset({R_RTT_ARBITRATED})


@dataclass(frozen=True)
class GeoRecord:
    """What the internet says about one public IP."""

    country_code: str = ""
    city: str = ""
    latitude: float | None = None
    longitude: float | None = None
    asn: int | None = None
    as_prefix: str = ""
    as_holder: str = ""
    source: str = "ripestat"

    @property
    def has_coordinates(self) -> bool:
        return valid_coordinates(self.latitude, self.longitude) is not None


@dataclass(frozen=True)
class Vantage:
    name: str
    latitude: float
    longitude: float


@dataclass(frozen=True)
class Verdict:
    verdict: str
    reasons: list[str] = field(default_factory=list)
    #: The country the verdict is ABOUT when the RTT had to pick between
    #: disagreeing sources — the one to persist. Empty otherwise (the caller
    #: keeps its usual RIPEstat-then-NetBird choice).
    country_code: str = ""


# ─── helpers ──────────────────────────────────────────────────────────


def is_public_ip(value: str | None) -> bool:
    """A routable public unicast address — the only kind GeoIP means
    anything for. CGNAT (`100.64/10`, the NetBird overlay itself) must be
    excluded — it is not `is_private`, only not `is_global`."""
    if not value:
        return False
    try:
        ip = ipaddress.ip_address(str(value).strip())
    except ValueError:
        return False
    # `is_global` is the registry-backed predicate: it excludes private,
    # loopback, link-local, reserved, unspecified AND the shared address
    # space 100.64/10 (RFC 6598) — which `is_private` does NOT. It still
    # admits global-scope multicast and IPv4-mapped forms, hence the rest.
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    if ip.is_multicast or ip.is_link_local or ip.is_loopback or ip.is_unspecified:
        return False
    if isinstance(ip, ipaddress.IPv6Address) and ip.is_site_local:
        return False
    return bool(ip.is_global)


def _normalize_ip(value: Any) -> str:
    try:
        return str(ipaddress.ip_address(str(value).strip()))
    except ValueError:
        return ""


def _finite(value: Any) -> float | None:
    try:
        f = float(value)
    except (TypeError, ValueError):
        return None
    return f if math.isfinite(f) else None


def valid_coordinates(lat: Any, lon: Any) -> tuple[float, float] | None:
    """Finite and in range, or nothing — a NaN latitude must not satisfy a
    `distance > bound` comparison by making it False."""
    la, lo = _finite(lat), _finite(lon)
    if la is None or lo is None or not (-90.0 <= la <= 90.0) or not (-180.0 <= lo <= 180.0):
        return None
    return la, lo


def haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Great-circle distance in km (mean Earth radius 6371 km)."""
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dphi = p2 - p1
    dlmb = math.radians(lon2 - lon1)
    a = math.sin(dphi / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dlmb / 2) ** 2
    return 2 * 6371.0 * math.asin(min(1.0, math.sqrt(a)))


def parse_netbird_ts(value: Any) -> datetime | None:
    """NetBird timestamps carry nanoseconds (`…59.812376277Z`), which
    `fromisoformat` rejects — trim to microseconds."""
    if not isinstance(value, str) or not value:
        return None
    s = value.strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    if "." in s:
        head, _, tail = s.partition(".")
        frac = ""
        rest = ""
        for i, ch in enumerate(tail):
            if ch.isdigit():
                frac += ch
            else:
                rest = tail[i:]
                break
        s = f"{head}.{(frac + '000000')[:6]}{rest}"
    try:
        parsed = datetime.fromisoformat(s)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed


def _timeout() -> float:
    return float(getattr(settings, "VALI_GEO_HTTP_TIMEOUT_S", 10.0))


def _http_json(url: str, *, label: str, headers: dict[str, str] | None = None) -> Any:
    """One GET returning parsed JSON. Raises `EffectUnavailable` on a
    transport failure and `EffectError` on a non-2xx or non-JSON body.
    The URL is never placed in an exception or a log line."""
    request = urllib.request.Request(url, headers=dict(headers or {}), method="GET")
    try:
        with urllib.request.urlopen(request, timeout=_timeout()) as resp:  # noqa: S310
            status, body = resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        status, body = exc.code, b""
    except (urllib.error.URLError, OSError, TimeoutError) as exc:
        raise EffectUnavailable(f"{label}: peer unreachable ({exc})") from exc
    if not 200 <= status < 300:
        raise EffectError(f"{label}: HTTP {status}")
    try:
        return json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as exc:
        raise EffectError(f"{label}: non-JSON response") from exc


def _required_setting(name: str) -> str:
    value = str(getattr(settings, name, "") or "").strip()
    if not value:
        raise EffectUnavailable(f"{name} is not configured")
    return value


# ─── source 1: NetBird management ─────────────────────────────────────


def fetch_netbird_peers() -> list[dict[str, Any]]:
    """The whole peer list, ONCE per cycle (the miners AND their tenants
    come from the same call). Same auth + error discipline as
    `effects._resolve_netbird_peer`."""
    base = _required_setting("VALI_NETBIRD_API_BASE").rstrip("/")
    token = _required_setting("VALI_NETBIRD_API_TOKEN")
    peers = _http_json(
        f"{base}/api/peers",
        label="netbird:list-peers",
        headers={"Authorization": f"Token {token}"},
    )
    if not isinstance(peers, list):
        raise EffectError("netbird:list-peers: expected a JSON list")
    return [p for p in peers if isinstance(p, dict)]


def peer_is_fresh(peer: dict[str, Any], *, now: datetime, stale_after_s: float) -> bool:
    """Is the management server's record of this peer CURRENT?

    NetBird's `last_seen` is the time of the peer's last (re)connection,
    not a heartbeat — a peer that has stayed connected for a week carries a
    week-old `last_seen` while `connected` is true (observed live 2026-09-22:
    three miners at 4–9 ms RTT flagged `peer-stale`). So `connected` is the
    liveness signal; `last_seen` only bounds how old a DISCONNECTED record
    may be before its `connection_ip` is treated as history."""
    if bool(peer.get("connected")):
        return True
    seen = parse_netbird_ts(peer.get("last_seen"))
    return seen is not None and (now - seen).total_seconds() <= stale_after_s


def match_miner_peer(
    peers: list[dict[str, Any]], netbird_ip: str | None, netbird_peer_id: str = ""
) -> dict[str, Any] | None:
    """The miner's own peer. Matched on the registered NetBird peer `id`
    when the operator recorded one, else on the overlay `ip` every order is
    dispatched to (miner peers are enrolled by Ansible with the machine
    hostname, so `name` is not a stable anchor). Prefer a connected peer if
    the address was ever re-assigned."""
    if netbird_peer_id:
        by_id = [p for p in peers if p.get("id") == netbird_peer_id]
        if by_id:
            return by_id[0]
    ip_norm = _normalize_ip(netbird_ip) if netbird_ip else ""
    if not ip_norm:
        return None
    matches = [p for p in peers if _normalize_ip(p.get("ip")) == ip_norm]
    if not matches:
        return None
    matches.sort(key=lambda p: bool(p.get("connected")), reverse=True)
    return matches[0]


def tenant_peers_by_host(
    peers: list[dict[str, Any]],
    vm_host_by_vm_id: dict[str, str],
    *,
    now: datetime,
    stale_after_s: float,
) -> dict[str, list[str]]:
    """`{miner_id: [connection_ip, …]}` for the tenant CVMs hosted on each
    miner whose NetBird peer has checked in recently. Peers with no public
    `connection_ip` are ignored (they say nothing about egress)."""
    out: dict[str, list[str]] = {}
    for p in peers:
        name = p.get("name")
        if not isinstance(name, str) or not name.startswith(TENANT_PEER_PREFIX):
            continue
        host = vm_host_by_vm_id.get(name[len(TENANT_PEER_PREFIX) :])
        if not host:
            continue
        if not peer_is_fresh(p, now=now, stale_after_s=stale_after_s):
            continue
        ip = p.get("connection_ip")
        if isinstance(ip, str) and is_public_ip(ip):
            out.setdefault(host, []).append(_normalize_ip(ip))
    return {k: sorted(set(v)) for k, v in out.items()}


# ─── source 2: RIPEstat ───────────────────────────────────────────────


def ripestat_geo(ip: str) -> GeoRecord | None:
    """GeoLite location + ASN for a public IP via RIPEstat's data API.
    Returns `None` when the IP is not public or RIPEstat has no location
    for it. Partial answers are fine: the ASN half failing does not throw
    away the location half. Every shape is checked — a 2xx with an
    unexpected body must degrade, not raise into the cycle."""
    if not is_public_ip(ip):
        return None
    base = str(getattr(settings, "VALI_GEO_RIPESTAT_BASE", "https://stat.ripe.net")).rstrip("/")
    q = urllib.parse.quote(ip, safe="")
    geo = _http_json(f"{base}/data/maxmind-geo-lite/data.json?resource={q}", label="ripestat:geo")
    country = city = ""
    lat = lon = None
    data = geo.get("data") if isinstance(geo, dict) else None
    resources = data.get("located_resources") if isinstance(data, dict) else None
    for res in resources if isinstance(resources, list) else []:
        locations = res.get("locations") if isinstance(res, dict) else None
        for loc in locations if isinstance(locations, list) else []:
            if not isinstance(loc, dict):
                continue
            country = str(loc.get("country") or "").upper()[:2]
            city = str(loc.get("city") or "")[:64]
            coords = valid_coordinates(loc.get("latitude"), loc.get("longitude"))
            lat, lon = coords if coords else (None, None)
            break
        if country:
            break
    if len(country) != 2 or not country.isalpha():
        return None
    asn, prefix = _ripestat_network_info(base, q)
    if asn is None:
        # network-info sometimes answers `asns: []` (seen live for an
        # APNIC-routed hosting-provider range) — prefix-overview names the
        # announcing AS and its holder in one call.
        asn, overview_prefix, holder = _ripestat_prefix_overview(base, q)
        prefix = prefix or overview_prefix
    else:
        holder = _ripestat_as_holder(base, asn)
    return GeoRecord(
        country_code=country,
        city=city,
        latitude=lat,
        longitude=lon,
        asn=asn,
        as_prefix=prefix,
        as_holder=holder,
    )


def _asn(value: Any) -> int | None:
    """A 32-bit ASN from an int or a numeric string, else `None`."""
    try:
        candidate = int(str(value).strip().upper().removeprefix("AS"))
    except (TypeError, ValueError):
        return None
    return candidate if 0 < candidate < 2**32 else None


def _ripestat_data(url: str, *, label: str) -> dict[str, Any]:
    doc = _http_json(url, label=label)
    data = doc.get("data") if isinstance(doc, dict) else None
    return data if isinstance(data, dict) else {}


def _ripestat_network_info(base: str, q: str) -> tuple[int | None, str]:
    """`network-info`: `{"asns": ["64500"], "prefix": "203.0.113.0/24"}`
    → `(asn, prefix)`. Never raises — the ASN is enrichment."""
    try:
        net = _ripestat_data(
            f"{base}/data/network-info/data.json?resource={q}", label="ripestat:asn"
        )
    except EffectError as exc:
        log.warning("ripestat: network-info failed: %s", exc)
        return None, ""
    asns = net.get("asns")
    asn = _asn(asns[0]) if isinstance(asns, list) and asns else None
    return asn, str(net.get("prefix") or "")[:64]


def _ripestat_prefix_overview(base: str, q: str) -> tuple[int | None, str, str]:
    """`prefix-overview`: `{"resource": "203.0.113.0/24", "asns": [{"asn":
    64500, "holder": "EXAMPLE-AS Example Hosting"}], …}`. Never raises."""
    try:
        over = _ripestat_data(
            f"{base}/data/prefix-overview/data.json?resource={q}", label="ripestat:prefix-overview"
        )
    except EffectError as exc:
        log.warning("ripestat: prefix-overview failed: %s", exc)
        return None, "", ""
    prefix = str(over.get("resource") or "")[:64]
    asns = over.get("asns")
    first = asns[0] if isinstance(asns, list) and asns and isinstance(asns[0], dict) else {}
    asn = _asn(first.get("asn"))
    holder = str(first.get("holder") or "")[:128] if asn is not None else ""
    return asn, prefix, holder


def _ripestat_as_holder(base: str, asn: int) -> str:
    """`as-overview` → `holder`. Never raises."""
    try:
        over = _ripestat_data(
            f"{base}/data/as-overview/data.json?resource=AS{asn}", label="ripestat:as-overview"
        )
    except EffectError as exc:
        log.warning("ripestat: as-overview failed: %s", exc)
        return ""
    return str(over.get("holder") or "")[:128]


# ─── source 3: latency ────────────────────────────────────────────────


def tcp_connect_rtt_ms(
    host: str, port: int = MINER_ORDERS_PORT, *, samples: int = 5, timeout_s: float = 3.0
) -> float | None:
    """Minimum TCP-connect time over `samples` attempts, in ms — `None`
    when no attempt connected. Connect-only: the socket is closed before a
    byte is sent, so the miner's mTLS listener sees a handshake-less
    connection and nothing else."""
    best: float | None = None
    for _ in range(max(1, samples)):
        t0 = time.perf_counter()
        try:
            with socket.create_connection((host, port), timeout=timeout_s):
                pass
        except OSError:
            continue
        ms = (time.perf_counter() - t0) * 1000.0
        best = ms if best is None else min(best, ms)
    return best


# ─── country extents (for arbitrating disagreeing sources) ────────────

#: `country → (lat, lon, radius_km)`: a disc meant to CONTAIN the country
#: as GeoLite labels it — including the outlying islands that carry the same
#: ISO code (Hawaii + Kure + Attu for US, the Canaries for ES, the Azores +
#: Selvagens for PT, Easter Island + Salas y Gómez for CL, Lord Howe +
#: Macquarie for AU, Chatham + Kermadec + Campbell for NZ, Minami-Torishima
#: for JP, Trindade for BR …), plus Svalbard + Jan Mayen for NO in case
#: GeoLite labels them NO rather than SJ — but not territories GeoLite codes
#: separately (GF, RE, GL, PR, GU …). Derivation: for each country the list of its extreme points
#: (`EXTREME_POINTS` in `tests/test_geo_arbitration.py`, which pins every
#: one inside its disc), the minimax centre over them, and a radius of
#: `1.1 × max distance + 100 km`, rounded UP to 50 km. An outlier missing
#: from that list is a bug: fix it there and re-derive.
#:
#: Too BIG is the safe direction. A disc only ever answers "could the RTT
#: have come from somewhere in this country?"; an oversized disc makes that
#: "yes" more often, so more disagreements stay `mismatch`. An undersized
#: one could wrongly rule a country out — which is why the radii are padded
#: and a test pins every extreme point inside its disc. A country NOT in
#: the table cannot be ruled in or out, so arbitration refuses (fail closed).
COUNTRY_DISCS: dict[str, tuple[float, float, float]] = {
    "FR": (45.5, 3.0, 850),
    "DE": (51.2, 9.7, 600),
    "NL": (52.2, 5.4, 300),
    "BE": (50.4, 4.4, 300),
    "LU": (49.8, 6.0, 200),
    "GB": (55.0, -1.6, 850),
    "IE": (53.2, -7.9, 400),
    "ES": (35.1, -8.0, 1500),
    "PT": (39.6, -18.8, 1300),
    "IT": (41.5, 12.6, 850),
    "CH": (46.3, 8.2, 300),
    "AT": (47.5, 13.4, 450),
    "PL": (51.8, 19.6, 550),
    "CZ": (50.0, 15.5, 400),
    "SK": (48.8, 19.8, 350),
    "HU": (47.9, 19.0, 400),
    "RO": (45.6, 25.0, 550),
    "BG": (43.1, 25.4, 400),
    "GR": (38.7, 25.0, 650),
    "SE": (62.0, 18.2, 1000),
    "NO": (69.9, 7.6, 1600),
    "FI": (64.5, 26.9, 800),
    "DK": (55.8, 11.8, 400),
    "EE": (58.7, 25.0, 350),
    "LV": (56.7, 24.6, 350),
    "LT": (55.3, 23.9, 350),
    "SI": (46.2, 14.9, 250),
    "HR": (44.2, 16.5, 400),
    "RS": (44.0, 20.2, 400),
    "UA": (49.3, 31.1, 850),
    "TR": (40.4, 35.9, 1100),
    "IS": (65.2, -19.0, 400),
    "US": (43.7, -128.0, 5350),
    "CA": (61.6, -88.5, 3150),
    "MX": (25.9, -102.1, 1950),
    "AU": (-34.6, 139.5, 3100),
    "NZ": (-41.8, 179.1, 1700),
    "JP": (30.6, 138.5, 2000),
    "KR": (36.1, 128.1, 500),
    "SG": (1.2, 103.9, 150),
    "HK": (22.3, 114.1, 150),
    "TW": (24.0, 120.5, 400),
    "IN": (20.5, 84.4, 2150),
    "ID": (-1.9, 118.0, 3050),
    "MY": (6.1, 109.5, 1250),
    "TH": (13.0, 100.1, 1050),
    "VN": (16.0, 105.0, 1050),
    "PH": (12.8, 121.4, 1150),
    "CN": (40.8, 103.9, 2950),
    "BR": (-10.4, -50.2, 3000),
    "AR": (-38.4, -66.2, 2150),
    "CL": (-36.2, -84.5, 2950),
    "CO": (4.0, -76.1, 1400),
    "PE": (-9.5, -74.0, 1300),
    "ZA": (-35.2, 29.9, 1750),
    "AE": (24.8, 54.1, 400),
    "IL": (31.4, 35.4, 350),
    "RU": (64.4, 91.3, 4650),
}


def country_distance_range_km(country_code: str, vantage: Vantage) -> tuple[float, float] | None:
    """`[min, max]` great-circle distance from the vantage to any point of
    the country's disc, or `None` for a country not in `COUNTRY_DISCS`."""
    disc = COUNTRY_DISCS.get(country_code.upper())
    if disc is None:
        return None
    lat, lon, radius = disc
    d = haversine_km(vantage.latitude, vantage.longitude, lat, lon)
    return max(0.0, d - radius), d + radius


@dataclass(frozen=True)
class _RttBounds:
    """What one RTT sample permits about the distance to the answerer.

    (a) Faster than light: `distance <= rtt × km_per_ms + slack_km`.
    (b) Not slower than the distance warrants:
        `rtt <= distance / km_per_ms × path_factor + extra_ms`.
    """

    rtt: float
    km_per_ms: float
    slack_km: float
    path_factor: float
    extra_ms: float

    def reasons_at(self, distance: float) -> list[str]:
        reasons: list[str] = []
        # (a) Faster than light: the IP geolocates farther than the RTT
        #     could possibly cover. Catches "claims far, answers near".
        if distance > self.rtt * self.km_per_ms + self.slack_km:
            reasons.append(R_LATENCY)
        # (b) Slower than the claim warrants: a NEARBY location must answer
        #     with a NEARBY round-trip. Real paths wander (~path_factor ×
        #     great-circle) and queue (+ extra_ms), but a host on another
        #     continent tunnelling through a nearby VPN exit cannot get
        #     under this — the packets still travel to where it really is.
        #     Catches "claims near, answers far": the VPN case.
        budget_ms = (distance / self.km_per_ms) * self.path_factor + self.extra_ms
        if self.rtt > budget_ms:
            reasons.append(R_RTT_TOO_HIGH)
        return reasons

    def admits_range(self, lo_km: float, hi_km: float) -> bool:
        """Does SOME distance in `[lo_km, hi_km]` satisfy both (a) and (b)?
        (a) caps the distance from above, (b) floors it from below."""
        ceiling = self.rtt * self.km_per_ms + self.slack_km
        floor = (self.rtt - self.extra_ms) * self.km_per_ms / self.path_factor
        return max(lo_km, floor) <= min(hi_km, ceiling)


def _candidate_consistent(
    country_code: str, coords: tuple[float, float] | None, vantage: Vantage, bounds: _RttBounds
) -> bool | None:
    """Is this candidate location RTT-consistent? `None` = cannot tell (a
    country-only candidate absent from `COUNTRY_DISCS`)."""
    if coords is not None:
        distance = haversine_km(vantage.latitude, vantage.longitude, *coords)
        return not bounds.reasons_at(distance)
    extent = country_distance_range_km(country_code, vantage)
    if extent is None:
        return None
    return bounds.admits_range(*extent)


def _arbitrate(
    peer_cc: str, geo: GeoRecord, vantage: Vantage, bounds: _RttBounds
) -> tuple[str, bool] | None:
    """The two GeoIP sources name different countries for the same IP; the
    RTT picks one. Returns `(country, bounded_by_coordinates)` when EXACTLY
    one candidate is RTT-consistent, else `None` (both consistent, neither,
    or one that cannot be judged — all "cannot arbitrate", fail closed).

    What a miner can steer: both opinions are about the IP it connects
    from, and the RTT can only be inflated (delayed SYN-ACKs), never
    shortened. So it can make a FARTHER candidate win, never a nearer one
    it is not near — the same residual as today's "claim a far region on an
    IP the GeoIP already puts there", now reachable when only RIPEstat's
    GeoLite puts it there (NetBird's is the same MaxMind lineage, so it was
    never an independent witness). Whatever wins still faces every check
    `assess` applies.
    """
    ripe_coords = valid_coordinates(geo.latitude, geo.longitude)
    ripe_ok = _candidate_consistent(geo.country_code, ripe_coords, vantage, bounds)
    peer_ok = _candidate_consistent(peer_cc, None, vantage, bounds)
    if ripe_ok is None or peer_ok is None or ripe_ok == peer_ok:
        return None
    if ripe_ok:
        return geo.country_code, ripe_coords is not None
    return peer_cc, False


# ─── the verdict ──────────────────────────────────────────────────────


def assess(
    *,
    peer: dict[str, Any] | None,
    geo: GeoRecord | None,
    rtt_ms: float | None,
    guest_egress_ips: list[str],
    vantage: Vantage,
    now: datetime,
    km_per_ms: float,
    slack_km: float,
    peer_stale_s: float,
    rtt_path_factor: float = 2.5,
    rtt_extra_ms: float = 30.0,
) -> Verdict:
    """Fold the evidence into a `LocationVerdict`. Pure.

    Order matters: contradictions (`mismatch`) win over missing checks
    (`unverified`), because a contradiction is a statement about the miner
    while a missing sample is a statement about the probe. The tenant
    egress contradiction is never arbitrated away. Two GeoIP sources that
    disagree ARE, when the RTT rules exactly one of them out (`_arbitrate`):
    a hosting provider's range registered to its Canadian entity but routed
    in Australia, so NetBird's GeoLite said CA while RIPEstat said AU — at
    293 ms from a European vantage point,
    where Canada is at most ~100 ms.
    """
    if peer is None:
        return Verdict(LocationVerdict.UNKNOWN, [R_NO_PEER])
    connection_ip = peer.get("connection_ip")
    if not isinstance(connection_ip, str) or not is_public_ip(connection_ip):
        return Verdict(LocationVerdict.UNKNOWN, [R_NO_PUBLIC_IP])
    if geo is None or not geo.country_code:
        return Verdict(LocationVerdict.UNKNOWN, [R_GEO_FAILED])

    peer_cc = str(peer.get("country_code") or "").upper()
    disagree = bool(peer_cc) and peer_cc != geo.country_code
    host_ip = _normalize_ip(connection_ip)
    if any(_normalize_ip(ip) != host_ip for ip in guest_egress_ips):
        return Verdict(
            LocationVerdict.MISMATCH,
            ([R_SOURCE_DISAGREE] if disagree else []) + [R_GUEST_MISMATCH],
        )

    rtt = _finite(rtt_ms)
    if rtt is not None and rtt < 0:
        rtt = None
    bounds = (
        _RttBounds(rtt, km_per_ms, slack_km, rtt_path_factor, rtt_extra_ms)
        if rtt is not None
        else None
    )
    stale = [] if peer_is_fresh(peer, now=now, stale_after_s=peer_stale_s) else [R_PEER_STALE]

    notes: list[str] = []
    country = ""
    if disagree:
        winner = _arbitrate(peer_cc, geo, vantage, bounds) if bounds is not None else None
        if winner is None:
            return Verdict(LocationVerdict.MISMATCH, [R_SOURCE_DISAGREE])
        country, bounded = winner
        if not bounded:
            # A country-sized disc is all that places this candidate. Good
            # enough to RULE a country out, never to vouch for one: inside a
            # large country, (b) is satisfied by its far edge, so a tunnel
            # from anywhere in it would pass. Stored, never verified.
            return Verdict(LocationVerdict.UNVERIFIED, [R_ARBITRATED_COUNTRY_ONLY, *stale], country)
        notes.append(R_RTT_ARBITRATED)

    reasons: list[str] = list(stale)
    coords = valid_coordinates(geo.latitude, geo.longitude)
    if bounds is None:
        reasons.append(R_RTT_UNAVAILABLE)
    elif coords is None:
        # A country with no coordinates cannot be bounded — not verified.
        reasons.append(R_LATENCY)
    else:
        reasons.extend(
            bounds.reasons_at(haversine_km(vantage.latitude, vantage.longitude, *coords))
        )
    all_reasons = reasons + notes
    lowering = [r for r in all_reasons if r not in NOTE_REASONS]
    verdict = LocationVerdict.UNVERIFIED if lowering else LocationVerdict.VERIFIED
    return Verdict(verdict, all_reasons, country)


def positive_setting(name: str, default: float, *, allow_zero: bool = False) -> float:
    """A numeric knob that must be finite and positive (or non-negative)
    — `nan` / `inf` / a negative value in the environment would otherwise
    make every comparison in `assess` come out `verified`. Falls back to
    the default, loudly."""
    raw = getattr(settings, name, default)
    value = _finite(raw)
    if value is None or value < 0 or (value == 0 and not allow_zero):
        log.error(
            "geo: setting %s=%r is not a finite positive number — using %r", name, raw, default
        )
        return float(default)
    return value


def vantage_from_settings() -> Vantage:
    """Where the RTT is measured from. Invalid coordinates fall back to
    (0, 0) in the Gulf of Guinea — every real miner is then thousands of
    km away and fails the RTT budget, i.e. the misconfiguration is loud
    and fail-closed rather than silently permissive."""
    coords = valid_coordinates(
        getattr(settings, "VALI_GEO_VANTAGE_LAT", None),
        getattr(settings, "VALI_GEO_VANTAGE_LON", None),
    )
    if coords is None:
        log.error("geo: VALI_GEO_VANTAGE_LAT/LON are not valid coordinates — using 0,0")
        coords = (0.0, 0.0)
    return Vantage(
        name=str(getattr(settings, "VALI_GEO_VANTAGE_NAME", "vali")),
        latitude=coords[0],
        longitude=coords[1],
    )


def geo_require_verified() -> bool:
    return bool(getattr(settings, "VALI_GEO_REQUIRE_VERIFIED", True))


def placeable_locations(*, now: datetime | None = None, verified_only: bool | None = None):
    """The `MinerLocation` rows a consumer (the scheduler's region gate,
    `GET /v1/operator/regions`) may treat as "this miner IS in that
    region". One rule, shared, so the regions API never advertises a miner
    the gate would refuse:

    - a country is known and the miner is scheduler-bridged;
    - the row is FRESH — `observed_at` within `VALI_GEO_MAX_AGE_S`. A probe
      that stopped running, or a miner that vanished from NetBird, must not
      leave a `verified` verdict standing forever;
    - the verdict is `verified`; with `verified_only=False` (or
      `VALI_GEO_REQUIRE_VERIFIED=False`) `unverified` rows join it. Never
      `mismatch` (a contradiction) and never `unknown` (no country anyway).
    """
    from django.utils import timezone

    from .models import MinerLocation

    if verified_only is None:
        verified_only = geo_require_verified()
    now = now or timezone.now()
    max_age = positive_setting("VALI_GEO_MAX_AGE_S", 7200.0)
    verdicts = [LocationVerdict.VERIFIED]
    if not verified_only:
        verdicts.append(LocationVerdict.UNVERIFIED)
    return (
        MinerLocation.objects.filter(miner__chain_node_id__isnull=False)
        .exclude(country_code="")
        .filter(observed_at__gte=now - timedelta(seconds=max_age), verdict__in=verdicts)
    )
