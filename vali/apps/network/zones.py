"""Routing zones: the continent-scale groups of countries a public
address may be routed across.

An address is announced by an edge in one country and carried to the VM
over the overlay; within a zone that detour costs a few milliseconds,
across continents it costs a round-trip of a hundred or more and puts
the address's geolocation on the wrong continent. So an attach that
finds nothing in the VM's own country may fall back to another country
of the SAME zone, never further.

A country missing from the map has no zone: it falls back nowhere, and
an edge in it serves only an exact-country match.
"""

from __future__ import annotations

ZONES: dict[str, frozenset[str]] = {
    "EU": frozenset(
        {
            "AT", "BE", "CH", "CZ", "DE", "DK", "ES", "FI", "FR",
            "GB", "IE", "IT", "LU", "NL", "NO", "PL", "PT", "SE",
        }
    ),
    "APAC": frozenset({"AU", "HK", "IN", "JP", "KR", "NZ", "SG"}),
    "NA": frozenset({"CA", "US"}),
}  # fmt: skip

_ZONE_OF: dict[str, str] = {country: zone for zone, cs in ZONES.items() for country in cs}


def zone_of(country: str) -> str:
    """The zone of an ISO 3166-1 alpha-2 code, or `""` when it has none."""
    return _ZONE_OF.get(country.upper(), "")


def countries_in(zone: str) -> frozenset[str]:
    return ZONES.get(zone, frozenset())
