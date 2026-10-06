"""`vali_geo_probe` — detect where every miner is, and how sure we are.

One cycle (`probe_once`), every `VALI_GEO_PROBE_INTERVAL_S`:

1. Read the NetBird peer list ONCE (`geo.fetch_netbird_peers`).
2. For each `MinerIdentity`: match its peer → GeoIP/ASN of the observed
   `connection_ip` (RIPEstat, cached in the row for `VALI_GEO_GEOIP_TTL_S`
   from the moment it ANSWERED) → time a TCP connect to `netbird_ip:9700`
   → collect the egress IPs of the tenant CVMs hosted there → `geo.assess`
   → upsert `MinerLocation`.
3. Log a line per VERDICT CHANGE and one cycle summary; push per-miner
   gauges to the Pushgateway when one is configured.

Fail-soft, per source: a NetBird outage skips the whole cycle (the peer
list is the root of every other lookup, and a stale-but-true row beats a
fresh `unknown` written because an API blinked — consumers age rows out
via `VALI_GEO_MAX_AGE_S` anyway). A RIPEstat or RTT failure degrades that
miner's verdict honestly (`geo-lookup-failed`, `rtt-unavailable`) instead
of aborting the cycle, and one miner raising never starves the rest.
`--once` runs a single cycle for the cron-shaped deployment and for tests.
"""

from __future__ import annotations

import logging
import signal
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from django.conf import settings
from django.core.management.base import BaseCommand
from django.utils import timezone

from apps.lifecycle.models import Vm, VmState
from apps.miners import geo
from apps.miners.models import LocationVerdict, MinerIdentity, MinerLocation
from apps.orchestration.effects import EffectError, EffectUnavailable

log = logging.getLogger("apps.miners.geo_probe")

M_VERIFIED = "hippius_geo_miner_verified"
M_RTT = "hippius_geo_miner_rtt_ms"
M_RUN_TS = "hippius_geo_probe_run_timestamp"


@dataclass
class ProbeReport:
    probed: int = 0
    changed: list[tuple[str, str, str]] = field(default_factory=list)
    skipped_reason: str = ""

    @property
    def skipped(self) -> bool:
        return bool(self.skipped_reason)


def _setting(name: str, default: Any) -> Any:
    return getattr(settings, name, default)


def _cached_geo(
    row: MinerLocation | None, connection_ip: str, now: datetime
) -> geo.GeoRecord | None:
    """Reuse the stored GeoIP answer while the observed IP is unchanged and
    the ANSWER is younger than the TTL — RIPEstat is a public service, not a
    per-cycle dependency. Keyed on `geo_refreshed_at` (when RIPEstat last
    answered), never on `observed_at` (which every cycle rewrites, so a TTL
    on it would never expire); a row whose lookup FAILED has no
    `geo_refreshed_at` and is retried next cycle."""
    if row is None or row.geo_refreshed_at is None or not row.country_code:
        return None
    if row.connection_ip != connection_ip:
        return None
    ttl = geo.positive_setting("VALI_GEO_GEOIP_TTL_S", 86400.0)
    if (now - row.geo_refreshed_at).total_seconds() > ttl:
        return None
    return geo.GeoRecord(
        country_code=row.country_code,
        city=row.city,
        latitude=row.latitude,
        longitude=row.longitude,
        asn=row.asn,
        as_prefix=row.as_prefix,
        as_holder=row.as_holder,
        source="cache",
    )


@dataclass(frozen=True)
class _Cycle:
    """Everything a single miner's probe needs that is shared by the cycle."""

    peers: list[dict[str, Any]]
    guests_by_host: dict[str, list[str]]
    geo_cache: dict[str, geo.GeoRecord | None]
    vantage: geo.Vantage
    now: datetime
    stale_s: float
    km_per_ms: float
    slack_km: float
    samples: int
    rtt_path_factor: float
    rtt_extra_ms: float


def probe_once(now: datetime | None = None) -> ProbeReport:
    """One detection cycle over the whole registry. Kept a module function
    so tests can drive it without the daemon loop."""
    now = now or timezone.now()
    report = ProbeReport()
    try:
        peers = geo.fetch_netbird_peers()
    except (EffectUnavailable, EffectError) as exc:
        report.skipped_reason = f"netbird peer list unavailable: {exc}"
        log.warning("geo-probe: cycle skipped — %s", report.skipped_reason)
        return report

    stale_s = geo.positive_setting("VALI_GEO_PEER_STALE_S", 900.0)
    vm_host_by_vm_id = {
        vm_id: host
        for vm_id, host in Vm.objects.filter(state=VmState.ACTIVE)
        .exclude(host="")
        .values_list("vm_id", "host")
    }
    cycle = _Cycle(
        peers=peers,
        guests_by_host=geo.tenant_peers_by_host(
            peers, vm_host_by_vm_id, now=now, stale_after_s=stale_s
        ),
        geo_cache={},
        vantage=geo.vantage_from_settings(),
        now=now,
        stale_s=stale_s,
        km_per_ms=geo.positive_setting("VALI_GEO_KM_PER_MS", 100.0),
        slack_km=geo.positive_setting("VALI_GEO_SLACK_KM", 300.0, allow_zero=True),
        samples=max(1, int(_setting("VALI_GEO_RTT_SAMPLES", 5))),
        rtt_path_factor=geo.positive_setting("VALI_GEO_RTT_PATH_FACTOR", 2.5),
        rtt_extra_ms=geo.positive_setting("VALI_GEO_RTT_EXTRA_MS", 30.0, allow_zero=True),
    )
    existing = {row.miner_id: row for row in MinerLocation.objects.all()}

    for miner in MinerIdentity.objects.order_by("miner_id"):
        report.probed += 1
        try:
            _probe_miner(miner, existing.get(miner.miner_id), cycle, report)
        except Exception:  # noqa: BLE001 — one miner must not starve the rest.
            log.exception("geo-probe: %s: probe raised — continuing", miner.miner_id)
    log.info("geo-probe: cycle done probed=%d changed=%d", report.probed, len(report.changed))
    return report


def _probe_miner(
    miner: MinerIdentity, row: MinerLocation | None, c: _Cycle, report: ProbeReport
) -> None:
    """Evidence → verdict → row, for ONE miner."""
    peer = geo.match_miner_peer(c.peers, miner.netbird_ip, miner.netbird_peer_id or "")
    connection_ip = peer.get("connection_ip") if peer else None
    if not isinstance(connection_ip, str) or not geo.is_public_ip(connection_ip):
        connection_ip = None

    record: geo.GeoRecord | None = None
    geo_refreshed_at: datetime | None = None
    if connection_ip:
        record = _cached_geo(row, connection_ip, c.now)
        if record is not None:
            geo_refreshed_at = row.geo_refreshed_at  # type: ignore[union-attr]
        else:
            if connection_ip not in c.geo_cache:
                try:
                    c.geo_cache[connection_ip] = geo.ripestat_geo(connection_ip)
                except (EffectUnavailable, EffectError) as exc:
                    log.warning("geo-probe: %s: GeoIP lookup failed: %s", miner.miner_id, exc)
                    c.geo_cache[connection_ip] = None
            record = c.geo_cache[connection_ip]
            # Answered ⇒ the TTL starts now; failed ⇒ left unset so the next
            # cycle asks again instead of trusting a fallback country.
            geo_refreshed_at = c.now if record is not None else None

    rtt_ms = (
        geo.tcp_connect_rtt_ms(str(miner.netbird_ip), samples=c.samples)
        if peer and miner.netbird_ip
        else None
    )
    guest_ips = c.guests_by_host.get(miner.miner_id, [])
    verdict = geo.assess(
        peer=peer,
        geo=record,
        rtt_ms=rtt_ms,
        guest_egress_ips=guest_ips,
        vantage=c.vantage,
        now=c.now,
        km_per_ms=c.km_per_ms,
        slack_km=c.slack_km,
        peer_stale_s=c.stale_s,
        rtt_path_factor=c.rtt_path_factor,
        rtt_extra_ms=c.rtt_extra_ms,
    )
    country = (
        verdict.country_code
        or (record.country_code if record else "")
        or str((peer or {}).get("country_code") or "").upper()[:2]
    )
    # The RTT settled a source disagreement AGAINST the RIPEstat record: its
    # city and coordinates describe the rejected country, so they are not
    # stored — and the row can no longer replay as a cached RIPEstat answer
    # (`_cached_geo` rebuilds one from these columns), so RIPEstat is asked
    # again next cycle.
    place = record if record and record.country_code == country else None
    if record is not None and place is None:
        geo_refreshed_at = None
    previous = row.verdict if row else None
    fields = {
        "connection_ip": connection_ip,
        "country_code": country,
        "city": place.city if place else "",
        "latitude": place.latitude if place else None,
        "longitude": place.longitude if place else None,
        "asn": record.asn if record else None,
        "as_prefix": record.as_prefix if record else "",
        "as_holder": record.as_holder if record else "",
        "rtt_ms": round(rtt_ms, 3) if rtt_ms is not None else None,
        "rtt_vantage": c.vantage.name,
        "guest_egress_ips": guest_ips,
        "verdict": verdict.verdict,
        "verdict_reasons": verdict.reasons,
        "netbird_last_seen_at": geo.parse_netbird_ts((peer or {}).get("last_seen")),
        "geo_refreshed_at": geo_refreshed_at,
        "observed_at": c.now,
        "evidence_json": {
            "peer": (
                {
                    k: peer.get(k)
                    for k in (
                        "id",
                        "name",
                        "ip",
                        "connection_ip",
                        "country_code",
                        "connected",
                        "last_seen",
                        "version",
                    )
                }
                if peer
                else None
            ),
            "geo_source": record.source if record else None,
            # What RIPEstat said, even when the verdict overruled it.
            "geo_country_code": record.country_code if record else None,
            "rtt_samples": c.samples,
        },
    }
    MinerLocation.objects.update_or_create(miner=miner, defaults=fields)
    if previous != verdict.verdict:
        report.changed.append((miner.miner_id, previous or "-", verdict.verdict))
        log.warning(
            "geo-probe: %s verdict %s → %s region=%s connection_ip=%s rtt_ms=%s reasons=%s",
            miner.miner_id,
            previous or "-",
            verdict.verdict,
            country or "??",
            connection_ip,
            fields["rtt_ms"],
            ",".join(verdict.reasons) or "-",
        )


def _push_metrics(now: datetime) -> None:
    """Per-miner gauges to the Pushgateway, when one is configured. Emits a
    sample for EVERY located miner each cycle (an omitted sample would
    linger at its last value). Never raises."""
    gateway = str(_setting("VALI_SYNTHETIC_PUSHGATEWAY_URL", "") or "")
    if not gateway:
        return
    try:
        from apps.synthetic import metrics

        ms = metrics.MetricSet()
        for row in MinerLocation.objects.select_related("miner"):
            labels = {"miner_id": row.miner_id, "region": row.region or "unknown"}
            ms.gauge(
                M_VERIFIED,
                1.0 if row.verdict == LocationVerdict.VERIFIED else 0.0,
                help_text="1 when vali has VERIFIED the miner's detected location.",
                **labels,
            )
            if row.rtt_ms is not None:
                ms.gauge(M_RTT, row.rtt_ms, help_text="Min TCP-connect RTT vali→miner.", **labels)
        ms.gauge(M_RUN_TS, now.timestamp(), help_text="Last geo-probe cycle (unix).")
        metrics.push(ms, gateway_url=gateway, job="geo-probe", grouping_key={}, replace=True)
    except Exception:  # noqa: BLE001 — metrics must never mask the probe.
        log.exception("geo-probe: metrics push failed")


class Command(BaseCommand):
    help = "Detect each miner's geographic location from server-observed evidence (loop)."

    def add_arguments(self, parser: Any) -> None:
        parser.add_argument("--once", action="store_true", help="Run a single cycle and exit.")

    def handle(self, *args: Any, **options: Any) -> None:
        once: bool = options["once"]
        interval = float(_setting("VALI_GEO_PROBE_INTERVAL_S", 600.0))
        self._running = True

        def _stop(signum: int, _frame: Any) -> None:
            self._running = False
            log.info("vali_geo_probe received signal %s — stopping after this cycle", signum)

        signal.signal(signal.SIGTERM, _stop)
        signal.signal(signal.SIGINT, _stop)
        log.info("vali_geo_probe started (interval=%.1fs once=%s)", interval, once)
        while self._running:
            try:
                now = timezone.now()
                report = probe_once(now)
                if not report.skipped:
                    _push_metrics(now)
            except Exception:  # noqa: BLE001 — daemon loop must survive.
                log.exception("geo-probe cycle raised — continuing")
            if once:
                break
            self._sleep(interval)
        log.info("vali_geo_probe stopped")

    def _sleep(self, interval: float) -> None:
        slept = 0.0
        while self._running and slept < interval:
            step = min(0.5, interval - slept)
            time.sleep(step)
            slept += step
