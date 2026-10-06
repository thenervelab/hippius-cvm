# Design: Detected miner geolocation, region-constrained placement

**Status:** Implemented (PR-A detection + operator API; PR-B scheduler gate) · **Date:** 2026-09-22

## 1. Goal

Know where each miner physically is, let a launch ask for a region, and give
the layer above a read-only view of the regions that have miners with
capacity — **without a single declared value**. A miner asserts nothing
about its location; everything below is measured by a party the miner does
not control, or bounded by physics.

The trust question underneath: *how do we know the miner is not behind a
VPN?* GeoIP alone cannot answer it — a VPN exit inside a hosting
provider's range looks exactly like a server of that provider. Latency can: a tunnel only ever ADDS round-trip
time, so an exit that geolocates farther than the measured RTT permits is a
lie.

## 2. Evidence sources (`vali/apps/miners/geo.py`)

| # | Source | What it gives | Who controls it |
|---|---|---|---|
| 1 | NetBird management API, `GET /api/peers` | for the miner's peer (matched by overlay `ip == MinerIdentity.netbird_ip`): `connection_ip` — the public IP the peer connects FROM — and a GeoLite `country_code` | the management server (ours), observing the TCP/WireGuard endpoint |
| 2 | RIPEstat data API (public, key-free) | GeoLite country/city/lat/lon of `connection_ip`, announcing ASN, prefix, holder | RIPE NCC |
| 3 | TCP connect from the probe pod to `netbird_ip:9700`, min of N samples | round-trip time, checked BOTH ways: the IP may not geolocate farther than `rtt × 100 km + slack` (faster than light), and a location claimed near the vantage must answer within `distance/100 km × 2.5 + 30 ms` (a far host behind a near VPN exit cannot) | physics |
| 4 | The tenant CVMs' own NetBird peers (`hippius-tenant-<vm_id>`), joined to `Vm.host` | the host's NAT egress IP *as the attested guest experiences it* | the guest (measured image) + the management server |

Example values: miners 198.51.100.10 / 198.51.100.20 / 198.51.100.30, all
in the same country as the vantage, AS64500, 9.0 / 9.5 / 4.0 ms from the
control plane.

## 3. The verdict (`geo.assess`, pure)

| verdict | when |
|---|---|
| `unknown` | no peer matched, no public `connection_ip`, or GeoIP failed |
| `mismatch` | a tenant CVM on this host egresses from a different public IP (`guest-egress-mismatch`) or the two GeoIP sources disagree on the country and the RTT cannot settle it (`geo-source-disagree`, see §3.1). A contradiction wins over a missing check. |
| `unverified` | location known but a physical check is missing or failed: `rtt-unavailable`, `latency-inconsistent` (distance(vantage, geo) > rtt × 100 km + `VALI_GEO_SLACK_KM`), `rtt-exceeds-claimed-distance` (rtt > distance/100 km × `VALI_GEO_RTT_PATH_FACTOR` + `VALI_GEO_RTT_EXTRA_MS`), `peer-stale` (the peer is DISCONNECTED and its `last_seen` — NetBird's last (re)connection time, not a heartbeat — is older than `VALI_GEO_PEER_STALE_S`) |
| `verified` | location known, latency consistent, sources agree (or the RTT settled their disagreement — `geo-rtt-arbitrated`, informational), tenants egress from the same IP |

### 3.1 Disagreeing GeoIP sources — the RTT arbitrates

Registries lag routing, e.g. a provider whose APAC prefix is registered in
another country. Say AS64500's 203.0.113.0/24 is registered (in its RIR) to
the provider's North American entity, but announced from an APAC data
centre, so NetBird's GeoLite says `CA` while RIPEstat's says `AU`. From a
European vantage the miner answers in ~290 ms — impossible for Canada. So when the country codes
differ, each candidate is tested against BOTH RTT bounds:

- RIPEstat's candidate at its coordinates (exactly the §3 check);
- NetBird's (country only) as a distance RANGE: `geo.COUNTRY_DISCS` holds a
  padded disc (centre + radius) containing each country, and the candidate
  is consistent when some distance in `[d − r, d + r]` satisfies both bounds.

| outcome | verdict |
|---|---|
| only RIPEstat's candidate consistent, and it has coordinates | the normal §3 checks run on it (freshness, both RTT bounds, tenant egress); `verified` possible, with the informational reason `geo-rtt-arbitrated`; `country_code` = RIPEstat's |
| only NetBird's (or a coordinate-less RIPEstat) candidate consistent | `unverified` / `geo-rtt-arbitrated-country-only`; `country_code` = that country. A country-sized disc can rule a country OUT but not vouch for one: inside a large country bound (b) is met by its far edge, so it cannot catch a nearby-exit tunnel. |
| both consistent, neither, no RTT, or a country missing from `COUNTRY_DISCS` | `mismatch` / `geo-source-disagree` (fail closed) |

`guest-egress-mismatch` is never arbitrated away.

`region = country_code` (ISO 3166-1 alpha-2, uppercase). One shared rule,
`geo.placeable_locations`, decides which rows the scheduler's gate and
`GET /v1/operator/regions` may treat as "in a region": the row is FRESH
(`observed_at` within `VALI_GEO_MAX_AGE_S`, 2 h — a probe that stopped or a
miner that vanished must not leave `verified` standing), and the verdict
is `verified` (`unverified` joins only when `VALI_GEO_REQUIRE_VERIFIED` is
off; `mismatch`/`unknown` never).

## 4. Threat model — what this proves and what it does not

- **A host on another continent behind a NEARBY VPN exit** (the realistic
  cheat: a miner elsewhere renting an exit near the vantage): the IP says 240 km, but
  every packet still crosses the ocean, so the RTT is ≥ 70–100 ms where
  240 km warrants ≤ 36 ms ⇒ `rtt-exceeds-claimed-distance`. A tunnel can
  add latency, never remove it; the miner cannot answer faster than its
  real distance allows.
- **An exit claimed far while answering near**: an IP placed ~9 600 km from
  the vantage ⇒ needs ≥ 96 ms RTT; 4 ms is impossible ⇒ `latency-inconsistent`.
- **Deliberately delaying handshakes**: only makes the RTT longer. That
  can never make a location look NEARER than the host really is. It can
  make a FARTHER GeoIP answer look plausible — for an IP GeoLite already
  places far away — and, since §3.1, it can also make RTT arbitration
  favour RIPEstat's far answer over NetBird's near one. Both GeoIP
  opinions are MaxMind lineage, so the second one was never an independent
  witness; the residual hole is "claim a region farther than you are, on
  an IP the GeoIP already puts there".
- **A host that tunnels only guest traffic**: caught by source 4 — the guests'
  egress IP differs from the host peer's.
- **A miner that reports a false location**: it cannot; nothing is reported.
- **NOT proven — the proxy front.** The RTT is a TCP handshake to the
  miner's NetBird endpoint. A miner that places a machine NEAR the vantage
  to terminate that endpoint (answer the SYN, forward the mTLS stream to
  its real hardware elsewhere) shows a near RTT while computing far away.
  Every other signal (NetBird `connection_ip`, the tenants' egress) then
  also points at the front, consistently. v1 proves the proximity of the
  network endpoint, not of the CPU. Closing it needs a challenge answered
  from INSIDE the attested host — a signed RTT probe in the host-attestor
  beacon (§8) — which is the v2 item, not a tweak of this one.
- **NOT proven**: the exact location (bounds only), and a VPN whose exit is
  within ~30 ms of the true host (e.g. a miner behind a VPN exit in a
  neighbouring country, or in its own country). Country-level granularity
  and the ±30 ms budget are the v1 unit. The two GeoIP opinions share the
  MaxMind lineage — their agreement is a sanity check, not independence.
- **No tenants yet**: source 4 is vacuous until a CVM runs on the host; the
  latency check carries the verdict alone in that window.
- **Failure direction**: every missing or failing input degrades toward
  `unverified`/`unknown`, never toward `verified`. A wrong vantage
  coordinate flips the whole fleet to `latency-inconsistent`, visibly.
- **RTT is measured from the control plane**: a miner cannot make it
  shorter; it can make it longer (self-harm only).

## 5. The probe (`vali_geo_probe`)

One Deployment (`vali-geo-probe`), interval `VALI_GEO_PROBE_INTERVAL_S`
(600 s). Per cycle: one NetBird call for the whole fleet → per miner:
GeoIP (cached in the row while the IP is unchanged and younger than
`VALI_GEO_GEOIP_TTL_S`) → RTT (every cycle) → guest egress list → verdict →
upsert `MinerLocation`. A NetBird outage skips the cycle (a stale-but-true
row beats a fresh `unknown` written because an API blinked). Logs one line
per verdict change. Pushgateway gauges `hippius_geo_miner_verified{miner_id,region}`
and `hippius_geo_miner_rtt_ms` when a gateway is configured.

Network: a dedicated CiliumNetworkPolicy scoped to the geo-probe pod
(`component: geo-probe`) grants egress to `100.64.0.0/10:9700` (the RTT
probe; the node routes the CGNAT range through its NetBird interface, the
same path the Edge uses), `world:443` (NetBird API, RIPEstat) and the
Pushgateway — no other vali workload gains those.

## 6. API surface

- `GET /v1/operator/nodes` — each row gains `location {country_code, region,
  city, connection_ip, asn, as_holder, rtt_ms, verdict, verdict_reasons,
  observed_at} | null`.
- `GET /v1/operator/regions[?verified_only=]` — `{regions: [{region,
  country_code, miners_total, miners_verified, miners_dispatchable,
  hosted_vm_count, capacity {total_units, committed_units, free_units} | null,
  node_ids}], unlocated_miners, require_verified, vantage, generated_at}`.
  `OPERATOR_ONLY`, published on `api.hippius.network` (exact path).
- `POST /v1/vm/launch` — optional `region` (ISO alpha-2, case-insensitive).
  Hard constraint: no verified miner there ⇒ 409 `no-miner-in-region`,
  never a silent fallback. Re-placement and graceful-exit migration honour
  the VM's original region.
- `GET /v1/scheduler/feasibility?region=` — the fit half restricted to the
  region; `never/no-miner-in-region` when no miner is detected there at all,
  `not-now/region-unverified` when miners exist but none is verified,
  `not-now/region-unknown` when the probe has never run.

## 7. Settings

`VALI_GEO_PROBE_INTERVAL_S`, `VALI_GEO_RIPESTAT_BASE`, `VALI_GEO_HTTP_TIMEOUT_S`,
`VALI_GEO_VANTAGE_NAME/LAT/LON`, `VALI_GEO_KM_PER_MS`, `VALI_GEO_SLACK_KM`,
`VALI_GEO_PEER_STALE_S`, `VALI_GEO_GEOIP_TTL_S`, `VALI_GEO_RTT_SAMPLES`,
`VALI_GEO_RTT_PATH_FACTOR`, `VALI_GEO_RTT_EXTRA_MS`, `VALI_GEO_MAX_AGE_S`,
`VALI_GEO_REQUIRE_VERIFIED`. Each documented in `vali/vali/settings.py`.
The vantage coordinates describe the control-plane cluster that runs the
probe; a control plane that moves must move them, or the RTT budget is computed from the wrong place.

## 8. Later

- A challenge/response timed INSIDE the attested host-attestor CVM
  (signed beacon): the RTT is then bound to the SNP hardware, which
  defeats the proxy front above; several anchors give trilateration
  instead of a single-vantage bound.
- City-level granularity: a GeoLite City database on the NetBird management
  server (`city_name` / `geoname_id` are already in the peer object, empty today).
- ASN reputation (known VPN operators) as an additional `mismatch` trigger.
