# Design: A dedicated public IPv4 per VM, served from ingress edges

**Status:** Part 1 implemented (vali allocation, lifecycle, NetBird routing) · **Date:** 2026-09-23

## 1. Goal

A tenant VM has only a NetBird overlay address. Its egress leaves through
the miner's NAT, so it carries the miner's IP, changes on every migration
and reveals the host. That breaks any workload that announces its own
address: QUIC/iroh direct paths, WebRTC, SIP, mail.

A VM that opts in gets **one public IPv4 address that behaves as its own**:
the same address inbound and outbound, ports preserved, endpoint-independent
NAT (so peer-to-peer traffic goes direct instead of through a relay), and a
stateful inbound firewall that is closed by default.

## 2. Pieces

| Piece | Where | Role |
|---|---|---|
| Ingress edge | a rented server (not an SNP miner), a NetBird peer | owns a few public IPv4 addresses; DNAT/SNAT, firewall, rate cap, metadata endpoint |
| vali `apps.network` | this repo | edges, the address pool, which VM holds which address, the NAT target, NetBird exit routing |
| The layer above | out of this repo | sells the address, owns the tenant's firewall rules, serves each edge its merged desired state, relays the edge's reports |
| Edge agent | out of this repo | renders the desired state into netfilter atomically, keeps the last state across restarts |

vali never talks to an edge, and an edge never talks to vali. The layer
above fetches `GET /v1/network/edges/<name>/desired` with its root token,
merges in the firewall rules it owns, and serves the result to the edge it
authenticated.

"Edge" already names the edge-gateway (`/v1/edge/...`), the relay in front
of the miner plane. Hence the model name `IngressEdge` and the
`/v1/network/` prefix.

## 3. Model (`vali/apps/network/models.py`)

- `IngressEdge`: `name` (a slug, ≤ 28 chars — it ends up in NetBird object
  names), `provider`, `region` (ISO 3166-1 alpha-2), `netbird_ip`,
  `netbird_peer_id`, `status` (`active` | `draining` | `disabled`),
  `desired_revision` / `applied_revision`, `last_seen_at`, `last_report`,
  `per_ip_mbps`.
- `PublicIP`: `address` (unique), `edge`, `vm`, `state`
  (`free` | `attached` | `quarantined`), `target_ip` (the VM's overlay
  address last handed to the edge), `attached_at`, `released_at`,
  `last_tenant_id` (while quarantined, the tenant of the VM that released
  it).
  A partial unique constraint allows one attached address per VM.

`draining` and `disabled` edges take no new attachments; addresses already
attached on them keep working. An edge can only be deleted once every one of
its addresses is free — deleting a quarantined address would let it be
re-added elsewhere and handed out before its quarantine ends. Its NetBird
routing is removed before its row, so a NetBird failure leaves the edge in
place and the delete can be retried.

An edge can be registered **unbound** (no `netbird_ip`): its NetBird setup
key is minted for an edge that already exists, so it cannot enrol first.
An unbound edge (`bound: false`) takes no attachment, is not counted in
availability, gets no NetBird routing and is served an empty desired
state, whatever its `status`. `PATCH {"netbird_ip": ...}` binds it.

An edge's identity is its NetBird **peer ID**, bound when it is registered
(the peer holding the given overlay address, which must not be a tenant VM
and, when `VALI_PUBLIC_IP_EDGE_PEER_GROUP` is set, must be in that group).
Nothing re-binds it automatically: if the peer disappears and NetBird hands
its overlay address to another peer, that peer does NOT become the exit
router. A re-enrolled edge is re-bound explicitly with
`PATCH {"netbird_ip": ...}`.

## 4. Lifecycle

**Attach** (`POST /v1/vm/<id>/public-ip`). Only for a live VM (`active` or
`migrating`). The edge is chosen among active edges in, best first: the
region the VM runs in (its host's detected, verified location), the
caller's `region`, the region its launch asked for; then any active edge.
In each of those tiers, an address the VM's **own tenant** released and that
is still quarantined comes first (the most recently released), then a free
one on the edge with the most free addresses. Region beats reuse: a free
address near the VM wins over an own address in another region. A tenant
that destroys a VM and launches its replacement therefore gets the same
address back, and its DNS keeps pointing at the right machine. `address`
in the body asks for one specific address instead — free, or quarantined
from this tenant; anything else is `address-unavailable` (409), with the
same answer whether the address is another tenant's, attached, on a
draining edge or not ours. A VM with a blank `tenant_id` reuses nothing,
and "released by this tenant" means both `last_tenant_id` and the retained
previous holder's `tenant_id` match (a row written by a process predating
the field cannot carry a stale owner across). Attach never waits on a
locked address (`detach` locks address then edge, attach edge then
address): a row being expired at that instant is skipped and another
address chosen, and an explicit `address` request may be refused and retried. An
attach the database aborts
as a deadlock victim (two attaches walking edges in different orders) runs
again, up to three times.
Idempotent (a VM that holds an address gets it back, whatever `address`
asks). The address starts with no `target_ip`: it carries traffic once the
VM's NetBird peer is resolved.

**Detach** (`DELETE`, or the VM is destroyed). The address goes to
`quarantined`, records the VM's tenant in `last_tenant_id`, and returns to
`free` after `VALI_PUBLIC_IP_QUARANTINE_S` (1 h by default), so traffic
still aimed at the previous holder never reaches ANOTHER tenant. Until then
only its own tenant can take it back (above).

Why one hour, not a day: the edge drops the address's DNAT/SNAT rules on
its next render and deletes every conntrack entry translated to or from it
(`conntrack -D --orig-dst/--reply-dst`, owed on disk across a restart), so
no established flow — TCP, or a long-lived QUIC/UDP mapping — outlives the
detach. An edge that has not rendered the detach yet still holds the old
rule, but the old VM's peer leaves the edge's NetBird group on the next
tick — departures never wait for the edge — so that rule points at a peer
the edge can no longer reach. What the window still covers is the part the
edge cannot flush:
DNS records and resolver caches that still name the address (TTLs of
minutes, rarely above an hour), and clients or allow-lists that retry it.
A day held a scarce IPv4 address hostage for a risk that is mostly over
within the TTL; an operator with long TTLs raises the setting
(`config.publicIpQuarantineS` in the vali chart). Both destroy paths
(the §24 decommission and the lifecycle transition to `destroyed`) release
the address immediately; the reconcile loop below is the backstop.

**Reconcile** (every orchestration tick). One idempotent pass, rather than
hooks in every path that can move a VM:

- release any address still attached to a VM that is no longer live;
- return quarantined addresses past the window to the pool;
- every `VALI_PUBLIC_IP_NETBIRD_SYNC_S` (and on the tick right after an
  attach or detach): list NetBird peers once, follow each attached VM's
  overlay address — a migration, a reboot-recovery relaunch or the first
  enrolment changes or sets it — and bump the edge's revision when it
  moved; then make each edge's exit routing and group membership match,
  and remove the routing of edges that no longer exist. A VM's peer joins
  its edge's group only once the edge has applied every revision vali
  asked for: before that the edge has no SNAT rule for it, and may still
  DNAT a stale address to an overlay IP NetBird has recycled to this peer.
  Each join is re-checked against the database right before it happens.
  Leaving is immediate, and every departure across all edges runs before
  any join; if one fails, nobody joins that pass, so a VM moving between
  edges is never in both groups.
  A disconnected peer (a rebooting guest) keeps its record and its target;
  a peer whose record is GONE loses its target at once, because NetBird
  may hand its old overlay address to another VM. NetBird failures are
  logged and retried; they never block the database half or the rest of
  the tick.

Every change an edge must render bumps its `desired_revision`; the edge
reports the revision it applied, so `desired - applied` is its lag.

## 5. Traffic path

For an address `P` attached to a VM whose overlay address is `N`:

```
inbound   client → P (edge public iface) ── DNAT P→N ──▶ wt0 ──▶ VM (sees the client's IP)
outbound  VM ──▶ default route = NetBird exit route via the edge ──▶ SNAT N→P ──▶ internet
```

- **Exit route.** In NetBird, per edge: a route `0.0.0.0/0` whose routing
  peer is the edge, `masquerade=false` (the edge must see `N` to SNAT it to
  the VM's own `P`, not to its own address), distributed to the group
  `hippius-pip-vms-<edge>`; and a bidirectional all-protocol accept policy
  between that group and `hippius-pip-gw-<edge>`, which holds the edge's
  peer. Joining the VM's peer to `hippius-pip-vms-<edge>` is what moves its
  default route. The route and the policy are named `hippius-pip-<edge>`.
  The fixed `vms-` / `gw-` tags keep any two edges' group names distinct.
  vali creates and repairs these objects by name, from the orchestration
  tick only (a single writer).
- **NAT.** One DNAT and one SNAT rule per attached address. A per-address
  SNAT keeps the outside port equal to the inside port where possible and
  the mapping endpoint-independent, which is what lets peer-to-peer
  protocols find a direct path.
- **In the VM.** Applications bind `0.0.0.0`. The VM learns `P` from a
  metadata endpoint the edge answers on the overlay.

## 6. Firewall

Enforced on the edge, stateful:

- inbound: dropped, except ICMP, established/related traffic, and the
  tenant's own accept rules (protocol, port or range, optional source CIDRs);
- outbound: open, but only from overlay addresses that hold an attached
  address — the edge is never an open exit for other peers.

No port is ever opened by default or suggested. The rules live with the
layer that knows the tenant; vali only knows address ↔ VM.

## 7. API (all `OPERATOR_ONLY` and root-only)

| Route | Purpose |
|---|---|
| `GET` / `POST` / `DELETE /v1/vm/<id>/public-ip` | read, attach (`{region?, address?}`), detach |
| `GET /v1/network/availability?region=` | free addresses per region, active edges only |
| `GET` / `POST /v1/network/edges` | list; register (the edge's peer is found by `netbird_ip`) |
| `GET` / `PATCH` / `DELETE /v1/network/edges/<name>` | read; status, rate cap, provider; delete (409 while attached) |
| `POST` / `DELETE /v1/network/edges/<name>/addresses` | add addresses; remove free ones (all or nothing) |
| `GET /v1/network/edges/<name>/desired` | attached addresses whose target is known |
| `POST /v1/network/edges/<name>/applied` | `{revision, report}` from the agent |

`public_ip: {address, edge, region} | null` is part of the VM wire shape
(`/v1/vm/<id>/state` and the `/v1/vm` list).

`/v1/network` is published on the public Ingress as a prefix. That is safe
only because every route under it is root-only; a test fails if one is
added without that gate.

## 8. Threat notes

- **The edge sees the VM's public traffic in clear** unless the workload
  encrypts it (TLS, QUIC, WireGuard). It is a network hop like any ISP
  router, and it is ours, but tenants must treat the public address as an
  untrusted network — as they would any public address.
- **The miner never sees `P`.** Its view of the VM is unchanged: an
  encrypted overlay tunnel. It cannot tell which VM owns which address, nor
  inject traffic under `P`.
- **Addresses are never guessed.** An address is announced to its edge only
  once the VM's own NetBird peer (matched by its enrolment name) has an
  overlay address; until then the edge is told nothing. When that peer
  record disappears the target is withdrawn on the next pass, and a peer
  joins an edge's group only once the edge has caught up. The residual
  window is NetBird re-assigning a deleted peer's overlay address to a new
  peer that some OTHER policy already lets the edge reach, before the next
  pass plus the edge's next poll; NetBird allocates overlay addresses at
  random in a /10, which makes that improbable, not impossible. After
  detach, the quarantine keeps the address away from other tenants.
- **No new principal.** Edges hold no vali credential; the only caller is
  the existing root principal of the layer above.
- **Availability.** An edge is a single point of failure for its addresses.
  There is no anycast or failover; recovering an edge's addresses means
  moving them at the provider. Every edge keeps its last applied state if
  the layer above or vali is unreachable.
