# Design: VM egress, bandwidth metering and rate caps

**Status:** Proposed (spec only, nothing implemented) · **Date:** 2026-10-06

Spans this repo (vali, miner-agent, miner Ansible) and `hippius-backend`
(edge agent `edge/public_ip.py`, billing `compute/usage.py`, console API).
Backend paths are cited as `backend:<path>:<line>` against `origin/main` of
`thenervelab/hippius-backend`. The backend half is summarised in
`backend:docs/design/egress-and-bandwidth.md`.

## 1. Goal

A tenant VM's egress has to be metered, billed and capped wherever bandwidth
costs money, without trusting the miner. Specifically:

- In regions where bandwidth is expensive, send all VM egress through an
  edge the operator runs in that region. The edge meters it per VM and
  enforces a per-VM rate cap.
- In regions where the miners have unmetered bandwidth, keep today's miner
  NAT and add a per-VM cap. These regions are not billed.
- Bill outbound bytes only, per region, with an included allowance per VM
  per month. Inbound is free.
- Block outbound TCP 25 everywhere. Precisely: drop packets whose outer
  destination port is TCP 25. SMTP tunnelled inside HTTPS, a VPN or a
  tenant proxy is out of scope; no network rule can stop that short of a
  destination allowlist.
- Make sure a tenant who is root in their guest cannot go around the meter.

Non-goals: metering traffic inside a region between VMs, IPv6, and
per-destination pricing.

The examples below use two illustrative region keys from the ISO 3166
user-assigned range: `XA`, a region where bandwidth is expensive and egress
goes through an edge, and `XE`, a region where miners have unmetered
bandwidth.

## 2. Where we are today

### 2.1 VM networking on the miner

- Every VM, tenant or infra, has one virtio NIC on the stock libvirt
  `default` network. There is no `<mac>`, no `<target dev>`, no `<bandwidth>`
  and no `<filterref>` (`binaries/miner-agent/src/lifecycle/qemu_config.rs:362-365`,
  `binaries/miner-agent/src/lifecycle/infra.rs:283-286`). libvirt picks the
  tap name and the MAC.
- That network is defined as `<forward mode='nat'/>` on `virbr0`,
  192.168.122.1/24, with DHCP `.2-.254`
  (`deploy/ansible/playbooks/miner-tasks/networking-bridge.yml:29-39`).
  libvirt owns the masquerade and forward rules. No firewall backend is
  pinned. Hosts run libvirt 11.6 / 12.0
  (`deploy/ansible/group_vars/miner_nodes.yml:31-34`), which defaults to
  nftables, but nothing checks that.
- The host firewall is UFW: incoming deny, outgoing allow, routed deny
  (`deploy/ansible/playbooks/miner-tasks/host-firewall.yml:39-46`). It
  allows 22/tcp, 51820/udp and everything on `wt0` (`:48-67`). Outbound is
  deliberately open (`:24-27`), and guest traffic on virbr0 is left to
  libvirt (`:29-31`).
- Nothing blocks port 25, there is no `tc`, and there are no per-VM counters
  anywhere in `deploy/` or `binaries/miner-agent/`.
- Miners are not on the operator's private network. They have only a public IP
  (`group_vars/miner_nodes.yml:69-71`).
- The guest initramfs runs DHCP against libvirt's dnsmasq
  (`binaries/agent-initramfs/src/stages/network.rs:1-24`). A legacy guest
  reaches the KBS over HTTPS this way, through `hippius.kbs_url`. The
  current path goes over vsock through miner-agent, so the guest needs no
  network (`binaries/miner-agent/src/config.rs:50-55`,
  `binaries/miner-agent/src/main.rs:1011-1022`).

### 2.2 How config reaches a miner

- miner-agent's config is a static TOML that Ansible renders
  (`playbooks/miner-tasks/templates/miner-agent-config.toml.j2`).
- The heartbeat is one-way. Its response body is ignored
  (`binaries/miner-agent/src/heartbeat/pusher.rs:222`), and its fields
  include nothing about the network (`hippius-types/src/heartbeat.rs:205-260`).
- Control flows in as signed orders on the mesh-bound HTTP server
  (`binaries/miner-agent/src/orders/mod.rs:298-336`). Edge-gateway signs and
  posts them (`binaries/edge-gateway/src/order_signing.rs`). `OrderKind`
  (`binaries/miner-agent/src/orders/types.rs:38-77`) has no network or
  config order.

### 2.3 Guest NetBird and its default route

- A guest joins NetBird from cloud-init `runcmd`, using a single-use setup
  key that vali mints per VM:
  - backend `compute/userdata_netbird.yaml:138-163`;
  - vali `vali/apps/orchestration/services/launch.py:755-771,1366-1414`;
  - `effects.mint_netbird_setup_key`, `vali/apps/orchestration/effects.py:1854`.

  The Debian UKI image runs `netbird up` from a systemd unit instead
  (`packer/tenant-uki-debian/uki/rootfs-config/systemd/netbird.service:49-58`).
- The guest image does nothing special about routing. The only thing that
  moves a VM's default route is NetBird applying a `0.0.0.0/0` exit route,
  and vali creates that route only for VMs that hold a public IP
  (`vali/apps/orchestration/effects.py:2385-2391`).
- `ensure_edge_routing` (`effects.py:2506-2600`) creates:
  - group `hippius-pip-vms-<edge>`;
  - group `hippius-pip-gw-<edge>`, holding exactly the edge peer;
  - route `0.0.0.0/0` via the edge, with `masquerade: false` (the edge has
    to see the overlay source), `metric: 9999`, `keep_route: true` and
    `skip_auto_apply: false` (`:2530-2543`);
  - an all-protocol, bidirectional accept policy between the two groups
    (`:2566-2580`).
- vali reconciles group membership (`vali/apps/network/service.py:686-884`).
  A VM joins only after the edge has applied the current revision
  (`_may_join`, `service.py:751-769`). That way the edge never forwards for
  an overlay IP that NetBird has since recycled to another peer.
- `check_edge_peer` refuses to make a tenant peer an exit router
  (`service.py:574-587`).
- M1/M2 (customer-keys) VMs run `netbird up` with `--disable-dns
  --disable-client-routes --disable-server-routes`
  (`vali/apps/orchestration/services/customer_keys.py:644-658`). They
  therefore never apply an exit route. Even today, an M1/M2 VM with a public
  IP sends its egress through the miner's NAT. See §12, Q5.
- Without a public IP, a VM's egress goes through the miner's NAT with the
  miner's address, and nothing meters it
  (`backend:compute/views_public_ip.py:268-269`).

### 2.4 Regions, edges, miners

- A region is the ISO 3166-1 alpha-2 country of the miner's measured
  location (`vali/apps/miners/models.py:277-279`,
  `docs/design/miner-geolocation.md:61`).
- `IngressEdge` (`vali/apps/network/models.py:40-66`) holds `region` (the
  same key), the NetBird peer and IP, desired and applied revisions,
  `last_report`, and `per_ip_mbps` (default 1000, `:64-65`).
- `PublicIP` (`:80-119`) holds an address on an edge, the VM, and the NAT
  `target_ip`.
- A public IP is picked in this order: the VM's placed region, then the
  caller's hint, then the launch region, then **any active edge**
  (`service.py:188-213,319-333`).
- vali serves the edge feed `{edge, revision, per_ip_mbps, addresses:[...]}`
  (`service.py:460-487`). The backend merges in the tenant firewall
  (`backend:compute/public_ip.py:413-435`) and serves it to the edge
  (`backend:compute/views_public_ip.py:441-480`).
- `binaries/edge-gateway` is a different thing: the control-plane relay
  between miners and the operator's private network, an application relay with `ip_forward=0`
  (`binaries/edge-gateway/README.md:1-25`). Nothing in this spec touches it.

### 2.5 The edge agent today (backend `edge/public_ip.py`)

- One nft table, `inet hippius_edge_pip` (`backend:edge/public_ip.py:105`),
  rebuilt in a single `nft -f` transaction by `render_pip_nft` (`:433-605`):
  - DNAT P→N and SNAT N→P.
  - A `guard` chain on prerouting at `dstnat + 10`. It uses prerouting, not
    forward or input, because NetBird inserts `iifname wt0 accept` into
    those hooks (`:499-506`).
  - The guard's last rule keeps the edge from ever being an open exit:
    overlay → non-overlay unicast is dropped unless the source is an
    attached N (`:547-554`).
  - Per-address named counters `pip_<a_b_c_d>_in` / `_out`, in a postrouting
    chain at `srcnat + 10`, after the guard and after SNAT (`:588-599`).
- `render_tc` (`:708-735`) builds one HTB class per P at `per_ip_mbps` with
  fq_codel inside. On the public interface it matches source P; on `wt0` it
  matches destination N.
- Usage samples carry monotonic totals. They are POSTed every 60 s to
  `/api/compute/edge/public-ips/usage/` (`:1239-1269,1531`), authenticated
  with a ServiceToken of scope `edge:public-ips` bound to the edge name
  (`backend:compute/views_public_ip.py:425-438`).
- The backend ingests them into 5-minute `PublicIpUsageSample` buckets
  (`backend:compute/public_ip_usage.py:37,134-189`). A lower total is treated
  as a counter reset, and the first report only sets the baseline
  (`:112-113,155-158`).
- No port 25 rule exists on the edge
  (`backend:edge/ansible/templates/host-fw.nft.j2` protects the edge host
  only).

### 2.6 Billing today (backend)

- `ComputePrice` is an append-only catalogue. Its bandwidth resource is the
  single row `bandwidth`, priced per GB (10^9 bytes, in + out)
  (`backend:compute/models.py:1474-1518`). That row was seeded at 0
  (`backend:compute/migrations/0046_usage_ledger_seed.py:52-53`).
- The hourly close turns `PublicIpUsageSample` into `Kind.BANDWIDTH` lines:
  bytes in + out per VM, per price span (`backend:compute/usage.py:712-731`).
  Only public-IP traffic is ever counted.
- Hours close at H+10 min and are then frozen (`usage.py:44-57`).
- `price_list` exposes a single `bandwidth_per_gb`
  (`backend:compute/billing.py:412`).

## 3. Design overview

| | `edge` mode (e.g. `XA`) | `local` mode (e.g. `XE`) |
|---|---|---|
| Default route | NetBird exit route to the region's edge | libvirt NAT on the miner (unchanged) |
| Egress address | shared regional egress IP `E` on the edge (SNAT, no inbound) | the miner's IP |
| Meter (billing) | per-VM nft counters on the edge, keyed by VM and overlay IP | none (price 0, unlimited) |
| Rate cap | per-VM HTB class on the edge (authoritative), plus a looser libvirt cap on the miner | per-VM libvirt `<bandwidth>` on the miner |
| Anti-bypass | miner forward allowlist, fail closed | none needed |
| Port 25 out | dropped on the edge and on the miner | dropped on the miner |
| Floating IP VM | unchanged: own P, own counters on its edge | unchanged |

Billing has one rule: **bytes a VM sends that leave the region, or that
cross one of the operator's edges, are metered at that edge.** Overlay traffic between
VMs in the same region goes miner to miner and is not metered (§6.5).

## 4. Region policy (vali)

Add a new model to `vali/apps/network/models.py`:

```python
class EgressRegion(models.Model):
    region = models.CharField(max_length=2, primary_key=True)      # alpha-2, same key as IngressEdge.region
    mode = models.CharField(choices=[("local", ...), ("edge", ...)], default="local")
    routing_enabled = models.BooleanField(default=False)   # edge mode: put the region's VMs on the exit route
    enforce = models.BooleanField(default=False)           # edge mode: miners apply the forward allowlist
    default_cap_mbps = models.PositiveIntegerField(default=200)
    cap_mbps_by_flavor = models.JSONField(default=dict)    # {"<flavor code>": mbps}; overrides the default
    revision = models.BigIntegerField(default=1)           # bumped on any change to the miner policy (§7)
```

- A region with no row is `local` and has the default cap.
- `mode=edge` requires at least one bound, active `IngressEdge` in the
  region that has an `egress_ip`.
- The `routing_enabled` and `enforce` flags let rollout (§10) and rollback
  happen one step at a time.

Add a new field on `IngressEdge`: `egress_ip` (IPv4, unique, nullable). This
is the shared SNAT address. It must not belong to the edge's `PublicIP`
pool, and it is never DNATed.

vali exposes the policy to the backend as `GET /v1/network/egress-regions`
(root token, like `/v1/network/edges`) for pricing and console display.

## 5. Edge mode: the data path

```
outbound  VM ──▶ default route = NetBird exit route via region edge ──(WireGuard over miner uplink)──▶ edge
              edge: count(out, vm) → tc class(vm) → SNAT N→E ──▶ internet
inbound   reply to E ──▶ conntrack de-SNAT E→N → count(in, vm) → tc class(vm) on wt0 ──▶ VM
unsolicited to E ──▶ dropped
```

### 5.1 NetBird routing (vali `effects.py`, `network/service.py`)

These mirror `ensure_edge_routing`, one set per region rather than per edge:

- Group `hippius-egr-vms-<region>`: the region's VMs that do **not** hold a
  public IP.
- Group `hippius-egr-gw-<region>`: the region's egress edges, one today and
  two in phase 2 (§11).
- Route `0.0.0.0/0` with `peer_groups=[hippius-egr-gw-<region>]`,
  `masquerade: false` (per-VM attribution needs the overlay source),
  `metric: 9999`, `keep_route: true`, `skip_auto_apply: false`, distributed
  to `hippius-egr-vms-<region>`.
- An accept policy, all protocols, bidirectional, between the two groups.
- **The two groups are mutually exclusive.** A VM is in at most one of
  `hippius-pip-vms-*` and `hippius-egr-vms-*`. Two `0.0.0.0/0` routes with
  different `network_id`s on one client would make the exit nondeterministic.
  Attach and detach move the peer in this order: remove from the old group,
  wait until the new edge has applied, then add to the new group. The VM
  briefly has no internet, which fails closed. The same `_may_join` rule
  holds: a VM joins `hippius-egr-vms-<region>` only once the edge has
  applied a revision whose egress list contains `(vm_id, N)` and no longer
  contains any previous holder of N.
- Do not use setup-key `auto_groups` for this group. Joining at enrollment
  would skip the applied-revision check, and a recycled overlay IP would
  then bill the wrong VM.
- `check_edge_peer` is extended to egress edges. Only peers that pass it can
  be in `hippius-egr-gw-*`.

### 5.2 Edge feed

vali's `desired_state(edge)` (`service.py:460-487`) gains one block. The
backend passes it through `edge_feed` untouched apart from validation.

```json
"egress": {
  "address": "E",
  "block_smtp": true,
  "vms": [{"vm_id": "...", "target_ip": "100.x.y.z", "epoch": 17, "class_id": 4097, "cap_mbps": 200}]
}
```

`vms` lists the VMs of the edge's region that are on the exit route and hold
no public IP.

- `cap_mbps` is the VM's **effective cap**, defined once by vali for every
  path (§7.1).
- `epoch` increments every time the `(vm_id, N)` binding changes.
- `class_id` is a stable tc class that vali leases for the VM. It is never
  reused while the VM exists, unlike the index-derived class ids of the
  per-P classes (`backend:edge/public_ip.py:724`).
- `vm_id ↔ target_ip` must be one-to-one. The edge refuses a feed that
  repeats either.

Any change bumps `desired_revision`, which is what `_may_join` waits on.
`egress` is absent for a `local` region, and an edge
whose feed has no `egress` block renders exactly what it renders today.

### 5.3 Edge agent changes (`backend:edge/public_ip.py`)

All of this stays in the same `inet hippius_edge_pip` table and the same
single transaction:

1. **Validation:**
   - `E` must be in a new agent-side allowlist, `EDGE_EGRESS_IP`, the
     equivalent of `EDGE_PUBLIC_IP_ALLOWED` for P.
   - Every `target_ip` must be in `100.64.0.0/10`.
   - A `target_ip` that is also an attached N is dropped from `vms`, loudly
     and reported. This makes disjointness an invariant on the edge itself,
     not only a vali promise.
2. **SNAT:** `iifname wt0 oifname <public> ip saddr @egr_vms snat ip to E`,
   placed after the per-P SNAT rules.
3. **Guard:**
   - The exit guard (`:550-554`) exempts `@egr_vms` as well as the attached
     Ns.
   - New first rules, before `ct state established,related accept` and
     applying to anything from the overlay to a non-overlay destination:
     `tcp dport 25 drop`, plus `ip daddr E ct state new iifname <public>
     drop`. The second rule makes E outbound-only.
   - The exit guard also moves ahead of `established`, for the original
     direction: `iifname wt0 ct direction original ip daddr != 100.64.0.0/10
     fib daddr type unicast ip saddr != { attached Ns, @egr_vms } drop`. A
     flow from a VM that left the egress set, which would otherwise keep
     flowing uncounted under an old conntrack entry, dies on its next packet.
     This is the same trick the IPv6 rule already uses (`:522-525`).
4. **Hairpin from egress VMs:** today an overlay flow toward a P is dropped
   unless its source is an attached N (`:536-544`). Once non-PIP VMs default
   to the edge, a VM reaching another tenant's P on the same edge would be
   dropped. Extend the hairpin so that a source in `@egr_vms` reaching P is
   SNATed to E and judged by P's chain, exactly as an internet source would
   be. This also closes a leak: without it, the VM could reach P directly
   from the miner uplink and skip the meter.
   - Hairpin bytes travel `wt0 → wt0`, so the `oifname <public>` counters
     below never see them. A dedicated rule counts the sender's bytes into
     the sender's `out` counter: `iifname wt0 oifname wt0 ct direction
     original ct original ip saddr N ct original ip daddr @pip_addresses`.
     This is billed.
   - The receiver's `in` counter fires as well. Inbound is free, so nothing
     is billed twice.
5. **Counters:** one named pair per VM, `egr_<vm-key>_out` and `_in`, in the
   existing `count` chain at postrouting `srcnat + 10`. After SNAT the packet
   source is E for every VM, so the rules match on the conntrack tuple
   instead:
   - out: `iifname wt0 oifname <public> ct direction original ct original ip saddr N`;
   - in: `iifname <public> oifname wt0 ct direction reply ct original ip saddr N`.

   The totals stay monotonic and are carried across table rebuilds and
   restarts, as the per-P counters are (`_carry` / `_count`, `:1134-1184`).
   The counters are keyed by `(vm_id, N, epoch)`. A new key starts a new
   baseline, so a recycled N can never carry one VM's total into another's.
6. **tc, per VM, shaping every packet the VM sends regardless of
   destination:**
   - **Upload (from the VM):**
     - Redirect `wt0` ingress to an IFB device (`tc filter ... action
       mirred egress redirect dev ifb-egr`).
     - On the IFB, build an HTB with one class per VM (`class_id` from the
       feed), matched with `u32 src N`. Before NAT the source is still N,
       so this covers internet traffic, hairpins and the metadata endpoint
       alike.
     - Overlay traffic not in the feed falls into a **default class capped
       low** (for example 10 Mbit/s), never into HTB's unshaped direct
       queue.
     - No fwmark is needed, so nothing can collide with NetBird's
       `0x1BD0x` marks.
   - **Download (towards the VM):** HTB on `wt0` egress with `u32 dst N`, as
     the per-P classes do today (`:708-735`). It also has a capped default
     class.
   - Each class runs fq_codel inside. On a feed change, the agent flushes
     the conntrack entries of every removed or retargeted N,
     `conntrack -D -s N` and `-d N`, **before** it reports the revision as
     applied. `_may_join` therefore never admits a peer while a stale NAT
     binding for its address survives.
   - **Scale:** HTB under one root qdisc tops out at a few Gbit/s per
     device. Past that, move to `mq` + per-queue HTB or EDT/BPF (§9).
7. **Reporting:**
   - The 60 s usage sample gains a `vms` map next to `addresses`:
     `{"vms": {"<vm_id>": {"target_ip", "epoch", "bytes_in", "bytes_out", "pkts_in", "pkts_out"}}}`.
   - Per-address entries also carry the `vm_id` and an `epoch` (the lease).
     Today they are keyed by address alone
     (`backend:compute/public_ip_usage.py:124-131`), so a bucket that
     straddles a reassignment goes to whichever VM held the address first.
   - It uses the same endpoint, the same on-disk queue and the same ordering
     (`:1271-1311`). The applied report also carries the per-VM counters and
     any errors.
8. **NAT log for abuse:** a shared egress IP means abuse reports name E, not
   a VM. Log every new SNAT binding (time, vm_id, N, the E port, destination)
   with `conntrack -E -e NEW` or ulogd, and keep it for 90 days on the edge.
   This attributes abuse complaints and lawful requests. It is not used for
   billing.

### 5.4 Floating-IP VMs in an edge region

- Nothing changes on their path. They stay in `hippius-pip-vms-<edge>`, are
  counted by `pip_*` counters, and capped at their effective cap (§7.1).
- The miner allowlist (§6) covers them too: their only internet path is
  their edge.
- The public IP fallback to **any active edge** (`service.py:319-333`) has
  to be closed for VMs placed in an edge-mode region. An XA VM holding an
  XE-edge address would otherwise get XE pricing and haul its traffic
  across the world. See §12, Q6, and §8.3 for which region prices the bytes.

## 6. Edge mode: anti-bypass on the miner

The tenant is root in the guest. It can stop NetBird, run `netbird up
--disable-client-routes`, delete the route, set NetBird's fwmark on its own
sockets, or spoof addresses. Enforcement therefore lives outside the CVM,
on the host. Everything the guest sends leaves through `virbr0`, so a
forward allowlist there is the single choke point.

### 6.1 Per-VM identity on the bridge

`virbr0` is a shared L2 segment. A guest can claim other IP or MAC
addresses on it, ARP-spoof a neighbour, or impersonate the infra VM, so any
rule keyed on `ip saddr` would be forgeable. Identity therefore comes from
the **bridge port**:

- `qemu_config.rs` gives every tenant NIC a deterministic tap name,
  `<target dev='hvt<cid>'/>`. The vsock CID is unique per host and fits
  IFNAMSIZ.
- Every tenant NIC also gets libvirt's built-in `clean-traffic` nwfilter
  (`<filterref filter='clean-traffic'>` with the DHCP-learned IP), which
  stops MAC, IP and ARP spoofing at the tap.
- Every tenant NIC is set `<port isolated='yes'/>`, so guests cannot talk to
  each other at L2 on the same host. Same-host VMs still reach each other
  through the overlay. Isolation is not an egress requirement, but without
  it a co-tenant could ARP-poison a neighbour.
- The infra (attestor) VM moves to its own libvirt network, `hippius-infra`
  (§12, Q8).
- Per-VM meters (DNS, signal) are keyed on the tap through an nft `bridge`
  table that copies the port into `meta mark` at bridge prerouting, before
  the frame reaches the IP stack. These marks live on the miner, not the
  edge, so NetBird's marks on the host need a disjoint mask: use
  `0x7f000000` and masked read-modify-write.

### 6.2 Rules (new nft table `inet hippius_guest`, owned by miner-agent)

The table is rendered from the policy vali pushes (§7). Its chains:

- A `forward` chain at priority `filter - 10`, policy accept. It touches
  only traffic entering on `virbr0`; host traffic is untouched. A drop in
  any base chain is final, so this table needs no ordering against libvirt's
  or UFW's chains.
- The destination checks run on **every packet the guest originates** (`ct
  direction original`), not only on new flows. Enabling `enforce` therefore
  also kills miner-NAT flows that were opened before it.
- miner-agent also runs `conntrack -D -s 192.168.122.0/24` when it applies a
  stricter policy.

  ```
  iifname "virbr0" meta nfproto ipv6 drop
  iifname "virbr0" oifname != "<uplink>" drop          # never into wt0 / docker / other bridges
  iifname "virbr0" tcp dport 25 drop                   # both modes
  iifname "virbr0" ct direction reply accept
  # edge mode only, below (ct direction original):
  iifname "virbr0" ip daddr . meta l4proto . th dport @hippius_infra accept
  iifname "virbr0" ip daddr @region_miners meta l4proto udp accept
  iifname "virbr0" ip daddr . tcp dport @nb_control meter nbctl { meta mark & 0x7f000000 limit rate over 64 kbytes/second } drop
  iifname "virbr0" ip daddr . tcp dport @nb_control accept
  iifname "virbr0" reject with icmpx admin-prohibited
  ```

- An `input` chain, `iifname "virbr0"`, in both modes. It allows DHCP
  (udp 67) and DNS to the bridge address. DNS is metered per tap: 20
  packets/s and 16 KB/s. Everything else from guests to the host is
  dropped: host sshd, and the host's own `wt0` address with miner-agent
  `:9700` on it.
- **Visibility only:** `local` mode may add per-bridge counters. They are
  never sent for billing.

What each allowlisted set contains, all of it pushed by vali and all of it
plain IPs:

| Set | Contents | Why |
|---|---|---|
| `hippius_infra` (`ip . proto . port`) | Each edge's **own** public address: its WireGuard port (udp 51820) and its STUN port. Under R1 only (§6.5), also our metered relays. Also the WireGuard endpoints of the other infra NetBird peers that tenant VMs must reach: the shared exposure edge (`compute-edge`), the gateway, validators. | The exit route, public-IP edges in any region, the browser terminal and gateway SSH |
| `region_miners` | Public IPs of the region's miners, from their NetBird `connection_ip` (the geo evidence, `vali/apps/miners/geo.py`) | Direct WireGuard between VMs in the same region (managed K8s, tenant VPCs) |
| `nb_control` | The NetBird management and signal addresses | Enrolment and signalling. Rate-limited, because signal forwards opaque messages between peers. |

The edge's own services are not reachable from the overlay. The edge host
firewall's `overlay_to_host` chain admits only ICMP and the metadata port
from `wt0` to edge-local addresses
(`backend:edge/ansible/templates/host-fw.nft.j2:47-61`). That chain is a
hard requirement of edge mode. The relay listens on the edge's public
address, not on `wt0`.

Explicitly **not** allowed:

- An edge's `PublicIP` pool addresses and E. Reaching a P has to go through
  the overlay hairpin, where it is counted.
- Any NetBird relay or TURN server. Under R2 there are none at all; under R1 only our metered relays are allowed.
- The KBS over the network. Edge-mode regions require the vsock KBS proxy
  (`[kbs]` in miner-agent config), so `kbs.hippius.network` (a shared
  ingress address) never needs allowlisting.
- Any CDN or anycast address.

### 6.3 Requirements on allowlisted endpoints

Every allowlisted address must be **dedicated and ours**:

- Not behind a Cloudflare proxy or any other shared front. A CDN IP would
  allow the whole CDN through domain fronting.
- No open proxy or forwarder on an allowlisted `IP:port`.
- The NetBird relay never on the same `IP:port` as management or signal.
  NetBird's combined deployment serves all three on `:443`, and allowing
  management would then also allow the global relay.

This has to be checked on `vpn.hippius.network` before `enforce` is turned
on anywhere (§12, Q4). If management/signal and the relay share an address,
move the relay to its own address first.

### 6.4 Bounded control channels (declared exemptions)

Some guest traffic leaves through the miner and not through the edge, by
design. None of it is metered. Each channel is bounded per VM, so it cannot
carry bulk traffic:

| Channel | Path | Bound |
|---|---|---|
| DNS | guest → dnsmasq on the host → host resolver | per-tap meter, 20 pps / 16 KB/s (§6.2) |
| NetBird management and signal | guest → `nb_control` | per-tap meter, 64 KB/s |
| KBS over vsock | guest → miner-agent → our KBS, fixed paths only (`binaries/miner-agent/src/vsock/kbs_proxy.rs`) | destination is ours; add a per-VM byte rate (for example 256 KB/s) to the proxy |
| Key-guardian relay (M1/M2) | guest → miner-agent → the tenant's `guardian_ep` (`binaries/miner-agent/src/vsock/guardian_relay.rs:1-34`): exact paths, capped bodies, per-VM rate limit | also refuse `guardian_ep` port 25, and add a per-VM byte rate |

### 6.5 Overlay traffic: relays and tenant devices

NetBird traffic between peers is WireGuard. A VM can send its internet
traffic through **any** peer it can reach: its own laptop, its VM in a
`local` region, a tenant NetBird router, or a plain SOCKS proxy over the
overlay. NetBird routes are not required for any of this. The meter
therefore has to see every byte a VM sends to a peer outside its region,
or the path must not exist.

- **Inside the region:** direct WireGuard between VMs works because
  `region_miners` is allowed. Using another VM in the region as an exit gains
  nothing, because that VM's own egress is metered.
  - A tenant can push one VM's traffic through a sibling VM to use the
    sibling's cap and allowance. Both VMs are paid for, so this is accepted.
    In effect it pools caps and allowances across the tenant's VMs.
  - A miner that colludes with the tenant can run a UDP proxy on its own
    address. This is a residual risk (§6.7).
- **Outside the region** (tenant laptops, VMs in other regions): direct
  WireGuard is blocked by the allowlist, so NetBird falls back to a relay.
  The pinned NetBird client (0.71.3) does **not** let us choose the relay
  per session:
  - one side of each pair, chosen deterministically, uses its **home**
    relay, and the other side has to reach that relay as a foreign relay;
  - a guest that can reach only the XA edge's relay therefore fails to
    connect whenever the remote side picks its own home relay.

  Two workable options follow.
  - **R2 (XA launch default): no relay for edge-region guests.** Tenant
    devices reach the VM through a public IP, the browser terminal or
    gateway SSH. Overlay links to peers outside the region do not work. This
    fails closed. It is a product regression for VPC users who span regions.
  - **R1 (later): every relay we run is metered, and all of them are
    allowlisted.**
    - The relay is patched to export byte counters per
      `(source peer, destination peer, direction)`.
    - Per-peer totals are not enough: they cannot exclude sessions with an
      edge peer. If direct WireGuard to the edge fails, the exit traffic
      itself is relayed and is already counted by the nft counters.
    - Each relay reports to the backend alongside the edges. Peers are
      identified by the relay's hashed WireGuard key; vali maps that hash to
      a `vm_id` from the NetBird peer list.
    - Excluded from billing: pairs that include an edge peer, and pairs
      where both ends are VMs in the same region.
    - The patched relay also enforces an aggregate byte-rate bucket per
      source peer. That bucket is the relay-side share of the VM's cap. A
      per-connection limit would multiply with parallel connections.
    - Prerequisite: NetBird management advertises only our relays, and no
      public TURN.

  §12, Q3 asks which option to take.
- Whichever option is taken, the backend refuses tenant NetBird routers and
  network resources that cover `0.0.0.0/0` (or overlap the egress route) for
  groups that contain edge-region VMs. This is defence in depth, and it
  avoids confusing breakage. The allowlist is what actually enforces.

### 6.6 Fail closed

- **Edge down:** the exit route stays installed (`keep_route`), its traffic
  blackholes, and the host allowlist stops any fallback to the miner NAT.
  The region's VMs lose internet. Overlay links inside
  the region and the browser terminal keep working.
- **miner-agent cannot fetch or apply the policy:** a host in an edge-mode
  region that has no applied policy refuses launch and migrate-in orders.
  The last applied ruleset is persisted, and a systemd unit loads it
  `Before=libvirtd.service`, so a reboot never opens the bridge.

### 6.7 The miner is untrusted

A malicious miner can remove the table.

- The meter does not depend on the miner. Bypass costs the miner its own
  uplink and costs us revenue; it never makes the edge over-bill.
- Detection has three parts:
  1. The heartbeat carries `net_policy_revision` and the SHA-256 of
     `nft -j list table inet hippius_guest`. vali flags a mismatch. This
     only catches honest misconfiguration, since a miner can lie.
  2. **Bypass probe.** The `hippius-probe` tenant runs canary VMs in every
     edge-mode region. vali rotates their placement across the region's
     miners so every miner is visited at least once a day. Every 5 minutes
     the canary:
     - sends traffic on `eth0` that bypasses the exit route (for example
       `SO_BINDTODEVICE`, and a `0x1BD00` fwmark): TCP 443 to an external
       echo host, UDP to a random external `IP:port`, ICMP, DNS to `8.8.8.8`,
       TCP 25 to a sink, and a connection to a non-edge NetBird relay. Every
       one of these must fail.
     - sends traffic through the default route. It must succeed, and the
       echo host must report source `E`.

     Any unexpected success raises an alert and sets the miner's
     `egress_enforcement=failed`. vali then stops placing edge-region VMs on
     that miner and drains it.
  3. Edge-side sanity: a VM whose NetBird peer is connected but whose egress
     and relay counters stay at zero for days gets reported. This is a weak
     signal and only helps triage.
- **Accepted residual risks:**
  - A miner that colludes with a tenant can run a UDP proxy on its own
    address, which is in `region_miners`. It carries that traffic on its own
    uplink.
  - DNS and signal tunnels exist, but the meters bound them to tens of KB/s.

## 7. Pushing the policy to miners

The allowlist changes when edges, NetBird infra peers or the region's miners
change. This happens rarely, but it must not need an Ansible run on
operator-owned hosts.

- Add a new `OrderKind::NetPolicy` in `binaries/miner-agent/src/orders/types.rs:38-77`.
  It is signed and delivered the same way as the other orders
  (edge-gateway `order_signing.rs` to miner-agent `/v1/miner/order/net-policy`).
  Body:

  ```
  { revision, region, mode: "local"|"edge", enforce: bool,
    uplink_hint?, infra: [{ip, proto, port}], region_miners: [ip],
    nb_control: [ip], dns_limit_pps, vm_caps: {vm_id: mbps} }
  ```

- **Replay protection.** Every `NetPolicy` stays validly signed forever, so
  an old `{enforce: false}` order must not be able to reopen a host.
  - miner-agent persists `(region, revision, content_sha256)`.
  - It refuses any order with a lower revision, and any order with the same
    revision but different content.
  - A rollback is a **new, higher** revision with `enforce: false`.
  - The order also carries `not_after` (for example 24 h). vali re-signs
    within that window. A host whose policy expires keeps enforcing the last
    edge-mode policy; it never falls back to open.
- vali sends it when `EgressRegion.revision` or the inputs change, and
  re-sends it every 10 minutes to repair drift. miner-agent:
  - applies it atomically (`nft -f`);
  - persists it;
  - applies `vm_caps` live with `virDomainSetInterfaceParameters`
    (`virsh domiftune --live --config`) on each of its domains, setting
    outbound and inbound at the cap. In edge mode the miner cap is
    `cap × 1.1`, which leaves room for WireGuard overhead and still protects
    the miner uplink.
  - reports `net_policy_revision` and the ruleset hash in the heartbeat.
- **Effective cap (§7.1)** is carried in `LaunchOrder` (`orders/types.rs:185-287`)
  as an optional `net_cap_mbps`. It also goes in `MigrateActivate`, whose
  `into_launch_order()` builds the target's launch order, and in relaunch
  orders, so a migrated VM is capped from its first packet on the target.
  `qemu_config.rs:362` emits `<bandwidth><inbound average=…/><outbound average=…/></bandwidth>`
  so the cap is there from first boot.
  - Domain XML is not a measured launch input. Only OVMF, kernel, initrd,
    cmdline and vCPU count are measured (`infra.rs` notes the same for
    `<vsock>`). The measurement is unaffected.
  - libvirt's `outbound` is ingress policing on the tap: it drops rather
    than shapes. That is acceptable as a backstop. In `local` mode it is the
    only cap.
  - **Units.** libvirt `average`, `peak` and `burst` are in KiB/s and KiB,
    so `average = mbps × 125000 / 1024`, rounded down. Set
    `peak = average`, and `burst` = 10 ms at the rate with a 64 KiB minimum,
    the same rule as the edge's `htb_burst_bytes`
    (`backend:edge/public_ip.py:693-699`). Apply `domiftune` with both
    `--live` and `--config`, so a running domain changes now and a
    restarted one keeps the cap.

### 7.1 One effective cap per VM

vali computes `effective_cap_mbps(vm)` from `cap_mbps_by_flavor[flavor]`,
falling back to `default_cap_mbps`. Every enforcement point uses that one
number:

- the edge egress class;
- the edge public-IP class: the address entry carries its holder's
  effective cap, and the edge-wide `per_ip_mbps` becomes only the fallback
  for an entry without one;
- the relay bucket under R1;
- the miner libvirt cap, at ×1.1 in edge mode.

Attaching a public IP no longer changes a VM's cap.
- The infra (attestor) VM shares `virbr0`. Its network needs, if any beyond
  vsock, must be added to `hippius_infra`. If they cannot be pinned, move it
  to its own libvirt network (§12, Q8).
- Port 25 and the `virbr0 → !uplink` drop apply in **both** modes. Shipping
  them is step 1 of the rollout. The second rule also closes an existing
  leak: today a guest can reach the overlay through the host's `wt0`, under
  the miner's NetBird identity.

## 8. Billing (backend)

The details live in `backend:docs/design/egress-and-bandwidth.md`. In
summary:

### 8.1 Prices

- `ComputePrice` gets per-region rows `bandwidth:<region>`, unit `gb`. Each
  row's `unit_price` is the **overage** price per GB out. A new nullable
  column, `included_bytes_per_month`, holds the allowance per VM per month.
- The row stays append-only. A change of allowance is a new row, so a past
  hour is always priced and allowanced as it was.
- **Unlimited:** `unit_price = 0` and `included_bytes_per_month IS NULL`.
  XE is seeded this way.
- **Fallback, `local` regions only:** a `local` region without a row falls
  back to the legacy `bandwidth` row, which is 0 and therefore unlimited.
- **No fallback for `edge` regions:** an `edge`-mode region without a row
  raises `MissingPrice`. The close then stops and alerts, as it does for any
  catalogue gap (`backend:compute/usage.py:566-572`). An edge region is
  never silently free.

### 8.2 Usage

- New `VmEgressUsageSample(vm, edge_name, region, source ∈ {egress, relay, hairpin}, epoch, bucket_start, bytes_in, bytes_out, pkts_in, pkts_out)`.
  It is unique on `(edge_name, vm, source, epoch, bucket_start)` and has a
  companion counter model keyed by `(edge, vm, source, epoch)`, mirroring
  `PublicIpUsageSample` / `PublicIpUsageCounter`
  (`backend:compute/models.py:1119-1176`).
- `parse_report` / `ingest` (`backend:compute/public_ip_usage.py:68,134`)
  take the new `vms` map with the same delta and baseline rules, keyed by
  `(edge, vm_id, source, epoch)`.
- Public-IP samples are re-keyed the same way, by
  `(edge, address, vm_id, epoch)`. A bucket that straddles a lease change is
  split, instead of going whole to the first holder.
- A `vm_id` that vali has not served to that edge in the egress block during
  the last hour is refused and logged.
- **Outbound only, everywhere:** the bandwidth line for public-IP traffic
  switches from `b_in + b_out` (`usage.py:723-724`) to `b_out`. The price is
  0 today, so this changes no amount.

### 8.3 Region of a byte

- The rule shown to customers: **bandwidth is priced where the VM runs**,
  not where the edge is. That makes a foreign-edge public IP useless as a
  loophole.
- `ComputeVM.placed_region` is current state. A delayed sample (the edge
  queues up to an hour) could therefore be priced in the region the VM has
  since moved to. So the region is fixed at the source instead:
  - vali puts `vm_region` on every `vms` entry and on every address entry of
    the feed. Any change of it bumps `epoch`.
  - The edge echoes `vm_region` in each sample.
  - The backend stores it on the sample row, which needs a new `region`
    column on `PublicIpUsageSample`.
- A sample without a region is held, not priced, and an alert fires. It
  never falls into the free fallback.

### 8.4 Allowance: hourly accrual, pooled per VM per calendar month (UTC), derived from the ledger

A written hour is frozen, and its hash is what the chain is charged under
(`backend:compute/usage.py:50-57`). So the pool is not kept in a side table
that could drift from the ledger. It is read back from the frozen lines of
the month's earlier hours. Each VM-hour with bandwidth activity or accrual
writes up to three lines, `ref=vm_id`, unit `gb`, quantities in bytes:

| resource | quantity | price |
|---|---|---|
| `bandwidth_allowance:<region>` | bytes accrued this hour | 0 |
| `bandwidth_included:<region>` | bytes out covered by the pool | 0 |
| `bandwidth:<region>` | bytes out over the pool | the overage price |

The close first adds up every outbound source (public IP, egress, hairpin,
relay) per `(vm, region, hour)`. It then updates the pool once from that
total, so two sources can never each draw on the same allowance. Per VM and
region it computes:

- the accrual: `floor(included_bytes_per_month × billed_vm_seconds_this_hour / seconds_in_this_UTC_month)`,
  using the row in force. `billed_vm_seconds_this_hour` comes from the VM's
  own lines in the same close, so the accrual follows exactly what the VM is
  billed for. A stopped VM keeps its segment open and keeps accruing
  (`backend:compute/models.py:1584-1592`).
- `available = Σ allowance − Σ included`, summed over the month's earlier
  frozen lines, plus this hour's accrual.
- `included = min(bytes_out, available)`
- `overage = bytes_out − included`

The pool never goes negative, and a frozen hour never changes. The month
boundary resets the pool, with no carry-over.

`recompute_compute_usage_hour` rewrites one unsent hour. Any later hour of
the same month that is already closed was computed against the old pool.
The command therefore preflights the month:

- if every later closed hour of that user's month is still replaceable
  (`SHADOW` / `PENDING`, `backend:compute/usage.py:878-883`), it recomputes
  them all, in order, in the same run;
- otherwise it refuses.

The difference is then settled by an explicit adjustment, never by
rewriting a sent hour.

### 8.5 Double counting, summarised

| Risk | Why it cannot happen |
|---|---|
| A public-IP VM also counted as an egress VM | vali keeps group membership exclusive (§5.1). The edge drops an attached N from `vms` (§5.3.1). P counters match on P, egress counters on `ct original saddr ∈ egr_vms`. One packet matches one set. |
| Exit traffic counted by both the nft counters and the relay meter | Under R1 the relay counts per peer pair, and pairs with an edge peer are excluded (§6.5). Under R2 there is no relay. |
| A hairpin counted on both ends | Each side is billed only for what it **sends** (the sender's `hairpin` out counter, §5.3.4). The receiver's count is "in", which is free. |
| A recycled overlay IP billed to the old VM | Counters are keyed by `(vm_id, N, epoch)`, and `vm_id ↔ N` is one-to-one in the feed. The edge flushes conntrack for removed or retargeted N before it acknowledges (§5.3.6). A VM joins only after that (§5.1). The backend refuses vm_ids not served to that edge. |
| A public IP reassigned inside a 5-minute bucket | Samples are keyed by `(edge, address, vm_id, epoch)` (§8.2). |
| Two sources drawing the same allowance | All sources are summed per `(vm, region, hour)` before the single pool update (§8.4). |
| Miner host counters | Never billed. Visibility only. |
| Two edges in a region (phase 2) | A packet traverses one edge. Samples are keyed by `(edge, vm)` and summed. |
| A late or replayed sample | Monotonic totals, a lower total is treated as a reset, and replays are ignored, as for public IPs today. Late hours stay frozen, which under-bills and never over-bills. |

### 8.6 Console

- `price_list` (`backend:compute/billing.py:380-416`) keeps
  `bandwidth_per_gb` for compatibility and adds:

  ```json
  "bandwidth_by_region": {"XE": {"mode": "local", "unlimited": true, "cap_mbps": {...}},
                          "XA": {"mode": "edge", "unlimited": false,
                                 "included_bytes_per_month": "...", "overage_per_gb": "...", "cap_mbps": {...}}}
  ```

  The create page shows "Bandwidth: unlimited" or "X TB included per month,
  then Y credits/GB" for the chosen region, together with the flavor's cap.
- `vm_dict` (`backend:compute/views.py:375-448`) gains:

  ```
  bandwidth: {region, unlimited, cap_mbps, included_bytes_month, accrued_bytes_month,
              used_out_bytes_month, overage_bytes_month}
  ```

  `GET /vms/<id>/traffic/` generalises the public-IP usage series
  (`backend:compute/views_public_ip.py:544-575`) to all sources.
- Bandwidth stays out of the burn rate (`backend:compute/billing.py:92`),
  because it is usage-based. The VM page shows the month-to-date overage
  instead.

## 9. Edge capacity and monitoring

Every byte of an edge-mode region passes through the edge: in and out,
egress, ingress replies, public-IP traffic and relayed overlay traffic.

- **The NIC carries each byte twice:**
  - once inside WireGuard between the miner and the edge;
  - once in the clear between the edge and the internet.

  Relayed traffic under R1 also crosses twice. Size RX and TX separately:
  - `TX ≥ peak VM egress (to the internet) + peak VM ingress (into WireGuard towards miners) + relay out`
  - `RX` is the mirror image.

  Example: 100 VMs at 20 Mbit/s each way need about 4 Gbit/s RX **and**
  4 Gbit/s TX, which a 10 Gbit/s full-duplex port carries with headroom.
  The provider's billed volume is a separate number, often RX + TX octets
  summed. Many providers in expensive regions count both directions.
- **The miner uplink still carries every byte**, inside WireGuard with
  roughly 4-5% overhead. Only a private network between miners and the
  edge takes it off the public uplinks. Third-party miners sit on public
  uplinks, so the region's edge sees all of their traffic as internet
  traffic. The edge-mode price must cover the edge's traffic. The
  miner's own uplink cost is the miner's.
- **CPU:** run kernel WireGuard on the edge, not netbird userspace. One core
  handles roughly 1-2 Gbit/s; plan multi-queue NICs and RPS. tc HTB under a
  single root lock limits each interface to a few Gbit/s. Past that, use
  `mq` with per-queue HTB, or EDT/BPF shaping.
- **conntrack:** size `nf_conntrack_max` for the region's concurrent flows,
  for example 1M entries at about 300 MB. The UDP timeouts already set in
  `backend:edge/ansible/site.yml:34-41` stay.
- **SNAT port space:** with one E there are about 64k concurrent flows per
  `(destination IP, destination port, proto)`. If many VMs talk to one hot
  endpoint, add a second egress address and hash VMs across them.
- **Metrics, exported by the edge agent and alerted on in Grafana:**
  - NIC bits/s and packets/s against capacity and the provider quota;
  - WireGuard peer count and handshake age;
  - conntrack fill;
  - per-class tc drops;
  - top-N VMs by bytes out;
  - relay sessions and bytes;
  - `desired - applied` revision lag;
  - age of the oldest unsent usage sample;
  - the result of the bypass probe;
  - E on a blocklist (Spamhaus and others).

## 10. Rollout

One region first (`XA` here), behind the per-region flags. Every step can
be reverted on its own.

0. **Prerequisites:**
   - Answer §12.
   - Verify the NetBird server topology (§6.3) and split the relay off if
     needed.
   - Provision E on the XA edge and size the edge (§9).
   - Confirm that XA miners run the vsock KBS proxy.
1. **Everywhere, no billing impact:** ship the miner-agent `NetPolicy` order
   in `local` mode. It carries:
   - the port-25 drop and the `virbr0 → !uplink` drop;
   - the input restrictions;
   - the per-VM libvirt caps;
   - deterministic tap names, `clean-traffic` and isolated ports (§6.1);
   - the infra VM on its own network.

   Also ship the edge port-25 drop for public IPs, and the port-25 refusal
   for guardian endpoints.
2. **Backend, shadow:**
   - add the models, `bandwidth:<region>` rows (XE 0, XA 0 for now), egress
     ingest and the console fields;
   - switch public-IP bandwidth to outbound only.
3. **Edge agent:** deploy the egress support. An empty `egress` block is a
   no-op, so this is safe before any VM uses it.
4. **XA routing for canaries:**
   - set `EgressRegion(XA, mode=edge, routing_enabled=true, enforce=false)`,
     limited to the probe tenant and opt-in VMs (an allowlist of vm_ids in
     vali for this step);
   - check SNAT to E, the counters against `iperf3` byte counts on both
     ends (including hairpins), and the caps in both directions;
   - check that conntrack is flushed on a retarget;
   - under R1 only, check that the relay meter attributes peer pairs.
5. **XA routing for all VMs:**
   - Existing VMs need no restart. vali moves their peers into
     `hippius-egr-vms-XA`, and NetBird installs the route live.
   - Open connections reset because the source address changes from the
     miner's IP to E. Announce a window.
   - Add `hippius-wait-egress` to `userdata_netbird.yaml` right after
     `netbird up`. It waits until `ip route get 1.1.1.1` goes through `wt0`,
     with a 180 s timeout, so user `runcmd` steps that need the internet do
     not race the join.
   - Document that cloud-init `packages:` and `apt` steps that run before
     `runcmd` have no internet in edge-mode regions.
6. **Enforce:**
   - set `enforce=true` and push the allowlist to XA miners;
   - start the bypass probe;
   - run the anti-bypass test matrix below on a staging XA miner first.
7. **Bill:**
   - shadow-meter for at least two weeks, with per-VM usage visible on the
     VM page;
   - then append the XA `bandwidth:XA` row with the agreed allowance and
     overage, `effective_from` = the first day of a month, announced in
     advance.

**Anti-bypass test matrix** (staging, then the probe in production):

1. `netbird down`; `netbird up --disable-client-routes`;
   `ip route replace default via 192.168.122.1`; and sockets marked with
   `0x1BD00`. Each must give no internet.
2. Direct TCP, UDP and ICMP to the internet, and DNS to external resolvers.
   All must be blocked.
3. DNS tunnelling (iodine) through dnsmasq. Throughput must be at or below
   the meter limit.
4. Traffic from `virbr0` to the host's `wt0` address, the overlay, or the
   host's public IP. All must be dropped, except DHCP and DNS to the bridge.
5. IPv6, both RA-configured and static. Must be dropped.
6. A connection to any relay or TURN server that is not ours, and
   WireGuard to the IP of a miner in another region. Both must be blocked.
7. A tenant NetBird router `0.0.0.0/0` on the tenant's XE VM, distributed to
   the XA VM. The backend must refuse it. If it is forced through anyway,
   the traffic must fail under R2, or be metered by our relay under R1.
   Never free.
8. XA VM to another tenant's P on the same edge. It must be hairpinned, SNAT
   to E, and counted.
9. Edge stopped. The region's VMs must have no internet and must not fall
   back to the miner NAT.
10. Spoofed source IP, MAC or ARP from the guest on `virbr0`. `clean-traffic`
    must drop it, and the DNS and signal meters must stay per tap. On the
    overlay, the edge's WireGuard accepts only inner source N/32 from the
    VM's peer (cryptokey routing), so the edge attribution cannot be spoofed.
11. TCP 25 out from a VM without a public IP, from a VM with one, and in
    `local` mode. All must be dropped. A guardian endpoint on port 25 must
    be refused.
12. A long-lived flow opened through the miner NAT before `enforce`, for
    example a TCP stream or a UDP stream. It must die when `enforce` is
    applied.
13. Replay an older, validly signed `NetPolicy` with `enforce: false`. It
    must be refused.
14. An egress VM that is removed from the feed while a flow is open. The
    flow must stop at the edge (the exit guard runs before `established`)
    and must not continue uncounted.

**Rollback, per step, in reverse order:**

- Append a `bandwidth:XA` row at price 0 with a null allowance, effective
  now. Billing stops.
- `enforce=false`, pushed as a **new, higher** policy revision: miners drop
  the allowlist but keep port 25.
- `routing_enabled=false`: vali empties `hippius-egr-vms-XA`, VMs return to
  the miner NAT, and the edge renders no egress.
- `mode=local`.

The miner caps and the port-25 drop stay in place.

## 11. Later phase: edge egress everywhere, with HA

Once every region has two edges, edge mode can become the default
everywhere. XE stays at price 0 and unlimited, but gains a clean egress IP
and metering for visibility. HA needs the following:

- **Two exits per region.** Both edges sit in `hippius-egr-gw-<region>`. The
  route uses `peer_groups`, which NetBird turns into an HA route: each
  client uses one router at a time. The client picks by metric, then
  prefers a direct connection over a relayed one, then latency, and
  re-selects when the router disconnects. The pinned client version must be
  tested for this.
- **The data plane is not health-checked by NetBird.** An edge whose
  WireGuard is up but whose SNAT is broken keeps attracting traffic. The edge agent needs
  a self-check: SNAT probe, nft table present, tc present, sample queue
  healthy. On failure the edge withdraws itself (vali removes it from the
  gw group, or the agent stops `netbird`). vali also drains an edge whose
  applied revision lags.
- **Egress address:**
  - **(a) Two egress IPs, one per edge.** Simple, with no shared L2.
    Customers get a documented set. Flows reset on failover.
  - **(b) A shared IP with failover:** keepalived/VRRP when both edges share
    an L2, or the provider's floating-IP move API, which takes seconds to a
    minute. Add `conntrackd` so that flows survive failover.

  Recommendation: (a) first, with (b) only where the provider offers a
  movable IP.
- **Public IPs** need the same: `PublicIP.edge` becomes "home edge" plus a
  movable address, with the desired state served to both edges and the
  route repointed by vali.
- **Relays:** both edges run one, and both are in the allowlist.
- **Allowlist:** both edges are in `hippius_infra`. Fail-closed then means
  both edges must be down before the region loses internet.
- **Caps:** each edge enforces the full cap on its own classes. A client
  that switches router gets, for that moment, a fresh class on the other
  edge. NetBird keeps one router per client, so the cap is not doubled in
  steady state. This is accepted.
- **Capacity:** N+1. Each edge is sized for the full region load in §9.
- **Billing:** no change. Samples are keyed by `(edge, vm)` and summed.

## 12. Open questions

1. **XA allowance and overage price.** A starting point to discuss:
   - allowance: 1 TB out per VM per month for small flavors, 2-5 TB for
     larger ones (or flat);
   - overage: priced from the edge's bandwidth cost per GB, in credits.
2. **Cap in Mbit/s per flavor.** Suggested: 100 Mbit/s for 1-2 vCPU,
   250 Mbit/s for 4 vCPU, 500 Mbit/s for 8+ vCPU, and 1000 Mbit/s for a
   public IP (`per_ip_mbps` today). Should the XE cap be the same?
3. **Relays for edge-region guests (§6.5).** My recommendation is to launch
   XA with R2 (no relay; overlay links to peers outside the region do not
   work) and to build R1 (every relay we run patched to meter per peer pair,
   all of them allowlisted) afterwards. Is the R2 regression acceptable for
   XA?
4. **NetBird server topology.** Is `vpn.hippius.network` one address serving
   management, signal and relay on `:443`, and is it behind a shared proxy? It
   must be dedicated, and the relay must be separate (§6.3).
5. **M1/M2 customer-keys VMs** run with `--disable-client-routes`, so they
   never get the exit route. In an edge region they would have no internet
   at all. Should they be refused in edge regions, or get a guest-managed
   static WireGuard to the edge? The same flag already means an M1/M2 VM
   with a public IP egresses through the miner today.
6. **Public IP fallback to another region's edge** (`service.py:319-333`).
   Close it for edge-mode regions?
7. **Shared egress IP E:** confirm one dedicated address on the XA edge, the
   process for a tenant to request a port-25 unblock (if any), and 90-day
   retention of the NAT log.
8. **The infra attestor VM** moves to its own libvirt network (§6.1). What
   network does it actually need beyond vsock? `infra.rs:24-27` says it
   "reaches the outside world over NAT egress".
9. **Allowance pool scope:** per VM (this spec), or pooled per user and
   region as some providers do?

### Decisions (2026-10-06)

The open questions above are settled as follows:

1. **Price in an edge region**: start with shadow metering: a
   `bandwidth:<region>` row at 0. Once priced, a VM gets `<N>` TB per month
   included, then `<P>` credits per GB; the final numbers come after two
   weeks of measured traffic.
2. **Caps**: one cap per flavor size (small / medium / large), the same in
   `local` and `edge` regions. A public IP keeps the edge's per-IP cap
   (`per_ip_mbps`), which must stay within the hosting provider's per-IP
   bandwidth limit.
3. **Relays**: the first edge region launches with no NetBird relay. Metered relays come later.
4. **vpn.hippius.network**: the compute side checks its topology; dedicated
   addresses for management, signal and relay are a prerequisite of enforcement.
5. **Customer-keys (M1/M2) VMs** are refused in `edge` regions for now.
6. **Cross-region public IP fallback** is closed: a VM in an edge region only gets an address in its own region.
7. **Shared egress IP** per region: yes. Outbound TCP 25 can be unblocked on
   request through a support ticket. NAT logs are kept 90 days.
8. **Attestor VM network**: decided by the compute side during step 1.
9. **Allowance** is per VM.

Split: the compute side (vali, miner policy order, edge agent; rollout steps 1,
3-6) is done in this repo; the backend side (rollout step 2) in
hippius-backend.

## 13. Review notes

An independent review of this spec looked for bypass holes and double
counting. These findings were folded in:

| Finding | Where it is closed |
|---|---|
| A replayed old `NetPolicy {enforce:false}` reopens a host | §7: monotonic revision with content hash, rollback as a higher revision, `not_after` |
| Pre-existing miner-NAT flows survive `enforce` | §6.2: checks on every original-direction packet, plus a conntrack flush |
| `virbr0` is shared L2, so `ip saddr` meters are spoofable and the infra VM can be impersonated | §6.1: per-tap identity, `clean-traffic`, isolated ports, infra VM on its own network |
| vsock KBS and guardian relays egress through the host | §6.4: declared bounded channels with per-VM byte rates; guardian refuses port 25 |
| DNS and signal tunnels | §6.2, §6.4: per-tap meters, declared bounded exemption |
| Edge-local services reachable from the overlay | already closed by `overlay_to_host` (`backend:edge/ansible/templates/host-fw.nft.j2:47-61`), now a stated requirement (§6.2) |
| A colluding miner proxies via `region_miners`; sibling VMs share caps and allowances | §6.5, §6.7: accepted residual, documented |
| "Port 25 blocked" overclaims | §1: scoped to the outer destination port |
| Per-peer relay counters cannot exclude edge sessions; a per-connection relay cap multiplies | §6.5: counters per peer pair, aggregate per-peer bucket (R1) |
| Pinned NetBird picks the relay per pair, so a single-relay allowlist breaks sessions | §6.5: R2 at launch, R1 = every relay we run is metered |
| fwmark collisions with NetBird; HTB direct queue fails open; reused class ids | §5.3.6: IFB upload shaping without marks, capped default class, stable leased `class_id` |
| Egress-to-public-IP hairpin is neither billed nor capped | §5.3.4: sender `hairpin` counter; IFB shapes every upload |
| A recycled overlay IP keeps stale conntrack; a removed VM's flows continue uncounted | §5.2, §5.3.3, §5.3.6: one-to-one feed, epoch, exit guard before `established`, flush before apply |
| Cap differs by path and is lost on migrate; libvirt units | §7, §7.1: one effective cap, carried in launch, migrate and relaunch; KiB/s conversion |
| Public-IP samples keyed by address across lease reuse | §5.3.7, §8.2: `(edge, address, vm_id, epoch)` |
| Mutable region; free fallback for unknown regions | §8.1, §8.3: region fixed at the source; no fallback for edge regions; unknown regions held |
| Sources double-drawing the allowance; 730-hour month; recompute | §8.4: aggregate first, real month seconds, preflight before recompute |
| NIC sizing mixed duplex directions | §9: RX and TX sized separately |

