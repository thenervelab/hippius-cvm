# Design: Hippius CDN, a managed CDN on confidential cache nodes

**Status:** Proposed (spec only, nothing implemented) · **Date:** 2026-10-06

This spec spans this repo (the cache node image and guest agent, vali fleet
orchestration, the KBS) and `hippius-backend` (zones, the node feed, Route 53,
metering, billing, console API). Backend paths are cited as
`backend:<path>:<line>` against `origin/main` of `thenervelab/hippius-backend`.
The backend half is summarised in `backend:docs/design/cdn.md`.

## 1. Goal

Ship a managed CDN, complete at GA:

- **Cache nodes run by Hippius in several regions:** FR/EU and AU today, NL
  next. Each node is an SEV-SNP confidential VM on a miner, so the miner
  cannot read cached content or customers' TLS private keys.
- **Origins:**
  - a Hippius S3 bucket, first-class, including private buckets read through
    a signed origin credential;
  - any HTTP(S) origin, such as a customer site or API.
- **Hostnames:** `<id>.c.hipcdn.net` by default, plus custom domains by
  CNAME (or ALIAS/ANAME at the apex). TLS is automatic through ACME.
  Certificates are issued, stored and renewed inside the CVMs.
- **GeoDNS on AWS Route 53**, health checked per regional node, with
  failover between regions.
- **Features:**
  - cache rules and purge;
  - custom headers, CORS, gzip/brotli, range requests;
  - an origin shield;
  - per-zone stats;
  - signed URLs.
- **Billing** through the hourly usage ledger: `cdn_egress:<region>` per GB,
  `cdn_requests` per 10k requests, and an optional fee per custom domain.
  The meter is the cache nodes we run, never the miners.
- **Console and API**, with a `cdn` scope for account sharing.

Non-goals at GA: video packaging or transcoding, image optimisation, edge
compute (workers), WAF rule sets, IPv6, and HTTP/3. Each is a later phase.

## 2. What exists today, and what we reuse

| Need | What exists | Where |
|---|---|---|
| Confidential VM with encrypted disk | SNP launch, measured kernel/initrd/cmdline, KBS-released LUKS2 + dm-integrity upper, `/var/lib/hippius-data` bind | `binaries/miner-agent/src/lifecycle/qemu_config.rs:333`, `docs/design/golden-data-path.md:10-12,18-39,55-68` |
| What a miner can and cannot see | the matrix; metadata the miner sees by design | `docs/security/data-visibility.md:101-122,217-234` |
| User-data reaches the guest via the KBS, not the miner | the user-data rows are N for the miner | `docs/security/data-visibility.md:106,116-117` |
| Region = verified country of the miner; region-pinned launch, no fallback | `region` on the launch intent | `vali/apps/orchestration/schemas.py:126-139`, `docs/design/miner-geolocation.md:61-67` |
| Public IPv4 on a rented ingress edge, DNAT over NetBird to the VM | `IngressEdge`, `PublicIP`, edge feed | `vali/apps/network/models.py:42-119`, `docs/design/public-ip.md:21-29,149-173` |
| Edge sees clear traffic only if the workload does not encrypt | threat notes | `docs/design/public-ip.md:208-214` |
| One edge per region, no failover yet | | `docs/design/public-ip.md:227-230`, `docs/design/egress-and-bandwidth.md:983-1020` (§11) |
| Edge usage samples: monotonic totals every 60 s, 5-min buckets, reset/baseline rules | public-IP ingest | `backend:compute/public_ip_usage.py:37-45,68-190`, `backend:compute/views_public_ip.py:588-612` |
| Hourly ledger, frozen hours, on-chain hash | `ComputeUsageHour`/`ComputeUsageLine`, `compute_hour`, `close_hour` | `backend:compute/models.py:1636-1796`, `backend:compute/usage.py:1-69,702-884` |
| Lines not tied to a VM | `db_fee` / `k8s_fee`, ref `db:<pk>` / `k8s:<pk>` | `backend:compute/models.py:1769-1783`, `backend:compute/managed_fees.py:1-50` |
| Append-only price catalogue | `ComputePrice` (units `hour`, `gb`, `gb_hour`, `bp`) | `backend:compute/models.py:1475-1524` |
| Read-only bucket credential minted by the backend | `SubToken.mint(..., actions=["read","list"])` + gateway scope | `backend:compute/backups.py:55,151-179,564-569`, `backend:objectstore/models.py:107-181` |
| Hippius S3 gateway | `s3.hippius.com` | `backend:api_backend/settings.py:1078` |
| Edge-agent pull with ETag | `poll_routes` | `backend:edge/agent.py:1140-1178`, `backend:compute/views_exposure.py:257-287` |
| Account sharing scopes | `PRODUCTS`, `GROUPS` | `backend:accounts/grants.py:14-20`, `backend:docs/accounts.md:34-58` |

What does not exist anywhere: Route 53 or any runtime DNS code, per-tenant
ACME, a Hippius-operated fleet of tenant-shaped CVMs (the only infra CVM is
the per-miner `host-attestor`, `binaries/miner-agent/src/lifecycle/infra.rs:1-51,65`),
and host anti-affinity (issue #1366, open; today only a soft same-family
penalty, `vali/apps/scheduler/placement.py:200-206`).

The existing HTTP edge (`backend:edge/haproxy/haproxy.cfg:55`) terminates TLS
with one wildcard certificate obtained by certbot DNS-01 against Cloudflare
(`backend:edge/README.md:165-174`, `backend:edge/docker-compose.yml:156-169`).
The CDN must **not** use it: TLS for CDN hostnames terminates inside the CVMs.

## 3. Architecture

```
                       Route 53  (c.hipcdn.net, delegated from hipcdn.net)
                       *.c    --geo-->  region-oc / region-eu  --failover-->  pool-<region> (A, health-checked per node)
                                   |
 client --TLS--> P (public IP on the region's ingress edge) --DNAT over WireGuard--> cache node CVM (miner)
                                                                                          |  miss
                                                                     non-shield node --mTLS--> shield node CVM --HTTPS--> origin
                                                                                          |
                         backend <---- feed (zones, rules, sealed secrets, purges) ---- node agent
                         backend <---- usage samples (per zone, per region, 60 s) ---- node agent
                         vali    <---- launch / replace / drain (fleet reconciler) ---- (control)
                         KBS     ----> fleet key, released only to the measured cdn-node image
```

| Piece | Where | Role |
|---|---|---|
| Cache node | CVM on a miner, image `cdn-node` (§5) | TLS termination, cache, rules, token auth, ACME, counters |
| Node agent `cdn-agent` | in the image, this repo | feed pull, cert store, ACME client, purge generations, usage upload, health |
| Fleet orchestration | vali `apps/cdn` (new), this repo | nodes per region, placement with anti-affinity, public IPs from a CDN pool, replace, drain |
| Fleet key | KBS, new secret class `cdn-fleet` | released only to the measured `cdn-node` image on VMs vali registered as CDN nodes |
| Control plane | backend app `cdn/` (new) | zones, hostnames, verification, rules, purge, feed, stats, billing, console API |
| DNS | Route 53, driven by the backend with boto3 | geo routing, per-node health checks, ACME DNS-01 records |
| Ingress | existing ingress edges, a dedicated CDN address pool | public IPv4 per node, L3 DNAT only; the edge never sees plaintext |

Every node serves every zone (a shared, multi-tenant fleet). A zone is not
pinned to nodes. This keeps DNS per region rather than per customer (§7).

## 4. Trust model

This section is the product's main claim, so it lists what each party can
and cannot see, including what we cannot hide.

### 4.1 What is protected, and from whom

**The claim, in one sentence.** At GA the CDN protects customers from the
**miners**: the machines' owners cannot read cached content, TLS keys or
customer secrets. It does **not** cryptographically protect them from
**Hippius** or from the ingress edge Hippius runs. Both are trusted for
confidentiality, as with any CDN operator. They can see less than a
classic CDN operator (no plaintext at rest, no key material in our
databases), but an active, malicious Hippius has the capabilities listed in
the second table.

**Passive visibility** (what each party sees just by doing its job):

| Asset | Miner (host root) | Ingress edge (ours, rented) | Hippius control plane | AWS (Route 53) |
|---|---|---|---|---|
| Cached objects at rest (disk, RAM) | no: LUKS2 + dm-integrity, SNP-encrypted RAM | no: never stored | no | no |
| Customer TLS private keys | no | no: L3 only, TLS ends in the CVM | no: only ciphertext sealed to the fleet key | no |
| Signed-URL keys, origin credentials, origin headers | no | no | transiently at creation (§4.2), then ciphertext | no |
| Private content behind signed URLs | no | no | no | no |
| Request metadata: client IP, timing, sizes | **direct path only** (§6.2) | **yes** | aggregated counters only (no request logs leave a node by default) | no |
| SNI of each TLS connection | direct path only | **yes**: no ECH at GA | n/a (knows the hostnames from config) | no: it sees query names plus resolver IP or ECS subnet, not connections |
| Origin leg over **HTTPS** | no | n/a | no | no |
| Origin leg over **plain HTTP** | **yes, in clear** | n/a | n/a | no |
| Zone config: origins, hostnames, rules | no | no | **yes**: the backend owns it | no |

**Active capabilities** (what each party could do if malicious):

| Party | Could | Bounded by |
|---|---|---|
| Miner | deny service; observe metadata; on a direct path, answer HTTP-01 for hostnames resolving to its node | edge path at GA (§6.1); CAA pinning (§4.3.4); health-check failover |
| Ingress edge (or its hosting provider) | redirect 80/443 and pass HTTP-01 for any custom hostname **without** a restrictive CAA, then MITM it with a different valid certificate | CAA `accounturi` + `validationmethods=dns-01`; it cannot read existing keys |
| Hippius control plane | disable signed-URL enforcement, repoint an origin, add a hostname, read a private bucket with the credential it minted, bless a malicious image | customer-signed config (a later phase); published measurements and attestation (§4.3.1); CAA |
| Code execution in OpenResty or the agent on any node | read every zone's secrets, certificate keys, ACME account keys and the fleet CA (§4.3.2) | fleet-wide rotation; patching speed |

### 4.2 What the backend sees

- **Config.** The backend stores zone config in clear: origins, hostnames,
  rules and headers. It is not secret, and the console displays it.
- **Secrets are sealed to the fleet public key** (`cdn-fleet`, §5.3) the
  moment they exist, and only ciphertext is stored. This covers signed-URL
  keys, private-bucket credentials, custom origin request headers, and
  customer-uploaded certificates.
  - Customer-uploaded certificate keys are sealed **in the browser**. The
    backend never sees them.
  - Signed-URL keys are generated by the backend and shown once to the
    customer, who must hold them to sign URLs. The backend sees them at
    creation.
  - Private-bucket credentials are minted by the backend
    (`backend:compute/backups.py:551-578` pattern), so it sees them at mint
    time. This adds nothing new: Hippius operates the S3 gateway the bucket
    lives on.
- **Certificates.** Certificate private keys are generated inside a CVM and
  only leave it sealed to the fleet key. The backend stores and relays the
  ciphertext, and keeps the public certificate for the console.

### 4.3 Residual risks we state openly

1. **We build the image.** A malicious or compromised Hippius could bless a
   `cdn-node` measurement that exfiltrates keys. Mitigations:
   - reproducible image builds;
   - the measurement allowlist is published in the docs and changes only
     through the guest component release process
     (`docs/design/guest-component-rollout.md:96-158`);
   - every node serves its SNP report at `/.well-known/hippius-attestation`,
     bound to its TLS key (`REPORT_DATA = sha256(spki)`), so a customer can
     check which measurement served them.

   This reduces the trust placed in Hippius; it does not remove it.
2. **One fleet key, one trust ceiling.** All nodes share the `cdn-fleet` key
   and hold every certificate in memory. Exposing all customers needs
   neither an SNP break nor a hostile miner: a remote-code-execution bug in
   OpenResty or `cdn-agent` on **any** public node is enough. Mitigations:
   - the KBS enforces a minimum TCB;
   - the key is versioned (§5.3);
   - key operations (unseal, ACME, sealing) run in `cdn-agent` under its own
     user, never in the internet-facing OpenResty workers. OpenResty receives
     only the decrypted certificates it serves, through shared memory.
   - per-region or per-shard keys were rejected for GA, because every region
     must serve every hostname. Keyless TLS or zone sharding is the way to
     shrink the blast radius later.

   **Recovery from a suspected compromise** is not a re-seal, because
   re-sealing does not revoke plaintext already copied. It means:
   1. rotate the fleet key and the fleet CA;
   2. re-issue every certificate under new keys and revoke the old ones;
   3. rotate the ACME account keys and update the published `accounturi`;
   4. rotate every private-bucket credential;
   5. ask customers to rotate their signed-URL keys and origin header
      secrets.

   The runbook and a quarterly drill are GA items.
3. **Metadata is not hidden.** The ingress edge sees client IPs, SNI, sizes
   and timing. In the direct path (§6.2) the miner sees them too. ECH is a
   later phase.
4. **Whoever answers for a hostname can get a certificate for it.** This is
   true of every CDN with automatic TLS: a CNAME to us lets the party running
   our nodes pass ACME validation. Two consequences:
   - On the edge path, only Hippius and the edge host are on the port-80
     path. The miner sees WireGuard ciphertext. A malicious edge could still
     pass HTTP-01 (table above).
   - On a direct path the miner is on the port-80 path and could pass
     HTTP-01 for a customer domain with its own ACME account. That is why the
     direct path is gated on CAA pinning (§6.2).

   We tell every customer to publish one CAA record per CA we use, each
   pinned to our account (RFC 8657):

   ```
   CAA 0 issue "letsencrypt.org; accounturi=<our LE account>; validationmethods=dns-01"
   CAA 0 issue "pki.goog; accounturi=<our GTS account>; validationmethods=dns-01"
   ```

   A Let's Encrypt-only record would block our Google Trust Services
   fallback (§8.4). Pinning `dns-01` means the customer must also add the
   DCV CNAME (§8.2). The console shows whether the records are present
   (`caa_pinned`).
5. **Plain HTTP origins are not confidential.** The origin leg leaves the CVM
   in clear through the miner. The console labels such zones "origin leg not
   encrypted".
6. **Hippius controls config.** It could repoint a zone's origin or add a
   hostname. Customer-signed config (the managed k8s envelope pattern,
   `backend:compute/managed_k8s.py:327-367`) is a later phase.
7. **DNS is AWS.** Route 53 sees the queried names under `c.hipcdn.net`
   with the resolver's address or its ECS subnet.
8. **No shell on nodes.** As with managed databases, nodes have no SSH or
   console. Operations see metrics, health and events only.

### 4.4 Metering trust

- Counters are produced inside the CVM by our measured image. They are
  uploaded over TLS and signed with a per-VM node credential that the KBS
  releases only to that registered, measured VM (§9.2).
- A miner can drop or delay uploads, which means under-billing, never
  over-billing. It cannot forge or replay them.
- Miners are never paid per byte, so they have no incentive to inflate.
- Anyone, a miner included, can send requests to a public zone. That is
  billable to the zone owner, exactly as on any CDN. The defences are
  node-side rate limits and blocks, and spend caps (§9.6).

## 5. The cache node (this repo)

### 5.1 Image

- A dedicated golden image, `cdn-node`, baked by `vali/apps/tenant_bake`
  (`scripts/tenant-image-bake.sh`) with a new bake profile that installs the
  CDN packages. `TenantBake` has no package field today
  (`vali/apps/tenant_bake/models.py:175-262`).
- The verity root hash is folded into the SNP-measured cmdline
  (`scripts/tenant-image-bake.sh:1480-1481,1567-1610`). The measurement therefore pins the
  exact CDN software, which is what lets the KBS release `cdn-fleet` to it and
  nothing else. Software installed by user-data would not be measured, so
  user-data carries no software, only the node's identity (region, node id).
- **Data plane: OpenResty** (nginx + LuaJIT), built with `ngx_brotli`. Why:
  - a proven disk cache (`proxy_cache_path`);
  - `slice` for ranges;
  - `ssl_certificate_by_lua` for thousands of SNI certificates loaded from
    memory;
  - shared dictionaries for counters and purge generations.

  A Rust proxy on Pingora was considered. Its open-source cache has no disk
  storage, so we would write one. It is a later option.
- **`cdn-agent`** (Rust, `binaries/cdn-agent`):
  - pulls the feed;
  - unseals secrets with the fleet key;
  - runs the ACME client (`instant-acme`);
  - writes certificates into OpenResty's shared memory, never to disk in
    clear;
  - uploads counters;
  - serves the health endpoint;
  - signs usage reports with the per-VM node credential (§9.2).
- Updates go through the existing guest component and image rollout (canary,
  waves, one node per region at a time; `docs/design/guest-component-rollout.md:713-760`).
  A node is drained (§7.3) before it reboots.

### 5.2 Storage

- The cache lives on `/var/lib/hippius-data/cache`, the guest-keyed LUKS2 +
  dm-integrity volume (`docs/design/golden-data-path.md:18-39`). The miner
  sees ciphertext.
- `proxy_cache_path ... max_size=<75% of the volume> inactive=30d use_temp_path=off`.
  The other 25% is headroom, the same reasoning as managed DB sizing
  (`backend:compute/managed_db.py:19-29`).
- The largest flavor offered by default is `2xlarge`, 16 vCPU / 64 GB / 640 GB
  (`VALI_SCHEDULER_MAX_FLAVOR`, default `2xlarge`,
  `vali/apps/orchestration/schemas.py:40-47`). The catalogue goes up to
  `4xlarge` (`vali/apps/orchestration/services/flavors.py:32-39`), which the
  fleet could use if the cap is raised for it. That gives at most about 480 GB of cache per
  node until extra disks exist. A long tail spreads across the nodes of a
  region; the shield (§10.3) dedups origin pulls.
- Losing a node's cache is not data loss. The origin is the source of truth.

### 5.3 Fleet key and sealed secrets

- **What it is.** A new KBS secret class, `cdn-fleet`: an X25519 keypair plus
  a version number.
- **Release rule.** The KBS releases it only when the VM's measurement is on
  the `cdn-node` allowlist **and** vali registered the VM as a CDN node.
  That is the lifecycle binding: the same per-VM checks as the LUKS KEK
  (`ARCHITECTURE.md:139-210`).
- **What the backend holds.** Only the public half, published by vali, which
  it uses to seal secrets (libsodium sealed box). Nodes unseal in RAM.
- **Rotation.**
  1. vali mints version n+1.
  2. Nodes receive both versions.
  3. A leader node re-seals every blob to n+1 and uploads them.
  4. Version n is retired once no blob references it.
- **Per-VM node credential.** With the fleet key, the KBS releases to each
  VM an Ed25519 key plus a certificate
  `{vm_id, region, generation, not_after}` signed by vali's CDN CA.
  - The KBS release is already bound to that VM's lifecycle and generation,
    so the credential proves "this registered VM, this region, this launch".
  - A quote over guest-chosen fields would only prove that some approved
    image made the key.
  - The certificate lives 7 days and is renewed through the KBS. vali
    revokes it when the node is decommissioned.
- **Inter-node mTLS** (shield fetches, §10.3) uses the same per-VM
  credential. Neither NetBird nor the miner can impersonate a node.

### 5.4 Node sizing (bandwidth-bound)

- A CDN node is limited by network and TLS, not CPU or RAM. Under SNP, virtio
  traffic goes through SWIOTLB bounce buffers, which costs CPU per byte. The
  real figure must be measured before we commit to capacity numbers. That is
  a pre-launch spike: the target is ≥ 2 Gbit/s of TLS egress per `xlarge` node
  (8 vCPU / 32 GB / 320 GB) on a FR miner.
- **Default flavor:**
  - `xlarge` in FR/NL;
  - `large` in AU, where volume is capped by the traffic quota rather than by
    throughput.
- **Per node:** `worker_processes` equal to the vCPUs, 1 GB of `keys_zone`
  (about 8M keys), and a page cache for the hot set.

## 6. Network path

### 6.1 Edge path (launch default)

- Each node holds one public IPv4 on its region's ingress edge
  (`docs/design/public-ip.md:149-173`). The edge does L3 DNAT to the node's
  overlay address over WireGuard. It does no TLS and runs no HAProxy.
- **CDN pool.** CDN addresses come from a dedicated pool: a new
  `PublicIP.pool = "cdn"` in vali. They are never handed to tenant VMs. A
  former CDN address held by a tenant would receive CDN traffic and could
  answer HTTP-01 for our customers' domains.
- **Per-address cap.** The CDN pool is exempt from the per-address cap,
  `per_ip_mbps` (`vali/apps/network/models.py:64-65`; the edge-mode default in
  `docs/design/egress-and-bandwidth.md`). It gets its
  own cap, `cdn_ip_mbps`, sized to the node.
- **Origin fetches** leave through the VM's normal path. In an `edge`-mode
  region (AU) that is the regional egress address E
  (`docs/design/egress-and-bandwidth.md`, §3). The fleet runs under an
  internal tenant whose VM bandwidth is not billed.
- **Cost in bandwidth.** Every delivered byte crosses the miner uplink once
  (inside WireGuard, +4-5%) and the edge NIC twice
  (`docs/design/egress-and-bandwidth.md:835-852`). That is acceptable where
  bandwidth is unmetered. Where outbound traffic is metered by quota it
  spends **two** traffic quotas per delivered byte.
- **Single point of failure.** The edge is one per region
  (`docs/design/public-ip.md:227-230`). Route 53 fails the whole region over
  when the edge dies (§7.3). Two edges per region (egress spec §11) removes
  the regional SPOF and is a GA exit criterion for FR.

### 6.2 Direct path (later, cost optimisation)

- The miner routes an additional public IP straight to the node, through a
  new miner-agent order. This halves the bandwidth spent, which matters in
  AU.
- What it costs in trust:
  - the miner sees client IPs, SNI and timing;
  - the miner is on the port-80 path and can pass HTTP-01 for any hostname
    whose DNS points at that node.
- The direct path is therefore allowed only for zones whose every custom
  hostname has a CAA record pinning our ACME account and `dns-01`. The
  backend checks this daily. Those zones get their own `<id>` record pointing
  at direct pools (§7.2). Every other zone stays on edge pools.

## 7. GeoDNS on Route 53

### 7.1 Zone and delegation

- **Domain.** Customer zones are served under `c.hipcdn.net`, a registrable
  domain of their own (moved from `cdn.hippius.com` on 2026-10-08), so no
  customer content shares a site with hippius.com and its cookies.
- **Hosted zone.** `c.hipcdn.net` is a public Route 53 hosted zone,
  delegated by NS records in the `hipcdn.net` parent zone.
  - Nothing else in the parent zone may sit at or under `c.hipcdn.net`.
  - A CI check (`dig +trace`) alerts if the NS set in the parent and Route 53
    disagree.
- **DNSSEC.** The delegation stays insecure (no DS) at launch. Route 53
  DNSSEC signing (a KMS key) plus a DS in the parent is a later hardening.
- **Staging.** A staging zone `cdn-staging.hippius.com` is delegated the same
  way, for tests.

### 7.2 Records

The records are per region, not per customer. Customer names resolve through
one wildcard.

| Name | Type / policy | Value | Health |
|---|---|---|---|
| `pool-fr.c.hipcdn.net` | A, **multivalue answer**, one record per FR node (`SetIdentifier=node-<id>`) | node public IP | one health check per node |
| `pool-nl`, `pool-au` | same | same | same |
| `region-eu.c.hipcdn.net` | A **alias**, **failover**: PRIMARY → `pool-fr`, SECONDARY → `pool-nl` (→ `pool-au` until NL exists) | Evaluate Target Health = yes | inherited |
| `region-oc.c.hipcdn.net` | A alias, failover: PRIMARY → `pool-au`, SECONDARY → `region-eu` | ETH = yes | inherited |
| `*.c.hipcdn.net` | A alias, **geolocation**: continent `OC` → `region-oc`; **Default** → `region-eu` | ETH = yes | inherited |
| `_acme-challenge.c.hipcdn.net` | TXT | the wildcard order's DNS-01 values | none |
| `<h>.dcv.c.hipcdn.net` | TXT | DNS-01 value for a delegated custom hostname (§8.3) | none |
| `health.c.hipcdn.net` | A | unused; it is the Host header the health checks send | none |

- **Why geolocation rather than latency.** AU capacity is a monthly volume
  and AU is priced higher. Latency routing would send Singapore,
  Japan and India to Sydney: it spends the scarce quota and bills those users
  at the AU price. Geolocation makes the rule simple to state and to bill:
  "Oceania is served from AU, everything else from EU".
- **Fallback.** Geolocation falls back from the continent record to Default
  when the continent record is unhealthy. The failover layer makes the
  fallback explicit either way.
- **Client location.** Route 53 uses the resolver's address or its EDNS
  Client Subnet. Resolvers without ECS are located by their own address.
- **Reserved labels** cannot be zone ids: `pool-*`, `region-*`, `dcv`,
  `health`, `_acme-challenge`, `www`, `api`, `status`. Zone ids are `z` plus
  12 random base32 characters and are **never reused**, so a deleted zone's
  CNAME never resolves to another customer.
- **Per-zone records.** A zone gets its own record only for:
  - direct-path pools (§6.2);
  - a residency pin ("EU only" omits `region-oc`; later);
  - an abuse sinkhole when we must stop resolving it.

  An explicit name overrides the wildcard.

### 7.3 Health checks and failover

- **One health check per node, never per customer.** The cost stays flat in
  the number of zones.
- **Configuration:**
  - type **HTTPS**, `EnableSNI=true`;
  - `IPAddress` = node IP, port 443;
  - `FullyQualifiedDomainName=health.c.hipcdn.net`, served under the
    fleet wildcard certificate;
  - `ResourcePath=/__hippius/health`;
  - `RequestInterval=30`, `FailureThreshold=3`;
  - default checker regions.
- **Why HTTPS.** HTTPS is an optional, paid health-check feature on a
  non-AWS endpoint. A plain HTTP check on port 80 would
  stay green while 443, SNI certificate selection or object serving is
  broken.
  - The HTTPS check goes through the real serving path: TLS, SNI, the
    OpenResty server block, and a cache lookup of a canary object that every
    node holds.
  - Route 53 does not validate the certificate. Our blackbox probe (below)
    does.
- **What `/__hippius/health` checks.** It returns 200 only when all of these
  hold:
  - the cache volume is mounted and the canary object is served;
  - the fleet key is unsealed;
  - the certificate store is loaded;
  - the node is not draining;
  - the region's traffic-quota guard is not tripped;
  - the feed is not **locally** stale. This one means the backend is
    reachable and serving revision R, and the node has failed to apply R for
    more than 5 minutes.
- **A control-plane outage must not take the fleet down.**
  - When the backend is unreachable, every node keeps serving its
    last-known-good config and stays healthy for up to 24 hours. Ops get
    alerted; the nodes do not drop out.
  - The alternative, every node failing health together, would make Route 53
    fail open to possibly dead endpoints while customers lose nothing from
    the stale config, because new purges and zones cannot be issued during
    the outage anyway.
- **Firewall.** Node and edge firewalls must admit the published
  `ROUTE53_HEALTHCHECKS` ranges. The hosting provider's anti-DDoS must not rate-limit them
  (runbook item).
- **Failover times:**
  - a node fails: 3 × 30 s = about 90 s to unhealthy, plus the 60 s record
    TTL. Clients move within about 2.5 minutes, longer behind resolvers that
    stretch TTLs.
  - planned drain: the node fails its health check first, waits
    90 s + 2 × TTL, then stops. No client sees an error.
- **Failure behaviour, from the AWS rules**
  ([how Route 53 chooses records](https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/health-checks-how-route-53-chooses-records.html)):
  - one node unhealthy: it leaves the multivalue answer.
  - every node in a pool unhealthy: the failover alias sees an unhealthy
    target and answers with the secondary region.
  - both primary and secondary unhealthy: Route 53 returns the primary. In
    general, "if no record is healthy, all records are healthy". That is
    **fail-open**: DNS keeps answering, but it may answer with endpoints
    that are really dead. A global health-check fault (for example AWS
    checkers blocked by our firewall) stops the steering. It does not repair
    a real outage.
- **Cross-region failover moves cost and load.** Two cases:
  - **EU to AU:** spends AU quota. The quota guard takes AU out
    before it is exhausted. Billing never charges the customer more because
    of our failover (§9.4).
  - **AU to EU:** Oceania users get about 280 ms RTT instead of about 10 ms.
    Correct, but slow.
- **Monitoring outside AWS.** We do not buy CloudWatch alarms.
  Prometheus blackbox probes the same endpoints from our clusters and alerts.

### 7.4 TTLs

| Record | TTL | Why |
|---|---|---|
| NS delegation in the parent zone | 86400 | stable |
| `pool-*` A records | **60 s** | bounds failover time |
| alias records (`region-*`, wildcard) | n/a: an alias inherits its target's TTL | |
| TXT challenges | 60 s | short-lived |
| SOA negative TTL | 300 s | a freshly created zone resolves within 5 minutes even if someone queried it before it existed |

Raising the pool TTL to 300 s would cut query volume (and cost) by
about 5x, at the price of about 6-minute failovers. Start at 60 s and revisit
once real query volumes are known.

### 7.6 How the backend manages Route 53

- **Module.** `cdn/dns.py` in the backend, boto3 `route53` client, built with
  **explicit** credentials from settings, never the default chain. The pods
  already carry `AWS_S3_*` variables for R2
  (`backend:api_backend/settings.py:557-592`).
- **Credentials.** A dedicated Kubernetes secret, separate from the
  backend's general secret. Its keys:
  - `CDN_AWS_ACCESS_KEY_ID`;
  - `CDN_AWS_SECRET_ACCESS_KEY`;
  - `CDN_ROUTE53_ZONE_ID`.

  How they are used:
  - The pods that run the reconciler (celery worker, beat-triggered tasks)
    and the node-facing views (for DNS-01) load them with an extra
    `envFrom: secretRef`. No other pod gets them.
  - `cdn/dns.py` passes them explicitly:
    `boto3.client("route53", aws_access_key_id=..., aws_secret_access_key=...)`.
  - The values are never in git. `k8s/` only references the secret by name.
- **IAM.** A dedicated IAM user whose policy is limited to:

  ```json
  {"Version": "2012-10-17", "Statement": [
    {"Effect": "Allow", "Action": ["route53:ChangeResourceRecordSets", "route53:ListResourceRecordSets",
                                   "route53:GetHostedZone"],
     "Resource": "arn:aws:route53:::hostedzone/<zone id>"},
    {"Effect": "Allow", "Action": ["route53:GetChange"], "Resource": "arn:aws:route53:::change/*"},
    {"Effect": "Allow", "Action": ["route53:CreateHealthCheck", "route53:GetHealthCheck", "route53:UpdateHealthCheck",
                                   "route53:DeleteHealthCheck", "route53:ListHealthChecks",
                                   "route53:GetHealthCheckStatus", "route53:ChangeTagsForResource",
                                   "route53:ListTagsForResource"],
     "Resource": "*"}]}
  ```

  - Keys rotate every 90 days.
  - Moving to role federation (IAM Roles Anywhere) is a later hardening; the
    cluster has no IRSA.
- **Reconciler.** Celery task `cdn_reconcile_dns`, `single_flight`, every
  minute, plus on demand on node changes. Topology (pools, regions,
  wildcard, health checks) and ACME challenge TXTs are reconciled
  **separately**, so a burst of challenges never delays a failover change.
  Each run:
  1. **Desired state** = vali's CDN node list (`GET /v1/cdn/nodes`: id,
     region, IP, state) × the static region graph (§7.2) × the active
     challenge TXT rows.
  2. **Health checks.** Each node gets
     `CallerReference = "cdn-<node_id>-<ip>-v<config_version>"`.
     `CreateHealthCheck` with the same reference and the same config returns
     the existing check, which makes creation idempotent. Checks are tagged
     `hippius:cdn=1` and `hippius:node=<id>`.
  3. **Records.** Read `ListResourceRecordSets` and diff against the desired
     state. Send `ChangeResourceRecordSets` batches of `UPSERT`s and
     `DELETE`s, each atomic, and wait for `GetChange` = `INSYNC`.
     - **Batch limits.** A batch holds at most 1,000 elements (an UPSERT
       counts twice) and 32,000 characters of values
       ([Route 53 quotas](https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/DNSLimitations.html)).
       Larger diffs are split; topology changes go first, each in a batch
       that is self-consistent on its own.
  4. **Garbage collection.** A health check tagged `hippius:cdn=1` whose node
     is gone is deleted only after the record that referenced it is removed
     and `INSYNC`.
  5. Throttling (`Throttling`, `PriorRequestNotComplete`) backs off
     exponentially. The account limit is 5 requests/s.
- **Failure safety.**
  - A vali timeout, an error or an **empty** node list never counts as
    "no nodes". The run aborts and the last-known-good records stay.
  - A run that would remove more than half of any pool's records, or any
    region's last record, is refused without an operator override
    (`--allow-shrink`).
  - Health checks are the mechanism for taking nodes out quickly; the
    reconciler is not.
- **Ordering rules, which close the dangling-IP class of bugs:**
  - **Add:** a node gets its record only after it is `ready` (health 200
    from our blackbox probe).
  - **Remove:** drain, delete the record, wait for `INSYNC`, wait 2 × TTL,
    and only then decommission the VM and return the IP to the CDN pool. The
    pool quarantines it for 1 hour in any case
    (`docs/design/public-ip.md:99-120`).
- **Dry run.** `manage.py cdn_dns --plan` prints the diff. Tests use `moto`'s
  Route 53 mock.

## 8. Hostnames and TLS

### 8.1 Default hostname

- Every zone gets `<id>.c.hipcdn.net`, served immediately under the fleet
  wildcard certificate `*.c.hipcdn.net`.
- That certificate is issued by DNS-01 (§8.4). Its key is generated in a CVM
  and sealed to the fleet key.

### 8.2 Custom domains

The console shows, for each hostname:

- **Subdomain:** `CNAME www.example.com → <id>.c.hipcdn.net`.
- **Apex** (`example.com`), where a CNAME is not allowed:
  - Use **ALIAS / ANAME / CNAME flattening** at the DNS provider, targeting
    `<id>.c.hipcdn.net`. Cloudflare (CNAME flattening), DNSimple (ALIAS),
    DNS Made Easy (ANAME) and NS1 (ALIAS) support it.
  - **Route 53 customers cannot do this.** A Route 53 alias only targets AWS
    resources or records in the same zone. They should redirect the apex to
    `www`.
  - Flattening resolves from the provider's own location. Unless the provider
    forwards ECS, every apex visitor is geo-routed by the provider's resolver
    location, typically to EU. We document this.
  - We offer no static anycast IPs, so A records pointing at node IPs are
    unsupported: they break failover and change when nodes move.
- **Optional, recommended:**
  - `CNAME _acme-challenge.www.example.com → <h>.dcv.c.hipcdn.net`, where
    `h` = base32(sha256(hostname))[:16]. This enables DNS-01 (§8.4): wildcard
    custom hostnames, and issuance **before** traffic is moved.
  - the CAA record from §4.3.4.

### 8.3 Verification (backend)

**Ownership.**

- A hostname belongs to at most one live zone (unique index).
- Claiming it requires **one** of:
  - the CNAME chain ends at **this** zone's `<id>.c.hipcdn.net`;
  - `TXT _hippius-cdn.<hostname>` = the zone's verification token. This is
    mandatory for apex names, whose flattened A records cannot tell zones
    apart.

**Checks.**

- The backend resolves through two public resolvers (1.1.1.1 and 8.8.8.8,
  using `dnspython`, a new dependency) and requires both to agree.
- Schedule: every minute for the first hour, then every 10 minutes for a
  day, then hourly for 7 days. After that the hostname is `failed` until
  "re-check" is clicked.

**States:** `pending_dns` → `verified` → `cert_pending` → `active`, plus
`failed(reason)`, `dns_moved` and `removed`. The console shows each state
live, with the resolver answers it saw.

**Re-verification, daily and before every issuance or renewal.**

- The check reruns the **original, exact-zone ownership predicate**: the
  CNAME chain ends at this zone's `<id>`, or, for an apex, the TXT token
  is still published. "Still points at some CDN address" is not enough.
- **Failure:**
  1. The hostname leaves the feed **at once**, so nodes stop serving it under
     this zone and stop renewing its certificate.
  2. It becomes `dns_moved` and keeps a claim tombstone for 7 days, so the
     owner can fix DNS and recover the hostname without re-issuing.
  3. If, during those 7 days, the predicate holds for **another** zone (the
     domain moved, say from zone A to zone B), B's claim wins immediately
     and A's tombstone is dropped.
  4. After 7 days the hostname is `removed`.
- So a domain the customer moved away, or moved to another zone, is never
  served under the old zone.

### 8.4 ACME, inside the CVMs

- **CA.** Let's Encrypt is primary. Google Trust Services (ACME with EAB) is
  the fallback when Let's Encrypt fails or rate-limits.
- **ACME account keys** are generated in a CVM and sealed to the fleet key.
  The accounturi is published for CAA pinning.
- **One issuer per hostname.** The backend grants a lease
  (`POST /api/cdn/node/acme/lease/`, 10 minutes) to one node, by default a
  node of the zone's shield region. The request names what will be issued
  (`{hostname_id, name}`: the fleet wildcard, or the custom hostname). The
  backend refuses a lease whose name is not the one it issues for that id
  (its own wildcard, or the claimed hostname) with `name-mismatch`, e.g. a
  node baked for another domain across a domain move. Such a node logs it and asks again only every 6 hours, never
  holding the lease. The granted node:
  1. generates the key (ECDSA P-256) in RAM;
  2. creates the order;
  3. completes the challenge;
  4. seals `{key, chain}` to the fleet key;
  5. uploads the blob.

  The feed then carries the blob to every node, which unseal it into memory.
- **HTTP-01** (custom hostnames without the DCV CNAME):
  - The leader publishes the key authorisation (not secret) through the
    backend. Every node serves it from the feed at
    `/.well-known/acme-challenge/<token>`, since the CA's validators can land
    on any region.
  - The feed's propagation (§10.7) runs before the leader tells the CA to
    validate.
  - This is safe from miners only on the edge path. Even there, the edge
    host could pass HTTP-01 itself (§4.1). Customers who want issuance
    pinned to DNS use the DCV CNAME plus CAA (§4.3.4).
- **DNS-01:**
  - for the fleet wildcard: TXT at `_acme-challenge.c.hipcdn.net`;
  - for customer hostnames with the DCV CNAME: TXT at
    `<h>.dcv.c.hipcdn.net`; this is the only way to get wildcard custom
    hostnames.

  The leader asks the backend (`POST /api/cdn/node/acme/dns01/`, value
  only) to write the TXT, waits for `INSYNC`, then tells the CA. The backend
  writes only names derived from a verified hostname held by that node's
  lease.
- **Renewal:**
  - Renew when a third of the lifetime remains, or earlier if the CA's ARI
    (RFC 9773) says so. The design assumes lifetimes shorter than 90 days.
  - Failures retry with backoff and alert at 14 days before expiry.
  - The certificate status (issuer, not-after, last error) is shown in the
    console.
- **Rate limits.** Let's Encrypt allows 300 new orders per account per
  3 hours, so new orders are spread across up to 4 fleet ACME accounts.
  Before GA, ask Let's Encrypt for a hosting-provider limit increase.
- **Uploaded certificates** (optional) are sealed in the browser to the
  fleet public key (§4.2).

## 9. Metering and billing

### 9.1 What is metered

The node classifies **every request** at log phase as **billable** or
**not billable**, and adds it to the matching counters. The counters are
monotonic totals per node, per zone, per client GeoIP region (§9.4).

**A request is not billable** when the node answered it itself, without
touching the cache or the origin, because of:

- our protections: rate limit 429, block 451, a paused zone's 503 (§9.6),
  unknown host 421/404;
- an invalid signed-URL token (403).

Every other request is billable.

| Counter | Meaning |
|---|---|
| `billable_bytes_out` | application bytes **actually written** to clients for billable requests, headers plus body, after compression. An aborted stream counts what was written before the abort. TLS and TCP overhead are not counted. |
| `billable_requests` | billable requests, any status, aborted ones included |
| `rejected_bytes_out`, `rejected_requests` | the same for non-billable requests: stats and abuse only |
| `hits`, `misses`, `bytes_from_origin`, `bytes_from_shield`, `status_2xx`..`status_5xx` | stats only |

The ledger bills exactly `billable_bytes_out` and `billable_requests`, with
no subtraction. Shield-to-node transfer, origin fetches and health checks
are never billed.

### 9.2 How counters reach the backend

This mirrors the public-IP usage feed
(`backend:compute/public_ip_usage.py:1-21`).

**Registration.**

1. The node presents its per-VM node credential (§5.3). The certificate is
   signed by vali's CDN CA and carries `{vm_id, region, generation, not_after}`.
   The KBS released it only to that registered, measured VM.
2. The backend issues a **single-use challenge** (random, expiring in
   2 minutes, tied to the `vm_id`). The node signs it with the credential's
   key.
3. The backend checks:
   - the certificate chain against the CA public key published by vali;
   - that the `vm_id` and generation are in vali's current CDN node list
     (`GET /v1/cdn/nodes`);
   - the challenge signature.

   It then stores `CdnNodeKey(vm_id, region, generation, pubkey)`.

We do not use a guest-generated SNP quote over guest-chosen fields: it would
prove only that some approved image made the key, not which registered VM.
The existing `GET /v1/vm/<id>/attestation` returns only the launch-time
bundle (`docs/design/control-plane-api.md:458`).

The region is **vali's** record of the node, never self-reported. The
fallback until the credential ships is a per-node agent token in
KBS-released user-data, the managed DB pattern
(`backend:compute/tasks.py:1705-1764`).

**Samples.**

- `POST /api/cdn/node/usage/` every 60 s, signed with the node key.
- The body is `{node, counter_epoch, seq, at, applied_revision, zones: {zone_id: {client_region: {counters...}}}}`.
- Unsent reports queue on disk.
- **Counters live in `cdn-agent`, not in OpenResty shared memory**, which
  can evict entries. OpenResty streams per-request records to the agent over
  a local socket. The agent persists its totals with the epoch every 10 s.
- **Resets are explicit.**
  - `counter_epoch` is a random id. The agent creates a new one whenever it
    cannot prove continuity: first boot, a lost or corrupt counter file, or
    a restore.
  - A new epoch's totals start at 0 by construction.
  - The backend never infers a reset from a lower value.

**Ingest** (`cdn/usage.py`):

- It follows the public-IP ingest (`backend:compute/public_ip_usage.py:112-121,150-160`)
  with two deliberate differences, because those rules lose or misread
  traffic:
  - **Reset.** The public-IP rule "a lower value is a reset" misses a reset
    whose counter climbs past the old value before the next report. The CDN
    keys every counter by `(node, counter_epoch, zone, client_region)`; a new
    epoch is a reset, and the same epoch with a lower value is refused and
    alerts.
  - **First report.** On the public-IP feed, the first report only sets a
    baseline and its traffic is dropped. For the CDN, the first report of a
    new epoch is billed **from 0**, since the epoch started at 0.
- Unchanged from the public-IP ingest:
  - the delta against the stored counter;
  - replays (`seq` ≤ last for that epoch) are skipped;
  - a per-node advisory lock;
  - `MAX_CLOCK_SKEW` = 5 minutes.
- Results land in `CdnUsageSample(node, zone, serving_region, client_region, bucket_start, ...)`,
  in 5-minute buckets, unique on `(node, zone, client_region, bucket_start)`,
  plus `CdnUsageCounter`. Retention is 35 days; hourly rollups for stats are
  kept 13 months.
- A zone id the node was not served in the last hour is refused and logged.

**Lateness.** Hours close at H+10 minutes and freeze
(`backend:compute/usage.py:44-57`).

- Samples that arrive after their hour closed are not billed, so nothing is
  ever billed twice.
- They are stored with `billing = late`, against `billed` for those that made
  the close.
- A report gap over 5 minutes alerts.

### 9.3 Ledger lines

`compute_hour` (`backend:compute/usage.py:702-791`) gains a CDN input block,
the first one not derived from a VM or a lease. Zones carry their owner (the
account owner, as for VMs).

| kind | resource | ref | unit | quantity | amount |
|---|---|---|---|---|---|
| `cdn_egress` | `cdn_egress:<region>` | `cdn:<zone_id>` | `gb` (divisor 10^9) | billed bytes in the hour, per billing region (§9.4), per price span | floor(q × price / 10^9) |
| `cdn_requests` | `cdn_requests` | `cdn:<zone_id>` | **new** `req10k` (divisor 10^4) | billed requests | floor(q × price / 10^4) |
| `cdn_domain` | `cdn_domain` | `cdn:<zone_id>/h<hostname_pk>` | `hour` | seconds a custom hostname was `active` (timed, like a lease) | the catalogue's monthly ÷ 730 rule |

The hostname itself is not put in `ref`: a 253-character name would
overflow the 128-character column (`backend:compute/models.py:1781`), and
that failure would come after other users' hours were already written.
Every line is built and validated (lengths, u128 bounds) **before** any
hour is written.

Required backend changes:

- `ComputeUsageLine.Kind` gains the three kinds, all within 16 characters
  (`backend:compute/models.py:1769-1779`).
- `ComputePrice.Unit` gains `req10k` (6 characters ≤ 8) and `DIVISORS` gains
  10^4 (`backend:compute/usage.py:114-118`).
- The usage-hash document is unchanged in shape: new kinds and units are new
  values, and the chain only sees the total and the hash
  (`backend:compute/usage_chain.py:1-22`).

### 9.4 Region of a byte, and failover fairness

- A byte is priced at the **cheaper** of two regions:
  - its **serving region**: the node's region, from vali;
  - its **client GeoIP region**: the region our continent table assigns to
    the client's IP, using a country database baked into the image (DB-IP
    Lite Country, CC BY 4.0, pinned by month and sha256; refreshed by the
    monthly cdn-node re-bake). The database version is reported with the
    counters; a private or unknown address is `XX`.
- This is **not** what Route 53 decided: Route 53 locates the resolver or
  its ECS subnet, not the client. The two usually agree. When they do not,
  the customer still pays the cheaper of the two prices, so the mismatch
  can only lower a bill.
- When we fail EU users over to AU, they still pay EU prices. When AU users
  are served from EU, they pay EU prices.
- The ledger reads each price at the bucket's instant and picks the lower.
  The line's resource names the region whose price was used.

### 9.6 Spend caps, arrears, abuse of the bill

- **Spend caps are in credits and cover every CDN line:** egress, requests
  and domains.
  - Every zone has a monthly cap chosen by the customer. The default is set by
    the operator.
  - Alerts fire at 50, 80 and 100%. At 100% the zone is `paused`: nodes
    answer 503 with `Retry-After`, and paused requests are not billed.
  - The customer raises the cap to resume.
- **Enforcement is near real time, not ledger-based.** The ledger lags by up
  to 70 minutes. Instead, the backend recomputes every zone's month-to-date
  spend from the samples each minute and pauses the zone through the feed.
- **Bounded overshoot.** The worst case is about 3 minutes of traffic: up
  to 60 s of reporting, 60 s of computing, and feed propagation. A per-zone
  hard throughput ceiling (default 2 Gbit/s and 20k requests/s, adjustable
  by support) bounds it:
  - at most about 45 GB per overshoot;
  - plus at most about 3.6M requests.

  In-flight responses finish. New requests get 503.
- **Arrears.** The existing enforcement (`backend:compute/delinquency.py`,
  hourly at :50, `backend:api_backend/celery.py:309-312`) suspends a
  delinquent user's zones exactly like their VMs.
- **Request floods.** Node-side rate limits answer 429, unbilled (§9.1).

### 9.7 Missing prices must not block the ledger

- A missing price raises `MissingPrice`, which makes the whole hour's close
  fail for **everyone** (`backend:compute/usage.py:857-863`).
- **Preflight the whole price matrix.**
  - A region cannot be activated for the CDN (vali `CdnRegion.active`, and
    the backend mirror) unless **every** CDN resource is priced: its own
    `cdn_egress:<region>`, `cdn_requests`, `cdn_domain`, and the
    `cdn_egress:<r>` of every region the cheaper-of-two rule (§9.4) can
    compare it with, i.e. every region in the continent table.
  - The activation is refused otherwise.
  - The close also preflights the matrix at the start of each hour. A gap
    pages ops before H+10. A test pins both checks.
- Price rows are appended with real prices **before the first invited
  user**. Nothing is free and there is no shadow period for customers.
  Later price changes are new rows (append-only,
  `backend:compute/models.py:1476-1489`).

## 10. Features

### 10.1 Cache behaviour and rules

**Cache key:** scheme, host, path, the normalised query (per rule), the
encoding class (`br` / `gzip` / identity), the zone generation, and the
generations of the matching purge prefixes (§10.2).

**Defaults:**

- For an S3 origin, ignore the origin's `Cache-Control`, `Expires`,
  `Set-Cookie` and `Vary`: the lifetime is the zone's alone. The Hippius S3
  gateway marks every private object `private, no-store`, so honouring it
  would make every request a miss. The client gets a `Cache-Control`
  computed from the zone, and only an allowlist of origin headers (the
  data-plane README has the list).
- Requests carrying `Authorization` or a cookie bypass the cache only for
  origins that receive client headers (HTTP origins, later). An S3 origin
  never receives one from the node, so those requests are cached like any
  other (backend contract, amended 2026-10-09).
- Cache 200/206 for 1 hour and 404 for 1 minute (the zone default, which a
  cache rule overrides). An origin redirect or error is never cached.
- `stale-while-revalidate` 60 s, `stale-if-error` 1 day.
- Maximum object size 10 GB.
- **Script-capable types are sandboxed on the fleet's names.** On
  `<id>.c.hipcdn.net` (zones are same-site with each other there), a
  response whose final type is HTML, any XML (XHTML, SVG, XSLT), `text/xsl`
  or `text/mathml` carries `Content-Security-Policy: sandbox allow-scripts`:
  it runs in an opaque origin, so classic scripts run but it cannot read or
  write cookies or use storage. The opaque origin also makes its same-host
  module scripts, fonts and `fetch` cross-origin, which the data plane does
  not answer with CORS: a full web app needs a custom domain, which is not
  sandboxed. A Public Suffix List entry for `c.hipcdn.net` would make zones
  separate sites and allow lifting the sandbox. The Content-Type fallback by
  extension never produces such a type, and every response carries
  `X-Content-Type-Options: nosniff`. This was decided while zones were
  served under `cdn.hippius.com` (same-site with hippius.com). The move to
  the dedicated `c.hipcdn.net` domain is the real fix; the sandbox stays as
  defence in depth.

**Rules** are ordered; the first matching rule wins, whole. The
authoritative semantics are the backend contract's (`cdn-contracts.md` in
hippius-backend, C.4 "Rules"): matches on the decoded request path, a glob
without `/` on the file name. The actions:

- edge TTL: seconds, or `"origin"` (the origin's `Cache-Control` /
  `Expires`, read by the node's internal origin server, so it still
  applies although the caching location ignores those headers; the S3
  gateway's blanket `private, no-store` counts as none); 0 means never
  stored;
- browser TTL: the client's `max-age` (null: the edge TTL in effect,
  `no-store` when that is 0 or the cache is bypassed);
- query string: ignore all, include all, or a whitelist, in the cache key
  only (never forwarded to the origin);
- bypass;
- ignore `Set-Cookie` (a no-op for S3 origins).

The data-plane README (`packer/cdn-node/openresty/README.md`, Cache rules)
has how the node applies them.

**Zone limits** (`settings.limits`: `max_mbps`, `max_rps`; 0 = no
allowance): over a ceiling, new requests get 503 and in-flight responses
finish. Each node enforces the whole ceiling on its own traffic (no
coordination), so a zone on N nodes can reach N times it fleet-wide.
Bandwidth counts body bytes before compression.

### 10.2 Purge

- `POST /api/cdn/zones/<id>/purge/` with `{paths: [...]}`, `{prefixes: [...]}`
  or `{all: true}`.
- **Purge is versioned keys, not deletion:**
  - `all` bumps the zone generation;
  - a prefix bumps that prefix's generation;
  - a path is a prefix that matches exactly.

  On lookup a node reads the generations of each ancestor prefix of the path
  (at most the path depth, in shared memory). Stale objects become
  unreachable and age out under LRU.
- This needs no index of keys, works the same for a path, a prefix or all,
  and purges a 10-million-object zone in O(1).
- **Status.** A purge is `done` when every active node has acknowledged the
  feed revision that carries it. Target: under 30 s at p95.
- **Limits.** 1,000 paths per call, 100 calls a minute per zone. `all` is
  limited to once a minute.

### 10.3 Origin shield

- Each zone has one shield region, by default FR because most origins and
  `s3.hippius.com` are in Europe. The customer can change it.
- A non-shield node takes its misses to a shield node of that zone's shield
  region, over HTTPS with fleet mTLS (§5.3), and only the shield fetches from
  the origin. On the shield, `proxy_cache_lock` collapses concurrent misses.
- The shield node for an object is chosen by consistent hashing of the cache
  key over the shield region's healthy nodes, so a region's cache is not
  duplicated.
- If the shield region is down, nodes go straight to the origin.
- Shield fetches are inbound traffic, which does not count against an
  outbound-only traffic quota.

### 10.4 Origins

**Hippius S3:**

- The origin is a bucket, chosen from the customer's account. For a private
  bucket the backend mints a read-only `SubToken` on that bucket
  (`backend:objectstore/models.py:141-181`, the `restore_material` pattern),
  with an optional prefix, seals it, and rotates it every 30 days.
  `expires_at` is set to 45 days so a missed rotation is visible.
- The sealed secret is the zone's `s3_credentials`. Its plaintext is a JSON
  object `{"access_key_id": str, "secret": str}`, plus `secret_access_key`
  (the same value, added later; it wins when both are present) and an
  optional `session_token`. The agent passes it to OpenResty unchanged;
  the router presigns with it, and refuses with a CRIT line that names the
  bad field, never a value. `test_vectors/cdn/s3_credentials.json` pins the
  shape for both.
- Nodes sign SigV4 requests to `s3.hippius.com`.
- Creating such a zone needs `cdn:admin` **and** `s3:admin`, because it mints
  a token.

**HTTP(S):**

- Settings: host or IP, port, scheme, Host header override, TLS verification
  (on by default, and turning it off is flagged), timeouts, and custom
  request headers (sealed; for example a secret that lets the origin trust
  only us).
- **SSRF guard: an allowlist, enforced by the node at connect time.**
  - **Only global unicast is allowed.** Every address in the IANA IPv4 and
    IPv6 special-purpose registries is refused. That includes:
    - RFC 1918, loopback, link-local (169.254.169.254);
    - `100.64.0.0/10`, the NetBird overlay and our internal services;
    - `192.168.122.0/24`, the miner's libvirt NAT;
    - IPv4-mapped, NAT64 and 6to4 IPv6;
    - multicast and reserved ranges.

    Our own CDN and edge addresses are refused too.
  - **Hosts are canonicalised** before checking: IDNA, no userinfo, and no
    decimal, octal or hex IP forms.
  - **Every resolved address** is checked. The connection is **pinned** to
    the checked address, so a re-resolution or rebinding between check and
    connect cannot change it.
  - **Origin redirects are never followed** by the node. They are passed to
    the client.
  - **Ports** are limited to 80, 443 and 1024-65535.
  - The backend runs the same check when the zone is saved, as a usability
    check only. The node's check is the enforcement.

### 10.5 Response features

- **Headers.** Custom response headers per zone or rule (set or remove).
  Hop-by-hop headers and `Set-Cookie` from rules are refused.
- **CORS.** Allowed origins (a list or `*`), methods and headers, `max-age`.
  Preflights are answered at the edge, without the origin.
- **Compression.** gzip and brotli for text types (a default MIME list,
  editable), when the client accepts it and the origin did not compress.
  Variants are cached per encoding class.
- **Ranges.** `slice 1m` for objects over 8 MB, so a range request fills and
  serves 1 MiB slices and a video seek does not pull the whole file.
  `If-Range` and `206`/`416` behave correctly.
- **HTTP/2** on. HTTP/3 is later. It needs UDP buffer tuning in the guest
  and QUIC through the edge DNAT, which is untested.
- **Redirect** HTTP to HTTPS per zone, default on. ACME and health paths are
  exempt.

### 10.6 Signed URLs

- **Token** = `base64url(HMAC-SHA256(key, path_prefix ‖ expires ‖ [client_ip] ‖ [kid]))`,
  passed as `?token=...&expires=...&kid=...` or as a path segment. It is
  verified on the node before the cache lookup.
- Up to two active keys per zone (by `kid`), for rotation.
- Options: a token valid for a path prefix (for HLS/DASH playlists), and an
  optional IP binding.
- The token parameters are removed from the cache key.
- Reference signing snippets in the docs: Python, JS, Go, PHP.

### 10.7 Feed (backend → nodes)

- `GET /api/cdn/node/feed/?since=<rev>` returns a snapshot when `since` is
  missing or too old, and the deltas otherwise. It long-polls for up to 25 s
  and uses ETags, like `poll_routes` (`backend:edge/agent.py:1140-1178`).
- Content:
  - zones (config, state, rules, sealed secrets);
  - hostnames;
  - purge generations;
  - blocks;
  - certificate blobs;
  - ACME HTTP-01 key authorisations;
  - fleet key version.
- Deltas keep it small: 10k zones × about 2 KB is 20 MB as a snapshot.
- Nodes acknowledge the applied revision in their usage report. That drives
  purge status, the health check's staleness rule, and the console.

### 10.8 Stats

- Per zone, per serving region, in 5-minute buckets for 35 days and hourly
  for 13 months: bytes, requests, hit ratio (`hits / (hits + misses)`),
  origin bytes, status classes, rejected requests.
- They come from the same samples as billing. A sample that arrived after
  its hour closed is shown as "late, not billed", so stats and invoices
  reconcile line by line.
- No top-URL or per-client reports at GA. That is for privacy: request logs
  leave a node only when the customer opts into shipping them to their own
  bucket.
