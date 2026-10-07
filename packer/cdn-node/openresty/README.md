# cdn-node data plane (OpenResty)

CDN plan I2. This directory holds the OpenResty build and the config that
serves customer traffic on a `cdn-node` CVM. It is the other half of the
contract in [`binaries/cdn-agent/README.md`](../../../binaries/cdn-agent/README.md):
the agent holds the secrets and pushes documents, and OpenResty serves.

| File | What it is |
|---|---|
| `versions.env` | Pinned sources (OpenResty 1.27.1.2, OpenSSL 3.4.3, PCRE2 10.45, zlib 1.3.1): versioned URLs and SHA-256 checked before use; upstream signatures verified when pinned |
| `build-openresty.sh` | Reproducible build to `/opt/openresty`, with OpenSSL, PCRE2 and zlib compiled in statically |
| `nginx.conf.in` | The config template, rendered once at bake time |
| `origin.conf` | The S3 origin endpoint, baked and measured |
| `render.sh` | `conf` renders the template, `cache` writes the `proxy_cache_path` include, `placeholder` writes the throwaway TLS pair |
| `lua/hippius_cdn/` | Control socket, routing, certificates, SigV4, metering, health |
| `tests/` | `run.sh`: render guards, Lua unit tests, integration against the real binary |

## Build

```
packer/cdn-node/openresty/build-openresty.sh out/openresty.tar.gz [download-cache]
```

The tenant-baker image builds this in its `openresty-builder` stage, on
bookworm (glibc 2.36). It ships the result at
`/usr/local/share/hippius/cdn-node/openresty.tar.gz` (plus `.sha256`), with
the config under `/usr/local/share/hippius/cdn-node/openresty-config/`.

The output is reproducible: two builds in the same image and the same
`BUILD_ROOT` give the same tarball hash. The tree depends only on glibc and
`libcrypt.so.1`.

Brotli is not built, because the beta is gzip-only. To add it:
1. pin `ngx_brotli` in `versions.env`;
2. add the module to `build-openresty.sh`;
3. enable it where `router.lua` handles compression;
4. flip `BROTLI_AVAILABLE` in the agent.

## The cdn-node image (I3)

`tenant-image-bake.sh --profile cdn-node` builds the node image. It is
golden_verity_overlay only, on the Debian family. After the standard
customise and its sshd gates, it purges `openssh-server`, then runs
[`scripts/cdn-node/install-cdn-node.sh`](../../../scripts/cdn-node/install-cdn-node.sh).
Everything below lands in the dm-verity base, so it is covered by the
measurement, and none of it comes from user-data.

**Users.** The ids are fixed so the agent's `control_socket_uid` can be
baked, and the bake fails if the base image already uses one of them:

| Name | Id | Role |
|---|---|---|
| `hippius-cdn` (group) | 61100 | Primary group of both services; owns the sockets |
| `cdn-agent` | 61101 | The agent |
| `openresty` | 61102 | The data plane |
| `hippius-snp` (group) | 61103 | Read access to `/dev/sev-guest` (udev rule), for the agent's attestation |

**`hippius-cdn-openresty.service`:**
- `User=openresty` and `Group=hippius-cdn`, master included. Only
  `CAP_NET_BIND_SERVICE` is granted.
- The control socket lives in `RuntimeDirectory=cdn` (0750,
  `openresty:hippius-cdn`). nginx makes a unix listener 0666 whatever the
  umask, so that directory is the barrier: only the agent's group can
  reach the socket.
- `Requires=hippius-cdn-firewall.service`: no listener runs without the
  input firewall. `LimitNOFILE=1048576`.
- `ExecStartPre` does two things:
  - writes the placeholder TLS pair;
  - runs `render.sh cache-auto … 75`, which sizes the cache at 75 % of the
    volume.
- It runs nginx with `-e stderr` and `daemon off`, under `ProtectSystem=strict`.

**`hippius-cdn-agent.service`:**
- `User=cdn-agent`, `Group=hippius-cdn` and `SupplementaryGroups=hippius-snp`,
  with no capabilities.
- `RuntimeDirectory=cdn-agent` (0750). This holds the metering socket in a
  directory OpenResty cannot write to.
- `LoadCredential=` brings in `lifecycle.key`, the `cdn-fleet` directory
  and the node identity `cdn-node.json`, all from the KBS release tmpfs. If
  one is missing, the agent does not start and systemd retries every 10 s.
- systemd hands each credential over as a root-owned 0400 file with an
  ACL for `cdn-agent`; the agent accepts that shape only inside its
  `$CREDENTIALS_DIRECTORY`.

**Both units:**
- find their directories on the data volume (`cache/`, `cdn/`) already
  there: `/etc/tmpfiles.d/hippius-cdn.conf` creates them at boot, owned
  and moded for each unit. An `ExecStartPre` cannot, since a unit's
  `ReadWritePaths=` must exist before any of its commands start;
- use `RequiresMountsFor=` and `ConditionPathIsMountPoint=` on
  `/var/lib/hippius-data`. If the data volume's bind is missing, they do
  not start; they never fall back to the overlay root;
- cannot reach NetBird's daemon socket (0666, unauthenticated gRPC that
  could re-point the daemon and enable root SSH), NetBird's or
  cloud-init's state, or `/run/hippius` (`InaccessiblePaths=`);
- dump no core (`LimitCORE=0`; `kernel.core_pattern` discards cores node-wide).

**Rendered config.** `/etc/hippius/cdn/nginx.conf` is rendered once, with
the production values in the installer. `/etc/hippius/cdn-agent.toml` holds:
- the backend URL, from `--cdn-backend-url`;
- mTLS on;
- `control_socket_uid = 61102`;
- the socket paths.

**Network:**
- **Inbound guard** (`hippius-cdn-inbound.timer`, every 30 s). This is the
  baked equivalent of the tenant user-data guard, restricted to TCP 80/443.
  It admits non-overlay sources on `wt0` only while the edge's metadata
  server says this VM holds a public IP.
- **Input firewall** (`hippius-cdn-firewall.service`, an nftables table).
  Off the overlay, a node admits only established traffic, DHCP, NetBird's
  WireGuard port and ICMP. On `wt0`, a prerouting hook admits only TCP
  80/443, replies and ICMP, whatever NetBird's own chains accept.
- **DHCP from the miner's network:** only an address, a gateway and
  resolvers. No classless routes (they would beat NetBird's exit default),
  NTP, MTU, hostname, domains, router advertisements or ICMP redirects.

**No runtime software changes.** `snapd` and `unattended-upgrades` are
purged, and the apt timers are masked; updates are a new bake.

**No SSH.** `openssh-server` is purged, and `ssh`/`sshd` service and socket
units are masked. The tenant user-data's `hippius-public-ip-inbound`
units, which open every port, are masked too. The standard M0 hardening also applies: no cidata
datasource, no guest agent, `ssh-generator` and serial getty masked.

**Node identity.** `/run/hippius/cdn-node.json` (`node_id`, `region`,
`backend_url`) comes from the KBS-released user-data (V3). The agent reads
it through `LoadCredential`.

**Not a tenant image.** vali refuses any launch off a cdn-node bake, by
image name or by `bake_id`, until the CDN launch role (V2/V3) exists. A
cdn-node bake can be blessed only as `cdn-node`, and nothing else can take
that name.

**Ephemeral root.** The golden upper is discarded on every boot. A
cdn-node bake stages a marker file,
`/etc/initramfs-tools/conf.d/hippius-cdn-ephemeral-upper`, which
mkinitramfs copies into the initrd's `/conf/conf.d/`, and the golden hook
then also stages a real `chown` at `/lib/hippius/chown`. The bake refuses
an initrd that lacks either. The marker sets `panic=10`, so a panic in any
initramfs stage reboots instead of opening a shell on the console, unless
the measured cmdline sets its own `panic=` (it is parsed after conf.d; the
library sets 10 again before the golden path). The
golden overlay library (`scripts/initramfs/hippius-golden-overlay.sh`)
checks for the marker and, only when it is present:
1. refuses key modes M1/M2 (a cdn node is M0 only);
2. after the anti-rollback gate and before the overlay is mounted, removes
   the upper and its workdir from the guest-keyed volume, and rebuilds
   `data/` from scratch: a fresh root-owned directory holding copies of
   `cdn/counters.json` and the regular files of `cdn/usage-queue/`
   (unsent usage reports) within cdn-agent's own limits (64 MiB a file,
   1440 reports, 1 GiB), owned by cdn-agent. The swap is synced and goes
   through `data.old`, so a power cut never loses both. The cache, the
   last-known-good feed, symlinks, fifos, every other entry, and any
   owner, mode, ACL or setuid bit a previous boot set are gone;
3. remounts `/var/lib/hippius-data` with `nosuid,nodev,noexec` and checks
   the options in `/proc/mounts`.

The effect is that a root implant cannot survive a reboot (nothing it wrote
under `/` is read again, not even `/etc/fstab`), and the data volume is
never a code path. Every failure is fail-closed: there is no `switch_root`,
`/init` exits, and the guest halts or reboots according to the kernel's
`panic=` on the measured cmdline. An implant can therefore keep a node from
booting (an immutable file the discard cannot remove, a full volume), but
not keep itself. The counters and queued reports it may have forged survive
one reboot: the backend must treat them as untrusted input, like any node
report. Without the marker, every other initrd runs none of these
steps. `scripts/dev/golden-ephemeral-test.sh` covers both.

One consequence: nothing under `/` survives a reboot, NetBird's enrolment
and cloud-init's instance state included. A rebooted node comes back
without its overlay identity, and the CDN reconciler replaces it. Losing
the cache is not data loss.

The baker image carries the inputs:
- `/usr/sbin/hippius-cdn-agent`;
- `/usr/local/share/hippius/cdn-node/openresty.tar.gz` and its `.sha256`;
- `/usr/local/share/hippius/cdn-node/openresty-config/`;
- `/usr/local/bin/cdn-node/`.

vali sends `BAKE_PROFILE=cdn-node` plus `BAKE_CDN_BACKEND_URL` (from
`VALI_CDN_BACKEND_URL`) only for a `profile: cdn-node` bake. Every
standard bake is unchanged.

## Behaviour

- **Control socket.** It accepts only `PUT /v1/{config,secrets,certs,health,attestation}`.
  - A document that does not validate gets 400, and nothing is stored.
  - `PUT /v1/health` gets 409 while config, secrets or certs are missing,
    which happens after a restart.
  - Bodies are never written to disk, because the buffer size equals the
    maximum body size.
  - Documents live in the `hippius_docs` shared dict. Each worker decodes a
    document once per version.
- **TLS.** The certificate is chosen by SNI: the exact name, then its
  wildcard, then the fleet-wildcard default. With no match, the handshake
  is refused. On HTTPS the `Host` must equal the SNI name, otherwise 421.
- **Routing.**
  - Host → zone, by exact name, then wildcard.
  - An unknown host gets 421.
  - A hostname block, or a path or prefix block, gets 451; a suspended
    zone gets 403 (spec §12.2).
  - A paused zone, or one with `serving: false`, gets 503.
  - Methods other than GET or HEAD get 405.
  - A path with a `.` or `..` segment, a control byte or a backslash gets 400.
  - The bucket root gets 404.
  - Plain HTTP gets a 301 to HTTPS, unless the zone sets
    `settings.redirect_https = false`.
  - None of these contacts the origin, and none is billable.
- **Origin.**
  - The request is `GET <origin.conf host>/<bucket>/<prefix><path>`,
    percent-encoded, and presigned (SigV4 query string, `X-Amz-Expires`
    one day, only `host` signed) when the zone has `s3_credentials`.
    Slice subrequests skip the Lua phases and reuse the main request's
    URL, so a header signature bound to a clock-skew window could expire
    mid-download; a presigned URL is valid for its stated lifetime.
  - Only `Host` and the slice `Range` are sent. No client header, body or
    query string reaches the origin.
  - The presigned URL is never logged: there is no access log, metering
    records carry no URL, and the customer location logs only at `crit`
    (nginx's upstream errors print the full upstream URL). Origin failures
    still show in metering as 502/504.
  - An empty object (S3 answers the first slice's range with 416,
    `Content-Range: bytes */0`) is served as an empty 200.
  - The feed names only the bucket and prefix, never a host.
- **Feed paths.** Block values and purge keys arrive percent-encoded and
  are stored decoded and slash-merged, the way nginx builds `$uri`, so
  `/a%20b.txt` blocks and purges the request `/a%20b.txt`. Purges come
  as two maps: `prefixes` (keys end in `/`, cover everything below) and
  `paths` (one exact path each; absent means empty). A `prefixes` key
  without the trailing `/` is an exact path: the backend sends exact
  purges there until it fills `paths`. An empty origin prefix is the
  whole bucket. A prefix
  block must end in `/`, and so must a zone's origin prefix (so `site`
  cannot reach `site-private/`). A block value or purge key that does not
  canonicalise to a request path (`/%2e%2e/x`, `/a%00`), or a block of
  unknown kind, is skipped and
  logged, never fatal: it can match no request, and one bad customer
  purge must not freeze the node's config (the agent drops them too).
- **Cache.**
  - The key is zone + zone generation + the generation of every covering
    directory prefix + the exact-path generation + path + the 1 MiB slice
    range.
  - Only origin statuses 200, 206, 301 and 404 are cached, whatever the
    origin's `Cache-Control` says.
  - Any status of 400 or above gets a short generic body: origin error
    XML (bucket, key, access key id) never reaches a client.
  - `X-Accel-*` headers from the origin are ignored and stripped.
  - A purge bumps a generation, and old objects age out.
  - Different query strings share one object, because the origin never
    sees the query.
  - Hostnames of one zone share objects.
  - Responses with `Set-Cookie` are not cached, and the cookie is stripped.
- **Compression.** gzip on text types, only when the client accepts it and
  the zone list enables it. The cache always holds the identity body.
- **Metering.** One JSON datagram per request goes to the agent, in the
  agent's `RequestRecord` shape. A request is billable only when it passed
  every check for a known zone; that includes the HTTP→HTTPS 301 and an
  origin 5xx passed through (spec §9.1: everything the node did not refuse
  itself). `bytes_from_origin` (stats only) counts every slice
  fetched for the request (slice subrequests are logged and add theirs to
  the main record; a background cache update is not counted).
  `client_region` is `XX` until the GeoIP database exists. Records are queued per worker and sent by a
  100 ms timer, because the log phase cannot use sockets.
- **Health.** `/__hippius/health` returns 200 only when all of these hold:
  - the agent's `ready` is true;
  - the agent's health document is no older than 30 s;
  - the canary file that worker 0 wrote on the cache volume reads back.
- **Other endpoints.** `/.well-known/acme-challenge/<token>` serves the
  feed's key authorisation for any host, over HTTP. `/.well-known/hippius-attestation`
  serves the agent's attestation document.

## Not yet (follow-ups)

- **Object size.** There is no per-object size cap yet (spec: 10 GB); the
  cache's LRU bounds the volume.
- **ACME tokens** are answered for any Host; the feed does not bind a
  token to its hostname.
- **Origin keepalive.** `proxy_pass` uses variables, so there is no
  upstream keepalive pool: each miss opens a new TLS connection to S3.
- **Zone rules.** Signed URLs, CORS, per-zone headers and cache rules are
  not enforced yet. The zone's `settings` are passed through but not acted
  on.
- **Origin shield.** There is no origin shield; every miss goes to the origin.
- **GeoIP.** There is no GeoIP database yet: `client_region` is always
  `XX` (decision G.7).
