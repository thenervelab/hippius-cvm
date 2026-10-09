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
  - `s3_credentials` is the plaintext the backend sealed, passed through
    unchanged by the agent: a JSON object
    `{"access_key_id": "...", "secret": "..."}` (the zone's read-only
    SubToken). `secret_access_key` is accepted in place of `secret`, and an
    optional `session_token` is signed as `X-Amz-Security-Token`. The
    region is the origin's `region`, else the node's default. Unusable
    credentials answer 503 without contacting the origin, with a CRIT line
    that names the field (`access_key_id missing or invalid`, `secret
    missing or invalid`, ...) and never a value.
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
  - Only origin statuses 200, 206 and 404 are cached, whatever the
    origin's `Cache-Control` says.
  - Any status of 400 or above gets a short generic body: origin error
    XML (bucket, key, access key id) never reaches a client.
  - `X-Accel-*` headers from the origin are ignored and stripped.
  - A purge bumps a generation, and old objects age out.
  - Different query strings share one object, because the origin never
    sees the query, unless a cache rule puts it in the key (see Cache
    rules).
  - Hostnames of one zone share objects.
  - The lifetime is the zone's alone: 1 h for 200/206 and 1 min for 404
    (`settings.default_ttl` and `proxy_cache_valid`) until zone rules are
    enforced. The origin's `Cache-Control`, `Expires`, `Set-Cookie` and
    `Vary` are ignored: the S3 gateway marks every private object
    `private, no-store`, which would make every request a miss. Set-Cookie
    never reaches a client, so it does not make a response uncacheable.
  - `Vary` is ignored because the origin request carries no client header,
    so the origin's answer cannot depend on one. Honouring `Vary: *` or
    `Vary: Origin` would only stop or split caching. The client sees gzip's
    own `Vary: Accept-Encoding`.
  - The client gets `Cache-Control: public, max-age=3600` on a 200/206,
    computed by the node, never the origin's. It does not count the time
    the copy already spent at the edge, so a browser or a downstream cache
    can hold an object up to about 2 h after the origin changed, and a
    purge cannot reach a copy a browser already holds.
  - An origin redirect (3xx other than 304) is not followed, never cached,
    and gets the same generic body as an error: S3's XML body names the
    bucket and endpoint.
- **Cache rules.** A zone's `settings.rules`, with the semantics of the
  backend contract (`cdn-contracts.md` in hippius-backend, C.4 "Rules",
  final since #439; validated by `cdn/rules.py`).
  - The first rule whose match matches wins, whole: no other rule applies,
    and its unset actions take the defaults. Specific rules go first.
  - The path matched is the decoded, normalised request path (`$uri`), the
    form purges and the cache key use. Patterns arrive percent-encoded and
    are decoded once. `path_prefix`: the path starts with it. `glob`: `*`
    any run of characters within a segment, `?` one character other than
    `/`, `**` any run across segments; without `/` it matches the last
    segment (`*.jpg` matches `/a/b/c.jpg`), starting with `/` the whole
    path (`/img/*.jpg` matches `/img/x.jpg`, not `/img/a/x.jpg`;
    `/img/**.jpg` both). `extensions`: what follows the last `.` of the last
    segment, case-insensitively. Globs and prefixes are case-sensitive.
  - `edge_ttl` (seconds) is how long the edge keeps a 200/206; a 404 is
    always cached a minute and errors are never stored. `0`: never stored,
    every request goes to the origin (the cache is not read). `"origin"`
    takes it from the origin's `Cache-Control` (`s-maxage`, `max-age`;
    `no-store`, `no-cache` or `private` means not cached) or `Expires`,
    else the default hour; the S3 gateway's blanket `private, no-store`
    counts as no header.
  - `bypass: true`: neither looked up nor stored (`proxy_cache_bypass` +
    `proxy_no_cache`).
  - Client `Cache-Control` on a 200/206: `public, max-age=<browser_ttl>`
    when the rule sets a number; else `no-store` when the request skips the
    cache (bypass, `edge_ttl: 0`) or the edge TTL in effect is 0; else
    `public, max-age=<the edge TTL in effect>` (3600 without a rule).
  - `query_string`: `"ignore"` (default), `"include"` or
    `{"whitelist": [...]}` changes only the cache key: the raw query split
    on `&`, each part at its first `=`, kept as sent, sorted by name then
    value. It never reaches the origin: an S3 object does not depend on it,
    and a client parameter on a presigned GET could select another version
    or override response headers.
  - `ignore_set_cookie` is a no-op: Set-Cookie never reaches a client and
    never prevents caching.
  - Requests carrying `Authorization` or a cookie are cached like any
    other: an S3 origin never receives a client header from the node, so its
    response cannot depend on one (as the contract states).
  - A rule the node cannot use is ignored and logged once per config
    version; the others still apply. Never a 5xx.
  - Globs are matched bit-parallel (Shift-And with wildcards): one pass over
    the path, the cost bounded by path length times pattern length whatever
    either contains, so no glob and path can stall a worker.
  - A zone's `glob` patterns total at most 2048 bytes (wire form as stored,
    summed over its rules; the backend validates the same cap). Over it,
    every glob rule of the zone is ignored (logged once per config version
    and worker), its prefix and extensions rules still apply. The matching
    work is per glob more than per byte, so the 50-rule maximum is what
    bounds it: the worst zone within both (50 globs of 40 bytes, none
    matching a 4 KiB path) costs about 10 ms a request.
  - A rule applies to what is fetched after it arrives: an object already
    cached keeps the edge TTL it was stored with (and its client max-age)
    until it expires or is purged. `bypass` / `edge_ttl: 0` take effect at
    once (the cache is not read). Purge the zone to apply a shorter TTL now.
  - How the edge TTL is applied: `proxy_cache_valid` takes no variable, and
    nginx reads a response's lifetime from its upstream headers before any
    Lua phase. So the caching location's upstream is an internal server on
    a unix socket (`/run/cdn/origin.sock`, reachable only by OpenResty and
    the agent). It fetches the presigned S3 URL and adds `X-Accel-Expires`
    (and `X-Hippius-TTL`, dropped before the client), computed from the
    rule; the origin's own `X-Accel-*` and `X-Hippius-TTL` are hidden there.
    Only misses take this local hop.
- **Zone limits.** A zone's `settings.limits` (contract C.4 "Zone
  settings"): `max_mbps` (bytes out, megabits per second; default 2000) and
  `max_rps` (requests per second; default 20000), integers, 0 = no allowance
  at all. Over a ceiling, a new request of the zone gets 503 (not billable);
  responses already in flight finish.
  - **Per node.** Each node applies the whole ceiling to the traffic it
    serves itself, with no coordination: a zone served by N nodes can reach
    up to N times its ceiling across the fleet.
  - Counted in one-second windows in a shared dict (`hippius_limits`, all
    workers): requests admitted, and body bytes as they are sent (main
    request and slice subrequests alike, so a long download counts while it
    runs; bytes before gzip). A request is refused when the current or the
    previous second is over the bandwidth ceiling, or when it would be over
    the request ceiling of the current second.
  - The 503 is the generic body (`503`), `Cache-Control: no-store`, never
    cached (refused before the cache), not billable, with `Retry-After: 1`
    (requests) or `2` (bandwidth); none for a ceiling of 0.
  - A new value through the feed applies to the next request: the ceilings
    are read from the config document, no reload.
  - Why Lua counters and not `limit_req` / `limit_rate`: `limit_req`'s rate
    is fixed in nginx.conf (one rate per zone of the directive, so a
    per-zone value from the feed would need a reload), and `limit_rate` is
    per connection, never a zone's total. The cost is bounded: one
    shared-dict read pair and one increment per request, one increment per
    64 KiB of body.
  - An unusable `limits` object falls back to the defaults (logged). A zone
    held at a ceiling logs one CRIT line per ceiling a minute per worker.
- **Response headers.** An allowlist: from the origin, a client sees only
  `Content-Type`, `Content-Length`, `Content-Range`, `Content-Encoding`,
  `Content-Language`, `Content-Disposition`, `ETag`, `Last-Modified` and
  `Accept-Ranges`. Every other origin header is dropped (`x-hippius-*`,
  every `x-amz-*`, `Set-Cookie`, `Expires`, `Vary`, `Location`, `Age`:
  nginx would replay the origin's value unchanged). The node adds `Cache-Control`, `X-Cache`,
  `X-Content-Type-Options`, `Content-Security-Policy` (script-capable
  types only) and gzip's `Vary`. There is no `Server` header.
- **Content-Type.**
  - `X-Content-Type-Options: nosniff` is on every response, nginx's own
    error pages and the node's endpoints included (`more_set_headers` at
    the http level).
  - When the origin sends no type, or `application/octet-stream` or
    `binary/octet-stream`, the type comes from the extension, using the
    build's `mime.types` (loaded at start).
  - Security: the fallback only yields types from an allowlist (`image/`,
    `audio/`, `video/`, `font/`, CSS, plain text, JavaScript, JSON, wasm),
    never HTML, SVG or any XML type, which browsers render as documents
    that can run script; anything else is `application/octet-stream`. A
    type the origin declares is kept.
  - On the fleet's own names (`<id>` under the fleet wildcard), a response
    whose final type is script-capable (HTML, any XML type, `text/xsl`,
    `text/mathml`) carries `Content-Security-Policy: sandbox allow-scripts`:
    an opaque origin, classic scripts run, no cookies or storage. Zones
    under one wildcard are same-site with each other, which this guards.
    Same-host module scripts, fonts and `fetch` become cross-origin there
    (no CORS is served), so a full web app needs a custom domain, which is
    never sandboxed.
- **Compression.** gzip on text types, only when the client accepts it and
  the zone list enables it. The cache always holds the identity body.
- **Metering.** One JSON datagram per request goes to the agent, in the
  agent's `RequestRecord` shape. A request is billable only when it passed
  every check for a known zone; that includes the HTTP→HTTPS 301 and an
  origin 5xx passed through (spec §9.1: everything the node did not refuse
  itself). `bytes_from_origin` (stats only) counts every slice
  fetched for the request (slice subrequests are logged and add theirs to
  the main record; a background cache update is not counted).
  `client_region` comes from the baked GeoIP database (see GeoIP below). Records are queued per worker and sent by a
  100 ms timer, because the log phase cannot use sockets.
- **Health.** `/__hippius/health` returns 200 only when all of these hold:
  - the agent's `ready` is true;
  - the agent's health document is no older than 30 s;
  - the canary file on the cache volume reads back. Worker 0 writes
    `<cache_dir>/.hippius-canary` at start and re-checks it every 10 s,
    rewriting it when it is missing or wrong. A failure is logged once,
    and so is the recovery. The cached objects live in `<cache_dir>/objects`,
    because nginx's cache loader deletes every file in its tree that is
    not a cache entry, a minute after start.
- **Cache usage.** The usage reports carry the cache's size
  (`disk.cache_used_bytes`). nginx creates the cache tree 0700, so the
  agent cannot measure it: `hippius-cdn-cache-usage.timer` runs `du` of
  `<cache_dir>/objects` every 10 minutes as the OpenResty user, at idle
  I/O priority, and writes the byte count to
  `<cache_dir>/.hippius-cache-usage` (outside the cache tree, so the cache
  loader leaves it alone). The cache maximum comes from the generated
  include (`/run/cdn/cache.conf`).
- **GeoIP.** `client_region` is the client's ISO 3166 alpha-2 country,
  from `$remote_addr` (the node has its own public IP, so it is the client).
  - The database is DB-IP Lite Country (MaxMind DB format), pinned by month
    and sha256 in `geoip.env`. `fetch-geoip.sh` downloads it when the
    tenant-baker image is built, from our mirror first and DB-IP second,
    and checks either copy against the one pinned sha256; the installer stages it read-only
    at `/opt/hippius-cdn/geoip/` with its `NOTICE`, and writes its version
    (`dbip-country-lite-YYYY-MM-<sha8>`) for the agent's reports. Nothing is
    downloaded on a node.
  - `lua/hippius_cdn/geoip.lua` reads it (country only) through the LuaJIT
    FFI; it is loaded once in `init_by_lua` and shared by the workers. A
    lookup costs about 2 µs.
  - Private, loopback, link-local and CGNAT addresses (the overlay
    included), an address without an entry, a code that is not alpha-2 or is
    `ZZ`, and any error all give `XX`. A missing or corrupt database logs
    once at start and gives `XX` everywhere; no request ever fails on it.
  - Refresh is a re-bake. The monthly bump, in order:
    1. download `dbip-country-lite-YYYY-MM.mmdb.gz` from DB-IP;
    2. `sha256sum` it;
    3. upload it unchanged and public:
       `aws s3 cp <file> s3://hippius-compute-images/geoip/ --acl public-read`.
       Without `--acl public-read` the object is private: the mirror answers
       403 to anonymous requests, and the build silently falls back to DB-IP
       until DB-IP drops the month;
    4. `curl` the mirror URL anonymously and check the sha256 again;
    5. bump `geoip.env` (month, both URLs, sha256), merge, pin the rebuilt
       tenant-baker image, re-bake cdn-node.

    DB-IP serves only the current and the previous month; the mirror keeps
    an older pin buildable.
    `cdn-geoip-freshness.yml` (weekly) warns when the pin is more than a
    month old or the mirror copy is unreachable.
  - Memory safety: every read of the file goes through a bounds check, the
    tree walk is bounded by the address length, data decoding by a depth
    limit, metadata decoding by a value budget. The unit tests load 400
    randomly corrupted databases through a verifying byte proxy and require
    XX or a country for every lookup and zero reads outside the buffer.
  - Attribution: IP Geolocation by DB-IP (https://db-ip.com), licensed
    under CC BY 4.0 (https://creativecommons.org/licenses/by/4.0/).
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
- **Zone rules.** Signed URLs, CORS and per-zone headers are not enforced
  yet (cache rules are, see Cache rules above).
- **Origin shield.** There is no origin shield; every miss goes to the origin.
