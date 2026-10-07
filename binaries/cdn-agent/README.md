# hippius-cdn-agent

The control agent of a `cdn-node` CVM (CDN plan I1; spec
[`docs/design/cdn.md`](../../docs/design/cdn.md) §5, §7.3, §9.2, §10.7).
It runs next to OpenResty, holds every secret on the node, and gives
OpenResty only what it serves.

## What it does

- Derives the per-VM **node key** from the KBS-released lifecycle key:
  `HKDF-SHA256(lifecycle_seed, info = "HIPPIUS_CDN_NODE_KEY_V1")`. vali
  derives the same public key and its CDN CA signs a 7-day Ed25519 X.509
  certificate with SAN URI
  `spiffe://hippius.network/cdn/<region>/<vm_id>/g<generation>`.
  The node accepts a certificate only if its key is the derived key and
  its SAN names this node.
- Loads the boot-time **fleet keyring** (`v<n>.key`, X25519). There is
  no in-guest rotation: rotation is a node replacement or reboot.
- **Registers** with the backend (challenge signed with the node key and
  the node certificate presented in the body), and refreshes the 1 h
  session. There is no mTLS: the node routes sit behind Cloudflare.
- **Signs every session request** (contract §C.0): feed, `usage/`,
  `certs/`, `acme/lease/`, `acme/dns01/` carry the bearer token plus
  `X-Hippius-Node-Timestamp` and `X-Hippius-Node-Signature`, an Ed25519
  signature with the node key over

  ```
  HIPPIUS_CDN_NODE_REQ_V1\n<vm_id>\n<METHOD>\n<host>\n<path_and_query>\n<timestamp>\n<hex sha256(body)>\n<session_id>
  ```

  `host` is the backend URL's host, `path_and_query` the raw target as
  sent, `session_id` the public id registration returned as
  `session_token_id` (`sess_` + 24 hex, new on every registration; the
  older `session_id` field is read if it is the only one; `-` if none).
  Registration answering 503 (`cert-auth-disabled` while the backend has
  certificate auth off) is retried under the feed loop's back-off.
  The timestamp is on the backend's clock: every response, errors
  included, carries `X-Hippius-Server-Time` (else `Date`, until the first
  `X-Hippius-Server-Time`), and the agent anchors it on the monotonic
  clock, since the guest wall clock is the miner's and steps. The backend
  refuses a replayed message, so a byte-identical request is never signed
  twice in the same second: the agent waits for the next second rather
  than run ahead of the server. A 401 `node-signature-stale` is re-signed
  and retried once; any other 401 (`node-signature-invalid`), on the feed
  or on a usage post, drops the session and re-registers under the normal
  error back-off. Session renewal times use the same server clock.
  The usage report's own `USAGE_V1` body signature stays on top. Golden
  vectors, shared with the backend: `test_vectors/cdn/node_req_v1.json`.
- **Polls the feed** with `since=<rev>` and `ETag` (the backend answers
  at once, no long-poll: after a 304 the next poll waits 5 s ± 20 %,
  after an error 5 → 60 s exponential ± 20 %, and never less than a
  server `Retry-After`; after a new revision, 1 s), applies
  snapshots and deltas (the backend serves snapshots only for now; an
  unchanged snapshot is not re-pushed), keeps **purge generations**
  (directory `prefixes` ending in `/`, exact `paths`) monotonic, drops
  purge keys and blocks that can never match a request, and
  persists a last-known-good snapshot (ciphertext only).
- **Unseals** certificate keys and zone secrets in RAM and pushes them
  to OpenResty over the control socket. Nothing cleartext touches disk.
- **Meters** every request into epoch-scoped counters and queues a
  signed usage report every 60 s.
- Publishes the **readiness bits** behind `/__hippius/health` and the
  TLS-bound **SNP report** behind `/.well-known/hippius-attestation`.

- **Issues and renews certificates** with ACME DNS-01 (I4, contract
  §C.6; `src/issuer.rs`, `src/acme.rs`, `src/csr.rs`):
  - what: the fleet wildcard (`fleet`, which also covers
    `health.<domain>` for the backend's probe) and every served custom
    hostname the wildcard does not cover, including the claimed ones
    still waiting for their first certificate (`needs_cert: true` in the
    feed's `hostnames[]`; those are never routed: OpenResty does not see
    them until the backend serves them). A name is due with no valid
    certificate in the feed, or two thirds into its certificate's life
    (± lifetime/30 jitter);
  - who: the backend's 10-minute lease makes one node the issuer of a
    name (`409 lease-held` waits about 3 min; the certificate then comes
    through the feed). Custom hostnames go first to nodes of the zone's
    shield region; the others wait 30 min for a missing certificate, or
    until it is overdue by lifetime/12. A draining node never issues;
  - how, one exchange per feed round: lease → account (first use) →
    order → authorization → `acme/dns01/` (re-posted until `insync`;
    `503 dns01-disabled` waits 1 h) → challenge → validation → order
    ready → the feed is checked again (a certificate that arrived from
    another node ends the job, no duplicate) → finalize with a fresh
    ECDSA P-256 key made in RAM → chain download → the chain must name
    exactly that host and carry that key → the key PEM is sealed to the
    newest `active` fleet key **this node holds** (a different public key
    in the feed is refused) → `certs/`. A job has 9 min (the lease is
    renewed every 4); failures back off 1 min → 1 h (± 20 %). A
    certificate issued but not uploaded is kept in RAM and uploaded again
    later rather than ordered again (CAs limit duplicates per name and
    week, across accounts); an abandoned order deactivates its pending
    authorization. CA URLs must stay on the directory's origin;
  - CAs: Let's Encrypt. After a CA rate limit or two CA failures in a
    row, the next attempt goes to Google Trust Services, and the one after
    back to Let's Encrypt. The fallback needs the external account
    binding in the node identity; a GTS binding registers one account, so
    it must be minted per node launch (a node never outlives its boot).
    Each CA's account key is generated in RAM on first use and lives as
    long as the agent (re-registered if the CA forgets the account). No
    key is ever written to disk or sent unsealed; `ring` keeps its own
    copy of private scalars, which it does not wipe;
  - residual: every node registers its own account per CA, in RAM, so a
    customer's CAA record can pin the CA (`letsencrypt.org`, `pki.goog`)
    but not an `accounturi`. Pinning an account needs one fleet-wide
    account per CA, whose key would have to reach every node sealed;
  - no HTTP-01: `acme_http01` from the feed is still pushed to OpenResty,
    and stays empty.

Not here yet: log shipping (I5), HTTP origins (I6). Their extension
points are in `src/hooks.rs`.

## Inputs

`/etc/hippius/cdn-agent.toml` is baked into the measured image. Every key
is optional; unknown keys, relative paths and a non-`https` backend are
refused (the agent exits).

```toml
[backend]
url = "https://api.example.invalid"   # or from the identity file; both must agree
# ca_bundle = "/etc/hippius/backend-ca.pem"  # replaces the web roots
request_signatures = true                 # §C.0 signatures (harmless until enforced)
request_timeout_s = 15
feed_poll_s = 25

[identity]
node_file = "/run/hippius/cdn-node.json"
lifecycle_key = "/run/credentials/hippius-cdn-agent.service/lifecycle.key"
fleet_key_dir = "/run/credentials/hippius-cdn-agent.service"
trust_domain = "hippius.network"
fleet_wildcard_hostname = "*.cdn.hippius.com"

[paths]
state_dir = "/var/lib/hippius-data/cdn"
data_mount = "/var/lib/hippius-data"
cache_dir = "/var/lib/hippius-data/cache"
control_socket = "/run/cdn/ctl.sock"          # OpenResty's directory
control_socket_uid = 990                       # required when attestation = true
metering_socket = "/run/cdn-agent/meter.sock"  # the agent's own directory
# geoip_version_file = "/usr/share/hippius/geoip.version"

[data_plane]
compression = ["gzip"]   # "brotli" is refused until OpenResty ships ngx_brotli
cache_fill_percent = 75
attestation = true

[timing]
usage_interval_s = 60
persist_interval_s = 10
health_interval_s = 5
feed_stale_after_s = 300
lkg_max_age_s = 86400
resync_interval_s = 300

[acme]
enabled = true
# directory = "https://acme-v02.api.letsencrypt.org/directory"
# fallback_directory = "https://dv.acme-v02.api.pki.goog/directory"  # needs acme_eab
# contact = "mailto:ops@example.invalid"
```

The node identity file comes from the KBS-released user-data:
`{"node_id": "...", "vm_id": "...", "region": "FR", "backend_url": "https://...",
"acme_eab": {"kid": "...", "hmac_b64u": "..."}}`
(`vm_id` defaults to `node_id`; `acme_eab`, the fallback CA's external
account binding, is optional and secret, so it never comes with the
image; no other keys accepted).

## Keys reach the agent as systemd credentials

The agent runs as its own unprivileged user. The lifecycle key and the
fleet keys are root-owned tmpfs files written by `guest-release`;
systemd copies them into the service's private credentials directory,
so no root helper and no privilege drop are needed:

```ini
[Service]
User=cdn-agent
LoadCredential=lifecycle.key:/run/hippius/lifecycle.key
LoadCredential=cdn-fleet:/run/hippius/cdn-fleet
RuntimeDirectory=cdn-agent
RuntimeDirectoryMode=0750
RequiresMountsFor=/var/lib/hippius-data
ConditionPathIsMountPoint=/var/lib/hippius-data
```

Key files must not be readable by group or other.

## OpenResty contract (I2)

**Control socket** (`/run/cdn/ctl.sock`, served by a `content_by_lua`
location bound only to it). The agent `PUT`s complete JSON documents;
each replaces the previous one.

| Path | Content |
|---|---|
| `/v1/secrets` | `{"zones": {zone_id: {name: cleartext}}}` |
| `/v1/certs` | `{"default": "*.cdn.hippius.com" or null, "certs": {hostname: {"chain_pem", "key_pem", "not_after"}}}` |
| `/v1/config` | `{"revision", "compression", "fleet_wildcard", "draining", "zones": {zone_id: {"state", "serving", "refusal", "origin", "shield_region", "settings", "secrets"}}, "hostnames": {hostname: zone_id}, "purges": {zone_id: {"zone_generation", "prefixes": {dir_prefix/: gen}, "paths": {exact_path: gen}}}, "blocks", "acme_http01": {token: key_authorization}, "peers"}` |
| `/v1/health` | `{"ready", "volume_mounted", "fleet_key", "cert_store", "not_draining", "quota_ok", "feed_fresh", "applied_revision", "at"}` |
| `/v1/attestation` | `{"format": "sev-snp-report-v1", "spki_sha256_hex", "report_b64"}` |

Answer `2xx` when stored, and `409` when shared memory is empty (after
an OpenResty restart): the agent then re-pushes everything. Push order
is secrets, certs, config. `/__hippius/health` returns 200 only when
`ready` is true **and** the canary object is served.

A zone with `serving: false` (origin refused, secret unreadable) must be
answered without contacting any origin. The S3 endpoint is part of the
OpenResty config, never of the feed.

Set `control_socket_uid` to the OpenResty user so the agent never sends
secrets to a socket someone else bound. The I3 baked config **must** set
it (the agent refuses to start without it while `attestation` is on), and `/run/cdn` must be writable by the
OpenResty user only: the owner check and the `connect` are two steps on
the same path. The metering socket's directory must be owned by the
agent and not group/other writable, or the agent refuses to start.

**Metering socket** (`/run/cdn-agent/meter.sock`, datagram, mode 0660,
in a directory only the agent can write; the OpenResty user needs the
group). One JSON object per request from `log_by_lua`, at most 2 KiB, no
other keys:

```json
{"zone": "z1", "client_region": "FR", "billable": true, "bytes_out": 1234,
 "cache": "hit", "bytes_from_origin": 0, "bytes_from_shield": 0, "status": 200}
```

`zone` is omitted or null for an unknown host. `client_region` is a
billing region code (upper-case ISO 3166 alpha-2, like vali's regions),
`XX` until the GeoIP database exists; the backend holds `XX` unbilled. A zone the applied feed
does not carry, or a record above 16 GiB, is never billed to anyone
(counted as unattributed, or dropped). `cache` is
`$upstream_cache_status` lower-cased. OpenResty decides `billable`
(spec §9.1: 429, 451, paused 503, 421/404 unknown host and invalid
signed-URL 403 are not billable).

**Cache size**: `hippius-cdn-agent cache-size` prints the
`proxy_cache_path max_size` value (`<n>k`, 75 % of the volume) for an
`ExecStartPre`.

## Backend contract

All paths, bodies, headers and signing domains are in `src/wire.rs`.
Two signatures use the node key, each domain-separated:

- registration: `"HIPPIUS_CDN_REGISTER_V1" 0x00 vm_id 0x00 generation(u64 BE) challenge`;
- usage: `"HIPPIUS_CDN_USAGE_V1" 0x00 body`, in `X-Hippius-Cdn-Signature`
  (base64), with `X-Hippius-Cdn-Node: <vm_id>`.

Every agent start opens a new `counter_epoch` and first queues one final
report closing the previous epoch, so continuity never has to be proven.

What the backend must do on its side:
- check that `X-Hippius-Cdn-Node`, the body's `node` and the session's
  `vm_id` agree (the header is not signed, the body is);
- deduplicate on `(node, counter_epoch, seq)`, skipping `seq` ≤ the last
  one seen (a crash can resend a `seq` with a different `at`);
- refuse an unknown zone inside a report, not the whole report;
- not bill usage stamped after a zone was paused or suspended.

## Known limits

The host controls the guest clock (no Secure TSC) and can roll the data
volume back to an older, still-authentic snapshot. So:
- a booting node serves its last-known-good config but reports **not
  ready** until its first successful backend round; only a node that was
  current can ride out a backend outage (up to 24 h);
- during such an outage, a node keeps the purge generations and zone
  states it last had. The backend's billing rules above bound the cost.

Accepted residue: parsing a certificate key to check it against its
leaf leaves copies of the key in freed heap (the PEM decoder's buffer,
ring's key pair), which these crates do not wipe. The keys live in the
CVM's encrypted memory either way.

The shared vectors (node-key HKDF, PyNaCl sealed boxes) are in
`test_vectors/cdn/vectors.json`, regenerated by `gen_vectors.py`.
