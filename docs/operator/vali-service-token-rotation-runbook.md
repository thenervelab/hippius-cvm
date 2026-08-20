# vali ServiceToken rotation runbook (#32)

Rotate a live `ServiceToken` **without an outage**, and retire the three
non-expiring credentials that exist today.

> ⛔ **Never echo a token value** into a terminal that is being recorded,
> a chat message, a PR, or this repository. The plaintext is printed
> ONCE by the mint command and is not recoverable — pipe it straight
> into Vault, or copy it from the terminal and clear the scrollback.

---

## Why this exists

`ServiceToken.expires_at` was nullable and, in production, always
`NULL`. Expiry has always been **enforced** at authentication
(`apps.identity.authentication` refuses a past `expires_at` in both
`ServiceTokenAuthentication.authenticate` and `resolve_principal`) — the
defect was that nothing ever **set** it. A bearer token for
`orchestration-root` — the principal that mints L1 OrderTickets, stages
Vault secrets, registers VMs with the KBS and dispatches launches — that
never expires is a permanent skeleton key whose only kill switch is
somebody remembering to flip `is_active`.

Migration `identity.0004` made the column `NOT NULL` and gave every
still-active token a **90-day** expiry counted from the moment the
migration ran. That is the deadline this runbook exists to meet.

Find the exact deadline (it is printed by the migration Job, and it is
in the row):

```bash
sudo k3s kubectl -n vali exec deploy/vali -- python manage.py shell -c "
from apps.identity.models import ServiceToken
for t in ServiceToken.objects.filter(is_active=True).select_related('client'):
    print(t.client.name, t.name, t.expires_at, t.last_used_at)
"
```

---

## The three live credentials and their consumers

Measured read-only on 2026-08-13 — 142 `ServiceToken` rows exist, but
only **3** are `is_active=True`. The other 139 are already deactivated
and cannot authenticate; do not treat the 142 as live.

| principal | current token label | lifetime class | consumer | secret path |
| --- | --- | --- | --- | --- |
| `orchestration-root` | `synthetic-monitor-2026q3` | `service` (90d) | synthetic monitor (full tier CronJob) | Vault `hippius-compute/vali/synthetic-monitor` property `root-token` → ESO → `Secret/vali-synthetic-monitor` key `root-token` → env `VALI_SYNTHETIC_ROOT_TOKEN` |
| `tenant-baker-worker` | `bake-worker-clean` | `service` (90d) | tenant bake path (baker pod → `/finalize`) | `Secret/vali-tenant-baker-worker-token` key `token` (ns `vali`) |
| `edge-telemetry-relay` | `edge-served-receipt-v1` | `infra` (365d) | Edge → `/v1/telemetry/ingest` served receipts | Vault `valiIngestToken.vaultPath` → ESO → `Secret/edge-gateway-vali-ingest-token` key `token` (ns **`edge-gateway`**) → env `HIPPIUS_EDGE_VALI_INGEST_TOKEN` |

Token *labels* are not secrets (the model's own `help_text` says so);
token *values* are, and appear nowhere in this document or in any
command output below except the one line the mint command prints.

Why the classes differ, in one line each: `orchestration-root` and
`tenant-baker-worker` are in-cluster machine identities a human rotates
alongside a deploy, so a quarter is a scheduled chore rather than an
interruption; `edge-telemetry-relay` is rotated from a *different*
namespace and cannot be driven from the control plane alone, so it gets
a year — long enough to be practical, short enough that the rotation
path is exercised annually instead of never. Full reasoning lives in
`apps.identity.models.TokenLifetime`.

---

## The procedure — one principal at a time

`ServiceToken.client` is a ForeignKey (not OneToOne) and authentication
resolves by the **presented** token's digest, so old and new
authenticate **simultaneously**. That overlap is what makes this
zero-downtime. Do not shorten it by revoking early.

### 0. Take the inventory (read-only)

```bash
sudo k3s kubectl -n vali exec deploy/vali -- \
  python manage.py vali_identity_deactivate_token \
    --client orchestration-root --dry-run
```

Note the OLD token's name and its `last_used_at`. You will compare
against this in step 3.

### 1. Mint the successor

Pick a `--token-name` that is not already taken for this client (the
`(client, name)` pair is unique) — a dated label works:
`synthetic-monitor-2026q4`.

```bash
sudo k3s kubectl -n vali exec -it deploy/vali -- \
  python manage.py vali_identity_issue_token \
    --client orchestration-root \
    --token-name synthetic-monitor-2026q4 \
    --operator \
    --lifetime service
```

The command prints the scope, the new `expires_at`, and then the
plaintext on its own final line. Capture it; it is not recoverable.

⚠️ `--operator` must match the client's EXISTING scope — the command
refuses to re-scope a principal while issuing a token, because that
would silently change the reach of every token already issued against
it.

### 2. Update the consumer, then roll it

**Vault-backed (`orchestration-root`, `edge-telemetry-relay`):**

```bash
vault kv put hippius-compute/vali/synthetic-monitor root-token=-   # reads stdin
```

ESO re-materialises the Secret on its `refreshInterval`. Confirm the
Secret's `resourceVersion` changed before continuing — a CronJob that
starts before ESO has refreshed will still hold the old value (harmless
during the overlap, but it means step 3 is not yet safe).

**Secret-backed (`tenant-baker-worker`):**

```bash
sudo k3s kubectl -n vali create secret generic vali-tenant-baker-worker-token \
  --from-literal=token=- --dry-run=client -o yaml | sudo k3s kubectl apply -f -
```

Then roll the consumer so it re-reads the value:

- `orchestration-root` → nothing to roll; the next CronJob run picks it up.
- `tenant-baker-worker` → `kubectl -n vali rollout restart deploy/vali-bake-spawner`
  (the baker Job reads the Secret at pod start).
- `edge-telemetry-relay` → `kubectl -n edge-gateway rollout restart deploy/edge-gateway`.

### 3. Prove the consumer moved BEFORE revoking

Re-run the inventory:

```bash
sudo k3s kubectl -n vali exec deploy/vali -- \
  python manage.py vali_identity_deactivate_token \
    --client orchestration-root --dry-run
```

Do not proceed until **both** are true:

- the NEW token's `last_used_at` has advanced past the roll;
- the OLD token's `last_used_at` has stopped moving.

For `orchestration-root` that means waiting for one synthetic-monitor
run. **Never revoke a credential you have not watched go idle** — a
botched heartbeat credential previously caused a fleet-wide
dispatchability outage.

### 4. Retire the old token

```bash
sudo k3s kubectl -n vali exec deploy/vali -- \
  python manage.py vali_identity_deactivate_token \
    --client orchestration-root \
    --token-name synthetic-monitor-2026q3
```

The command **refuses** to deactivate a principal's last *usable*
credential (active, unexpired, active client). If it refuses, step 1 or
step 2 did not land — do not reach for `--revoke-last`, which exists
only for a deliberate revocation where the principal is meant to stop
authenticating.

### 5. Rollback

There is nothing to undo: the old token is still in the database with
`is_active=False`. If the consumer breaks after step 4, re-activate it
from the Django admin (or `ServiceToken.objects.filter(...).update(is_active=True)`)
— provided it has not also passed `expires_at`. That is the second
reason not to let the overlap run to the wire.

---

## Emergency revocation

A credential believed to be leaked is a revocation, not a rotation. The
order inverts: kill first, restore after.

```bash
# one token
manage.py vali_identity_deactivate_token --client X --token-name Y --revoke-last
# the whole principal, all of its tokens at once
manage.py shell -c "
from apps.identity.models import ServiceClient
ServiceClient.objects.filter(name='X').update(is_active=False)"
```

`is_active=False` on the `ServiceClient` rejects every credential it
holds immediately — the auth path filters on `client__is_active=True`.

---

## Adding a NEW principal

Tokens are minted by `manage.py vali_identity_issue_token` only. There
is no HTTP endpoint that creates or re-scopes a principal, and the
Django admin is read/revoke-only (it cannot add a `ServiceToken`).
`--lifetime` is required; pick the class by **who holds the credential**,
not by how long you would like it to last:

- a human, for an incident or a one-off → `ops` (7d), optionally
  shortened further with `--expires-days`;
- an in-cluster machine principal → `service` (90d);
- an unattended relay whose secret lives in another namespace → `infra` (365d).

A new principal is `unclassified` unless `--operator` or `--tenant-id`
says otherwise, and `PrincipalScopeMiddleware` denies unclassified
principals the whole non-public `/v1/` surface — so forgetting the scope
is a loud 403, never a silent god-token.
