# `apps.miners` — compute-miner registry

The miner registry is the trust anchor for miner-signed telemetry
(§13 / §23). Every miner-signed envelope the §9 broker accepts is
verified against a key in this registry; the registry is **never**
derived from a miner's self-report.

This README is the operator runbook for the two write endpoints —
register a miner, quarantine a miner — and the read endpoint that
lists what is currently registered.

## Endpoints

| Endpoint                                       | Auth                | Idempotency                                |
| ---------------------------------------------- | ------------------- | ------------------------------------------ |
| `POST /v1/admin/miner/register`                | miner-admin token   | same `(miner_id, pubkey_hex, platform_id)` ⇒ `200`; mismatch ⇒ `409` |
| `POST /v1/admin/miner/<miner_id>/quarantine`   | miner-admin token   | already quarantined ⇒ `200`                |
| `GET  /v1/admin/miner/list`                    | any service token   | offset-paginated by `miner_id`             |

`POST` endpoints are gated by `apps.miners.permissions.IsMinerAdmin`,
which accepts only the single `ServiceClient` named by
`settings.VALI_MINER_ADMIN_PRINCIPAL`. An empty value fails closed —
the endpoints `403` until the principal is seeded. Both the seeding
command and the permission check `.strip()` the env value before
comparison (a Kubernetes ConfigMap can carry a trailing newline);
they are **case-sensitive**, so pick a casing and stay with it across
`values.yaml` and any future re-seed.

## One-time bootstrap — seed the miner-admin

The principal name is operator config (`config.minerAdminPrincipal`
in `deploy/gitops/apps/vali/values.yaml`, rendered into the
`VALI_MINER_ADMIN_PRINCIPAL` env var via `configmap-vali.yaml`). The
default — `miner-admin` — is fine for a fresh deploy.

Seed the principal AND mint its bearer token by execing into the vali
pod and running the management command. The token plaintext is shown
**once**:

```sh
KUBECONFIG=<PATH_TO_YOUR_KUBECONFIG>
TOKEN="$(kubectl -n vali exec deploy/vali -- \
    python manage.py vali_identity_seed_miner_admin \
    | tail -n 1)"

# Capture $TOKEN somewhere safe — vali has no recovery path.
```

The command is **idempotent**: re-running it after the principal is
already seeded is a no-op success (it prints a `--rotate` hint).

### Rotating the bearer token

If the token is lost, mint a fresh one. Rotation is non-destructive
— old tokens stay active so a running ops script does not break
mid-rotation; disable the obsolete tokens in Django admin or via SQL
once the new one is in use:

```sh
NEW_TOKEN="$(kubectl -n vali exec deploy/vali -- \
    python manage.py vali_identity_seed_miner_admin --rotate \
    | tail -n 1)"
```

A `--token-name <label>` argument is also accepted if you want to
issue a second named token under a stable label (e.g.
`--token-name ops-2026q2`).

## Register a miner

The body is JSON with three required fields and two optional ones:

```sh
VALI_URL="https://vali.hippius.network"   # or the in-cluster Service DNS

curl -sf -X POST "$VALI_URL/v1/admin/miner/register" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
          "miner_id":     "miner-2",
          "pubkey_hex":   "0123...64 lowercase hex chars (Ed25519 pubkey)",
          "platform_id":  "amd-epyc-9254",
          "netbird_peer_id": "abcdef0123456789",
          "netbird_ip":   "100.64.0.30"
        }' | jq
```

- `pubkey_hex` is the miner's self-generated Ed25519 public key — the
  output of `hippius-miner-agent init-identity --print-pubkey` on the
  miner host (the secret half never leaves that host).
- `platform_id` is the operator-assigned hardware class (e.g.
  `amd-epyc-9254`). It is a stable string, not a UUID.
- `netbird_peer_id` / `netbird_ip` are optional but recommended once
  the miner is in the mesh — they help operators correlate envelopes
  to a NetBird dashboard row.

Re-registering the **same** `(miner_id, pubkey_hex, platform_id)`
triple returns `200` (idempotent); a `miner_id` with different key
material — or a `pubkey_hex` / `platform_id` that collides with a
**different** miner — returns `409`.

## Quarantine a miner

Quarantine deactivates the miner's linked `TelemetrySource`, so the
§9 broker refuses its signed envelopes (`403`) until an operator
re-registers it. Idempotent — already-quarantined is `200`:

```sh
curl -sf -X POST "$VALI_URL/v1/admin/miner/miner-2/quarantine" \
    -H "Authorization: Bearer $TOKEN" | jq
```

## List the registry

Open to any authenticated service client (sentinel, ops) — read-only:

```sh
curl -sf "$VALI_URL/v1/admin/miner/list?limit=50" \
    -H "Authorization: Bearer $TOKEN" | jq
```
