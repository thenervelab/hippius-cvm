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
| `POST /v1/admin/miner/register`                | miner-admin token   | same `(miner_id, pubkey_hex, platform_id)` ⇒ `200`; upgrades an auto-provisioned `"onchain:<node_id>"` placeholder ⇒ `200`; mismatch ⇒ `409` |
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

The body is JSON with three required fields and four optional ones:

```sh
VALI_URL="https://vali.example.com"   # or the in-cluster Service DNS

curl -sf -X POST "$VALI_URL/v1/admin/miner/register" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
          "miner_id":     "miner-b",
          "pubkey_hex":   "0123...64 lowercase hex chars (Ed25519 pubkey)",
          "platform_id":  "amd-epyc-9254",
          "netbird_peer_id": "abcdef0123456789",
          "netbird_ip":   "100.64.0.30",
          "chain_node_id": "…64 hex (on-chain compute node_id)",
          "snp_generation": "milan"
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
- `snp_generation` is the host's SEV-SNP generation: `milan`, `genoa`
  or `turin`. It selects the vCPU model vali measures the guest with
  (`EpycMilan` / `EpycGenoa` / `EpycTurin`) in the launch-digest
  recompute, and the §25 same-generation migration gate. Omitted, vali
  infers it from the chip_id length: 8 bytes ⇒ Turin, 64 bytes ⇒ Genoa.
  **Required for Milan**: a Milan chip_id is 64 bytes too, so an unset
  Milan host is measured as Genoa and every launch is refused
  (`launch-digest-mismatch`). It must agree with the chip_id length
  (`turin` = 8 bytes, `genoa` / `milan` = 64), else `400`
  `snp-generation-mismatch`. It is backfillable: re-posting with a
  generation sets it once on a row that has none; a **different** stored
  value is `409` (correct a wrong one from the Django admin, which runs
  the same consistency check). A re-post that omits it leaves it as is.
  The length check cannot tell Milan from Genoa, so a wrong
  `genoa`/`milan` is accepted and then fails every launch on that host
  closed (`launch-digest-mismatch`): confirm the CPU (`lscpu`, EPYC
  7003 = Milan, 9004 = Genoa) before posting it.

Re-registering the **same** `(miner_id, pubkey_hex, platform_id)`
triple returns `200` (idempotent); a `miner_id` with different key
material — or a `pubkey_hex` / `platform_id` that collides with a
**different** miner — returns `409`.

**Auto-provisioned miners.** A permissionless miner's first
on-chain-gated heartbeat makes vali create its row itself
(`apps.telemetry.service.autoprovision_node_heartbeat_source`), with
`pubkey_hex` = `chain_node_id` = the node id and the placeholder
per-node placeholder `platform_id = "onchain:<node_id>"`
(`apps.miners.models.autoprovision_platform_id`; recognised everywhere
through `is_autoprovision_placeholder`, which also accepts the legacy bare
`"onchain"` that migration `0006` rewrites) — vali cannot know the
CHIP_ID, and the scheduler and the launch-digest mapping both refuse the
placeholder. Registering that `miner_id` with the **same**
`pubkey_hex` upgrades the row: the placeholder becomes the posted
`platform_id` and the unset fields below are backfilled. That is the
only case in which a stored `platform_id` changes; a different
`pubkey_hex`, or a stored real `platform_id` that differs, is still
`409`. Because the replacement is one-way, the posted `platform_id` must
be the CHIP_ID as bare hex, ≥ 8 bytes (no `0x`, no whitespace), else
`400` and the placeholder stays. `miner_id` must be the id the agent
signs its heartbeats with (the auto-provisioned row's key) — any other
id is a new registration and collides on `pubkey_hex` (`409`). A
concurrent auto-provision that lands mid-register is handled like a
sequential re-register.

The placeholder carries the node id because `platform_id` is unique: any
number of permissionless miners can be auto-provisioned before any of
them is registered. Posting a placeholder (another node's, or the legacy
literal) never replaces a stored one — that is a plain mismatch (`409`) —
and a NEW miner cannot be created on a placeholder (`400`): it would squat
that node's auto-provision.

Backfill rules on an existing row (all `409` checks run before any
write, and every change lands in one savepoint, so a `409` — including
a unique collision on `platform_id` / `chain_node_id` with another
miner — leaves the row untouched):

| Field | Unset on the row | Same value | Different value |
| ----- | ---------------- | ---------- | --------------- |
| `platform_id` | — | `200` | `409`, unless the stored one is the placeholder ⇒ upgraded |
| `chain_node_id`, `snp_generation` | set | `200` | `409` |
| `netbird_peer_id`, `netbird_ip` | set | `200` | ignored — stored value kept, `200` |

## Quarantine a miner

Quarantine deactivates the miner's linked `TelemetrySource`, so the
§9 broker refuses its signed envelopes (`403`) until an operator
re-registers it. Idempotent — already-quarantined is `200`:

```sh
curl -sf -X POST "$VALI_URL/v1/admin/miner/miner-b/quarantine" \
    -H "Authorization: Bearer $TOKEN" | jq
```

## List the registry

Open to any authenticated service client (sentinel, ops) — read-only:

```sh
curl -sf "$VALI_URL/v1/admin/miner/list?limit=50" \
    -H "Authorization: Bearer $TOKEN" | jq
```
