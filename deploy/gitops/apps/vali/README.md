# `apps/vali` — vali Django orchestration service + Postgres (PR-K7, §K)

Deploys the `vali` Django service (§G) and its Postgres database — the
OrderTicket intake path that unblocks Milestone A. Spec of record:
`ARCHITECTURE.md` §3 / §4 / §17.5; locked topology —
[issue #1 comment](https://github.com/thenervelab/hippius-compute/issues/1#issuecomment-4505904116).

## Layout

| File | Purpose |
|---|---|
| `application.yaml` | Argo CD Application — sync wave 11. |
| `Chart.yaml` / `values.yaml` | In-house Helm chart. |
| `templates/configmap-vali.yaml` | vali non-secret env. |
| `templates/external-secret-{db,django,s3,ghcr}.yaml` | Vault-backed secrets. |
| `templates/statefulset-postgres.yaml` + `service-postgres.yaml` | Postgres 16 + headless Service. |
| `templates/job-django-migrations.yaml` | `manage.py migrate` — Argo Sync hook. |
| `templates/deployment-vali.yaml` + `service-vali.yaml` | vali (gunicorn) + ClusterIP. |
| `templates/cronjob-postgres-backup.yaml` | Nightly `pg_dump` → Hippius S3. |
| `templates/networkpolicy.yaml` | 3 `CiliumNetworkPolicy` — default-deny. |
| `templates/poddisruptionbudget.yaml` | vali + Postgres PDBs. |

## Sync ordering

Argo processes the chart by `sync-wave`, waiting for each wave Healthy:

0. ConfigMap + the 4 ExternalSecrets.
1. Postgres StatefulSet + Service + PDB + NetworkPolicy.
2. **`vali-django-migrations`** — a `manage.py migrate` Job, an Argo
   **Sync hook** (not PreSync — PreSync runs before Postgres exists).
3. vali Deployment + Service + PDB + NetworkPolicy + the backup CronJob.

## Image

`ghcr.io/thenervelab/hippius-vali` is **private** — vali is a runc
workload, so the chart pulls it with a Vault-materialised GHCR
credential (the confidential/public-image rule applies only to
`kata-qemu-snp` pods — see `deploy/gitops/README.md`). The image is a
**3-stage build** (`vali/Dockerfile`): a Rust stage builds
`hippius-ticket-validator` (the OrderTicket intake view shells out to
it for COSE_Sign1 parsing — vali never verifies the L1 signature
itself), a Python stage installs the `vali` package + gunicorn, and the
runtime stage carries both, non-root. Pinned by digest; cosign-signed
keyless by `.github/workflows/vali-image.yml`.

## Wired to the vali codebase

The K7 brief predated a close read of `vali/`; the chart matches the
app's actual interface:

- Django project package is **`vali`** (not `api_backend`):
  `DJANGO_SETTINGS_MODULE=vali.settings`, gunicorn `vali.wsgi:application`.
- Env vars are `DJANGO_SECRET_KEY`, `DATABASE_URL`, `DJANGO_ALLOWED_HOSTS`,
  `DJANGO_DEBUG`, `VALI_TICKET_MAX_BYTES`, `VALI_TICKET_VALIDATOR_BIN`.
  Only `DJANGO_SECRET_KEY` is import-time-fatal (in production); every
  other `VALI_*` knob has a safe default.
- vali does **not** consume S3 credentials — its S3 client factory
  defaults to an in-process mock (the boto factory is a §G3 follow-up).
  The `vali-s3` secret feeds the backup CronJob only.
- `collectstatic` runs at **image build time** (PR #159, §G admin)
  into `/app/staticfiles`; WhiteNoise serves the Django admin's
  CSS/JS from gunicorn at runtime. The pod's
  `readOnlyRootFilesystem: true` invariant is preserved —
  `/app/staticfiles` is part of the read-only image layer, never
  written to at runtime.

## Reconciled vs the K7 template list

Dropped, with reason: `namespace.yaml` (Argo `CreateNamespace`);
`ingress-vali.yaml` (ClusterIP-only for now — the external L1↔vali
mTLS-terminated ingress needs the PR-K13 CA + real DNS; matches the KBS
/ Edge ClusterIP pattern); `configmap-postgres.yaml` (the migrations
need no Postgres extension); `serviceaccount.yaml` +
`automountServiceAccountToken: false` (vali's code makes no Kubernetes
API call — flip when PR-K10 wires Packer-as-Jobs); `servicemonitor.yaml`
(PR-K14 — vali has no `/metrics` endpoint yet); the `vali-state` PVC
(vali is stateless — no sessions, no admin). Postgres uses a
StatefulSet `volumeClaimTemplate`, not a standalone PVC.

## Operator setup — Vault secrets

`secret/hippius-compute/vali` and `.../vali/s3` (KV-v2) must exist in
Vault **before** the app syncs. External Secrets Operator reads them
with the `hippius-vault` ClusterSecretStore's own credential (PR-K11).
Provision them as:

```sh
# Strong, URL-safe secrets (the password rides a postgres:// URL — no
# '/' or '+' that would break URL parsing).
PGPASS=$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')
DJANGO_SECRET=$(python3 -c 'import secrets; print(secrets.token_urlsafe(64))')
vault kv put secret/hippius-compute/vali \
  postgres-password="$PGPASS" django-secret-key="$DJANGO_SECRET"
unset PGPASS DJANGO_SECRET

# Hippius S3 credentials for the nightly backup. TODO(operator):
# replace these placeholders with real Hippius S3 keys — until then the
# backup's pg_dump runs but the S3 upload fails.
vault kv put secret/hippius-compute/vali/s3 \
  access-key="<hippius-s3-access-key>" secret-key="<hippius-s3-secret-key>"
```

### KBS admin mTLS — vali's client identity

The KBS lifecycle admin API authenticates its callers with mTLS and
nothing else. vali's half is an operator-minted client leaf whose
`SAN URI` MUST be `spiffe://hippius.network/vali` (the KBS reads it back
as the `peer_san` on every admin audit row), plus the CA that pins the
listener's server cert:

```sh
vault kv put secret/hippius-compute/vali/kbs-admin-mtls \
  cert=@vali.crt key=@vali.key ca=@ca.crt
```

then set `kbsAdminMtls.secretName` / `.vaultPath` and the three
`config.kbsAdmin{ClientCert,ClientKey,Cacert}` paths. Staging the
material is **inert**: vali keeps dialling plaintext until
`config.kbsAdminUrl` becomes `https://`, and it logs
`client material staged and VALID` in the meantime — that log line is
the rollout's gate. Full procedure, including the KBS-side ordering and
the restart cost, in
**`docs/operator/kbs-admin-mtls-cutover-runbook.md`**.

The `hippius-compute/ghcr` credential is the fleet-wide GHCR PAT,
already provisioned (shared with PR-K8). The `vali` namespace carries
`hippius.network/vault-secrets: enabled` (via the Application's
`managedNamespaceMetadata`) so the ClusterSecretStore admits these
ExternalSecrets.

## Nightly backup

`cronjob-postgres-backup.yaml` runs daily: an init container `pg_dump`s
to a shared `emptyDir`, then an `amazon/aws-cli` container `aws s3 cp`s
the gzipped dump to `s3://hippius-compute-backups/vali/postgres/` (§K-K1
bucket). Both containers are upstream, digest-pinned, non-root, with no
runtime package install. Retention: `successfulJobsHistoryLimit`.

## Enabling `vali_create_vm` (DEV ONLY)

`vali_create_vm` is the DEV-MODE end-to-end provisioning command
(`docs/operator/vali-create-vm-runbook.md`). It wraps the
`stage → preflight → allowlist-pin → mint → register → launch` chain
in one mgmt command. The chart's `createVm.enabled` toggle gates the
extra Volume mounts the command needs (§22 root seed, the allowlist
manifest TOML, the Vault CA bundle). The L1 OrderTicket signing seed is
NOT mounted — vali fetches it from Vault
(`secret/hippius-compute/vali/l1-order-ticket`, field `seed`) and
materializes it 0600 in tmpfs only for the mint subprocess (#587
Phase 1A; no committed dev seed).

> **PRODUCTION (audit H2): trust anchors live in Vault, not k8s.** On a prod
> cluster `createVm.enabled` is `false` (the dev CLI is disabled with
> `VALI_ALLOW_PROD=true`, #679) and BOTH trust-anchor seeds are read at
> runtime from Vault by vali's scoped token —
> `hippius-compute/vali/allowlist-root` and
> `hippius-compute/vali/l1-order-ticket` (field `seed`), wired via
> `VALI_KBS_ALLOWLIST_ROOT_SEED_VAULT_PATH` /
> `VALI_L1_SIGNING_KEY_VAULT_PATH`. The plaintext `vali-allowlist-root-seed` /
> `vali-l1-signing-key` Secrets below are a DEV-cluster affordance ONLY and
> MUST NOT be applied on prod; the matching prod Secrets were removed. See
> [`docs/operator/trust-anchor-rotation.md`](../../../../docs/operator/trust-anchor-rotation.md)
> for the rotation runbook.

Operators MUST apply the objects below out of band BEFORE
flipping `createVm.enabled: true` on a DEV cluster — the chart deliberately
does not template them, so a templating typo cannot leak production-tier
authority.

```yaml
# §22 allowlist root signing seed (32-byte hex on a single line).
# DEV cluster only — prod reads this from Vault (see the note above).
apiVersion: v1
kind: Secret
metadata:
  name: vali-allowlist-root-seed
  namespace: vali
type: Opaque
stringData:
  seed: |
    <64-hex allowlist root seed — packer/kbs-uki/keys/dev/provenance-root.dev.ed25519 for dev>
---
# 3. The current dev-manifest.toml. Vali's auto-pin reads + bumps +
#    re-signs this file every time --auto-pin-allowlist is set.
apiVersion: v1
kind: ConfigMap
metadata:
  name: vali-allowlist-manifest
  namespace: vali
data:
  dev-manifest.toml: |
    <contents of test_vectors/allowlist/dev-manifest.toml>
---
# 4. Vault CA bundle for the KV v2 writes.
apiVersion: v1
kind: ConfigMap
metadata:
  name: vault-ca
  namespace: vali
data:
  ca.crt: |
    -----BEGIN CERTIFICATE-----
    <…>
    -----END CERTIFICATE-----
```

Then `helm install --set createVm.enabled=true …` (or set it via
ArgoCD). The vali pod re-rolls with the four read-only mounts.

The `VAULT_TOKEN` env var STILL has to be supplied per invocation
(not in pod state). The operator runs
`kubectl exec deploy/vali -- env VAULT_TOKEN=$(cat ~/.vault-token) AWS_ACCESS_KEY_ID=… AWS_SECRET_ACCESS_KEY=… python manage.py vali_create_vm …`
which keeps both tokens transient.

## Follow-ups

- **External L1↔vali ingress** — mTLS-terminated, on `vali.hippius.network`
  — gated on PR-K13 (the mTLS CA) + the real DNS.
- **Scheduler / orchestration / telemetry-GC workers** — the
  `vali_scheduler_reeval` / `vali_orchestration_tick` / `vali_telemetry_gc`
  management commands as their own Deployments (§G4/G5/G6).
- **PR-K10** — Packer-as-k8s-Jobs → vali gains a ServiceAccount + RBAC.
- **PR-K14** — a `/metrics` endpoint + a `ServiceMonitor`.
- **§G3 boto S3** — the real Hippius S3 client (vali → S3 egress added
  to the NetworkPolicy then).
