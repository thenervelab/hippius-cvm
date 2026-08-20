# vali — orchestration Django service

vali is the Hippius DePIN orchestration plane (ARCHITECTURE.md §3 /
§4 / §17.5): a small Django + DRF service that ingests L1 OrderTickets,
triggers Packer builds, runs the §23 trustless scheduler, owns the
§24/§25 VM-lifecycle state machine, and brokers §9 pull-only telemetry.

This README documents the operator surfaces. Each app under
`apps/<name>/` carries its own narrower README for the wire contract
it owns.

---

## Django admin — ops eyeball (#152)

vali ships a Django admin at `/admin/` so on-call has read-mostly
visibility into every durable model the app touches — `ServiceClient`,
`Vm`, `MinerIdentity`, `MigrationJob`, `DecommissionJob`,
`OrderTicketIntake`, `PackerBuild`, `MinerCapacity`, `Placement`,
`TelemetrySource`, `TelemetryEnvelope`, `ServiceToken`.

### Security envelope

- **ClusterIP-only.** The vali Service is `ClusterIP`; there is no
  Ingress in front of `/admin/`. Ops reach it via `kubectl
  port-forward` (see below). A future Ingress for the API surface
  must explicitly carve out `/admin/` (path-deny) — public exposure
  of the admin is OUT OF SCOPE for #152 and a hard policy line.
- **Separate auth plane.** The admin authenticates against
  `django.contrib.auth.User` (username + password, session cookie).
  This is **distinct** from the API-surface `ServiceClient` /
  `ServiceToken` registry — they share no rows, no permissions, no
  middleware. Compromising an admin password does not grant
  `ServiceToken` access (and vice-versa).
- **Read-mostly by policy.** Models whose lifecycle is owned by a
  state machine (`Vm.state`, `MigrationJob.state`,
  `Placement.status`, …) have those columns forced read-only at the
  `ModelAdmin` layer; hand-edits would race the optimistic-CAS
  invariant the views enforce. See each `apps/*/admin.py` docstring
  for the per-field rationale.
- **Secret discipline.** `ServiceToken.token_sha256`,
  `Vm.lifecycle_vk`, `Vm.eol_nonce`,
  `TelemetrySource.verifying_key`, `TelemetryEnvelope.payload_cbor`,
  and `OrderTicketIntake.cose_blob` are forced read-only AND excluded
  from `list_display` — they may not be edited from the admin and
  the changelist never renders them inline. The smoke tests in
  `apps/identity/tests/test_admin.py` keep this invariant locked.

### Seeding the first superuser

Use the `seed_admin_user` management command — `idempotent`, refuses
to silently promote an existing non-superuser of the same name, and
emits the connect hint after it succeeds.

**Non-interactive (deploy YAML, Kubernetes Job, ansible):**

```bash
DJANGO_SUPERUSER_PASSWORD='<from-Vault-or-Secret>' \
    python manage.py seed_admin_user --username ops
```

**Interactive (`kubectl exec` into the live pod):**

```bash
kubectl --kubeconfig=<PATH_TO_YOUR_KUBECONFIG> \
    -n vali exec -it deploy/vali -- \
    python manage.py seed_admin_user --username ops
# (prompts twice with getpass — terminal echo is suppressed)
```

A re-run with the same `--username` against an existing **active
superuser** is a no-op success. A re-run against a same-named
**non-superuser** fails loud (`CommandError`) — pick a different
username or fix the row by hand. Rotation = change the password
through the admin UI (`/admin/auth/user/<id>/password/`), not by
re-running this command.

### Reaching the admin

The vali Service has no Ingress. Open a local port to the cluster:

```bash
kubectl --kubeconfig=<PATH_TO_YOUR_KUBECONFIG> \
    -n vali port-forward svc/vali 8000:8000
# then open http://localhost:8000/admin/
```

`port-forward` proxies through the API server — kubeconfig RBAC is
the only auth between you and the admin login form, so the operator
must already hold cluster credentials.

### Static assets

`collectstatic` writes Django's admin CSS / JS into
`STATIC_ROOT` (`vali/staticfiles/` in the build, baked into the
container image at deploy time). A missing static asset shows up as
an unstyled admin page; functionality (login, list pages, edits) is
unaffected.

---

## Other ops surfaces

See:

- `apps/miners/README.md` — miner-fleet registry (the registry the
  §9 broker trusts for miner-signed envelopes).
- `apps/packer/README.md` — Packer trigger surface + Hippius S3
  presigning.
- `ARCHITECTURE.md` (repo root) — full Hippius DePIN spec.
