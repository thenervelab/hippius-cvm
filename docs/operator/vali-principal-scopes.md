# vali principal scopes (P2 — object-level authorization)

## What changed

vali used to authenticate a caller and then authorize nothing: any valid
`ServiceToken` could read every tenant's VMs, launch jobs and migration
jobs. That was survivable only because of the deployment shape —
**Architecture A**: tenants never hold a vali token; the upstream Django
API holds one, performs the ACLs, and calls vali on the tenant's behalf.
The whole multi-tenant boundary therefore rested on that one caller never
making a mistake, and vali would not have stopped the mistake.

vali now refuses cross-tenant access on its own. The Django API's ACL is
the first line, not the only one.

## The three scopes

Every `ServiceClient` carries an explicit `scope`:

| scope          | reach                                   | who has it |
|----------------|-----------------------------------------|------------|
| `operator`     | all tenants                             | the upstream product API, the Edge, sentinel, epoch-close, packer/bake workers, miner-admin |
| `tenant`       | exactly one `tenant_id`                 | (none today — the shape is ready for per-tenant credentials) |
| `unclassified` | **nothing** outside the public ingress  | the model default — a credential nobody scoped |

`unclassified` is the default on purpose: forgetting to scope a new
credential produces a loud `403 principal-unclassified`, never a silent
god-token.

## Issuing a credential

```
# cross-tenant (the upstream API / infra)
manage.py vali_identity_issue_token --client upstream-api \
    --token-name prod-2026q3 --operator

# confined to one tenant
manage.py vali_identity_issue_token --client acme-portal \
    --token-name prod --tenant-id acme
```

`--operator` XOR `--tenant-id` is **required** — there is no default.
The plaintext token is printed once and never persisted.

## What stops an operator grant happening by accident

- The scope is a required, mutually-exclusive CLI flag.
- vali exposes **no HTTP endpoint that creates or re-scopes a
  `ServiceClient`** — `apps.identity` has no `urls.py` and no
  `views.py`. No bearer token, however privileged, can mint or promote a
  principal over the API. The only grant paths are this command and the
  cluster-internal Django admin (`kubectl port-forward`, ClusterIP only).
- A DB CHECK constraint (`identity_serviceclient_tenant_scope_consistent`)
  refuses the `operator + tenant_id` combination outright, so a
  tenant-scoped principal cannot be promoted by a partial `UPDATE` — the
  `tenant_id` must be cleared first, through the same gated paths.
- `vali_identity_issue_token` refuses to re-scope an existing client
  while issuing a token (that would silently change the reach of every
  token already issued against it).
- Every root/worker permission class (`IsOrchestrationRoot`,
  `IsRootClient`, `IsMinerAdmin`, `IsTelemetryRoot`,
  `IsHostAttestorAdmin`, `IsPackerWorker`, `IsTenantBakeWorker`) now
  requires `scope=operator` **in addition to** the configured principal
  name — a name match alone no longer confers fleet authority.

## Adding an endpoint

Every DRF view routed under `/v1/` must declare its tenant posture:

```python
class MyView(APIView):
    object_scope = scoping.TENANT_SCOPED   # or OPERATOR_ONLY / NO_TENANT_DATA / PUBLIC
```

- `TENANT_SCOPED` — serves per-tenant objects. **Must** funnel its reads
  through `scoping.scope_queryset()` / `scoping.require_tenant_visible()`.
- `OPERATOR_ONLY` — fleet-wide surface; tenant principals are refused
  before the view runs.
- `NO_TENANT_DATA` — authenticated, but carries nothing a tenant owns.
- `PUBLIC` — deliberately unauthenticated (guest / miner ingress, docs).

If you forget, two things happen:

1. `manage.py check` fails with `identity.E001` (so does CI, via
   `test_every_shipped_api_view_declares_a_scope`).
2. At runtime `PrincipalScopeMiddleware` refuses the endpoint to any
   tenant-scoped principal — an undeclared endpoint is invisible to them.

Cross-tenant object reads answer **404, not 403**: a 403 would confirm
the object exists, which is itself a disclosure.

## Deploying this change

`manage.py migrate` **must run before** the new image is rolled out —
the code reads a `scope` column that migration `identity.0003` adds. A
vali deploy does not run migrations; the `vali-django-migrations` Argo CD
Sync-hook Job (sync-wave 2, before the Deployment at wave 3) does. A
manual out-of-band rollout must run the Job first.

The migration **grandfathers every principal that exists at migrate
time to `operator`**, preserving today's behaviour exactly. That is a
one-time compatibility grant, not a default. After the deploy, audit
`/admin/identity/serviceclient/` (the `scope` column is a list filter)
and demote anything that does not genuinely need cross-tenant reach.

## Known gap

`Vm.tenant_id` is stamped at launch from the request body. For an
`operator` caller that is an **assertion by a trusted caller**, not a
cryptographic binding — vali cannot independently verify which end user
the upstream authorized. For a `tenant` caller the value is bound to the
credential (`scoping.bind_tenant_id`). Closing the operator half needs
an upstream change (or routing launches through the L1-signed
OrderTicket, which does carry a signed `tenant_id`/`user_id`).
