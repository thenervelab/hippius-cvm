# `addons/external-secrets` — External Secrets Operator + Vault

PR-K11, §K (issue #54). Installs the [External Secrets Operator][eso]
(ESO) and wires a cluster-wide `ClusterSecretStore` named
`hippius-vault` to the Hippius **Vault Tier-0** instance. This is the
§K secret path: **every application secret transits Vault — never
plaintext in Git**. ESO pulls a secret out of Vault and projects it
into a native Kubernetes `Secret`; an app just mounts that `Secret`.

It is a prerequisite for PR-K6 (KBS deploy — KBS pulls its Vault
transit credentials through ESO) and PR-K12 (the Argo CD repo
credential is delivered as an `ExternalSecret`).

A wrapper Helm chart, same convention as the PR-K3 addons (see
[`../README.md`](../README.md)): `Chart.yaml` exact-pins the upstream
`external-secrets` chart; `templates/` adds the Vault CA ConfigMap, the
`ClusterSecretStore`, and the GitOps-only admission policy.

## What is deployed

| Resource | Purpose |
| --- | --- |
| ESO operator / webhook / cert-controller | the controllers (namespace `external-secrets`) |
| `ConfigMap/vault-ca` | the Vault Tier-0 self-signed CA — TLS verification |
| `ClusterSecretStore/hippius-vault` | the cluster-wide binding to Vault |
| `ValidatingAdmissionPolicy/hippius-eso-gitops-only` (+ binding) | admission guard — `external-secrets.io` writes are GitOps-only |

> **CRD prune blast radius.** The ESO chart renders its CRDs as plain
> templates with no `keep` flag (unlike cert-manager's `crds.keep`). A
> `kubectl delete` / Argo CD prune of this Application therefore removes
> the ESO CRDs, which cascade-deletes **every `ExternalSecret` and
> `ClusterSecretStore` cluster-wide**. Treat removing this addon as a
> fleet-wide operation, never a routine one.

## Who can use the store

`hippius-vault` is one cluster-wide store backed by a Vault token
scoped (RA-N1) to the ~12 `secret/hippius-compute/…` leaves ESO actually
syncs — NOT the whole subtree. Access to it is further constrained by
two gates:

- **Namespace gate** — the store's `spec.conditions` only serves
  `ExternalSecret`s in namespaces labelled
  `hippius.network/vault-secrets: enabled`. A consumer (KBS, vali, …)
  opts its namespace in as part of its own addon/app:
  `kubectl label namespace <ns> hippius.network/vault-secrets=enabled`.
- **Creation gate** — `external-secrets.io` resources in this fleet are
  created and modified by Argo CD from Git only, enforced in two layers:
  - *RBAC* — ESO's `rbac.aggregateToEdit/View` are turned **off**
    (`values.yaml`), so ESO's verbs are no longer folded into the
    built-in `view` ClusterRole (which carries the `get`/`list`/`watch`
    read verbs) or `edit` ClusterRole (`create`/`update`/`patch`/
    `delete`). This does **not** cover the built-in `admin` role: the
    ESO chart hardcodes `rbac.authorization.k8s.io/aggregate-to-admin:
    "true"` on its `*-edit`/`*-view` ClusterRoles with no Helm value to
    disable it, so a namespace `admin`-holder still gets `create` on
    `ExternalSecret`.
  - *Admission* — the `hippius-eso-gitops-only`
    `ValidatingAdmissionPolicy` closes that residual. It denies any
    CREATE/UPDATE/DELETE of an `external-secrets.io` resource that does
    not come from the Argo CD application-controller, the ESO
    controllers, or the `system:masters` group. It checks *who* is
    making the request, so it does not depend on which ClusterRole
    granted the verb — a namespace `admin` (or `edit`) cannot mint an
    `ExternalSecret` to siphon another app's secret.

**Operator break-glass.** The admission policy intentionally allows the
`system:masters` group, so a broken Argo CD never wedges debugging — an
operator on the direct cluster kubeconfig can still create or patch an
`external-secrets.io` resource by hand. No other identity can.

Per-app isolation (a `ClusterSecretStore` + Vault policy scoped per
application path) is a sound future tightening — out of scope for this
single-store MVP.

## Operator bootstrap — the Vault `jwt` backend

**There is no longer a `vault-token` Secret.** Since 2026-08-09 the
`hippius-vault` store authenticates with a short-lived TokenRequest token
minted for ESO's own ServiceAccount (`auth.jwt`); nothing is stored in the
cluster and there is nothing to rotate.

What the operator configures once, with the Vault root token (off-cluster,
so it cannot live in Git):

```sh
# 1. enable the backend
vault auth enable jwt

# 2. pin the cluster's SA signing pubkey — OFFLINE validation, so Vault
#    never has to reach the k8s API (see "Auth method" below for why).
#    Convert each JWK at `kubectl get --raw /openid/v1/jwks` to PEM.
vault write auth/jwt/config \
  jwt_validation_pubkeys=@sa-signing-pubkey.pem \
  bound_issuer="https://kubernetes.default.svc.cluster.local"

# 3. the role — bound to EXACTLY the ESO ServiceAccount
vault write auth/jwt/role/eso \
  role_type=jwt user_claim=sub \
  bound_audiences="https://kubernetes.default.svc.cluster.local" \
  bound_subject="system:serviceaccount:external-secrets:hippius-compute-external-secrets" \
  token_policies=hippius-compute-eso-read token_ttl=1h token_max_ttl=24h
```

Until the backend + role exist the `ClusterSecretStore` reports
`status: NotReady` — fail-closed, as intended.

⚠️ **Re-pin on SA key rotation.** The pubkey is pinned, not discovered. If
the cluster rotates its ServiceAccount signing key, every login fails until
step 2 is re-run with the new key.

### The Vault token's policy — least privilege

⚠️ **Do NOT write a `secret/data/hippius-compute/*` wildcard policy here.**
That read-all grant (the pre-RA-N1 shape) re-exposes, via a second
token, the H2 trust-anchor seeds (`vali/allowlist-root`,
`vali/l1-order-ticket`), every tenant KEK (`kbs/tenants/*`),
`s3/operator`, and `eso/vault-token` — an ESO-controller RCE could then
dump them. RA-N1 scoped the policy to **exactly the ~12 leaves ESO
actually syncs**.

The policy is source-controlled — apply it FROM the repo so the doc and
the live grant can never drift (writing an inline heredoc under the same
policy name would silently overwrite the scoped grant):

```sh
# Source of truth: deploy/terraform/policies/hippius-compute-eso-read.hcl
# (Terraform manages it via deploy/terraform/vault_policies.tf; this is
# the manual/break-glass equivalent.)
vault policy write hippius-compute-eso-read \
  deploy/terraform/policies/hippius-compute-eso-read.hcl
vault token create -policy=hippius-compute-eso-read -period=768h -orphan
```

Any NEW ExternalSecret leaf must be added to that `.hcl` (both the
`secret/data/…` and `secret/metadata/…` paths) — never widened back to a
wildcard.

**No token lifetime to manage.** ESO logs in per-sync and Vault returns a
1h token, so the ~32-day renewal chore — and the expiry class of outage it
caused elsewhere — is gone for this store. The `vault token create` line
above is no longer part of the bootstrap.

## Auth method — why `jwt` and not `kubernetes`

`kubernetes` auth (Vault calls TokenReview on the k8s API) is the more
usual choice and gives INSTANT revocation. It was implemented first and it
**does not work in this topology**: the node's ufw restricts `:6443` to the
operator IP and the NetBird range (INPUT policy `DROP`), Vault's public
address is not whitelisted, and Vault is not on the NetBird mesh. Vault
therefore cannot reach TokenReview and every login returns a bare
`permission denied` — with a clean config readback and a TokenReview that
succeeds from *inside* the cluster, which makes it a confusing failure.

> `:6443` reads as OPEN from an operator workstation because that
> workstation is itself whitelisted. That test is misleading.

Making it work would mean exposing the Kubernetes API to an external host.
The operator declined that trade (2026-08-09), so the store uses `jwt`
auth with the cluster's signing pubkey pinned in Vault — offline signature
validation, zero inbound exposure, no firewall change.

ACCEPTED trade-offs: re-pin on SA key rotation (above), and revocation is
TTL-bounded (1h) rather than instant.

This closes the ESO half of [issue #94][k8s-auth]; the remaining static
tokens (vali, tenant-baker, KBS) migrate in later phases.

[k8s-auth]: https://github.com/thenervelab/hippius-compute/issues/94

## Token rotation — N/A

There is no longer a token to rotate: ESO logs in per-sync and Vault issues
a 1h token. The old procedure (mint `-period=768h`, write the `vault-token`
Secret, revoke the old) is retired along with `auth.tokenSecretRef`.

The two operations that DO remain are in the bootstrap section above:
re-pinning `jwt_validation_pubkeys` if the cluster rotates its SA signing
key, and editing the `eso` role if the policy or ServiceAccount changes.

## Vault CA expiry

`templates/vault-ca-configmap.yaml` pins the Vault Tier-0 CA
(`CN=hippius-vault-tier0`), valid **2026-05-19 → 2028-08-21**. ESO
fails closed on an expired CA. Before `2028-08-21` (alert at 30 days
out): regenerate the Vault TLS material on the Vault host and update the
ConfigMap in the same PR. That regeneration belongs to the Vault
deployment and is NOT in this repository — this line used to name a
`scripts/` path for it that does not exist here.

```sh
# expiry check
kubectl get configmap vault-ca -n external-secrets \
  -o jsonpath='{.data.ca\.crt}' | openssl x509 -noout -enddate
```

## Secret-flow example

To project the Vault secret `secret/hippius-compute/kbs/foo` (KV v2)
into a `Secret/kbs-foo` in namespace `kbs` — the `kbs` namespace must
first be opted in (`kubectl label namespace kbs
hippius.network/vault-secrets=enabled`, see "Who can use the store"):

```yaml
apiVersion: external-secrets.io/v1
kind: ExternalSecret
metadata:
  name: kbs-foo
  namespace: kbs
spec:
  refreshInterval: 1h
  secretStoreRef:
    name: hippius-vault
    kind: ClusterSecretStore
  target:
    name: kbs-foo            # the k8s Secret ESO creates/owns
  data:
    - secretKey: foo         # key in the k8s Secret
      remoteRef:
        key: hippius-compute/kbs/foo   # path under the KV-v2 engine
        property: foo                  # field within that Vault secret
```

`status.conditions` reaches `SecretSynced` once ESO has read Vault and
written the `Secret`.

## Live validation (PR-K11)

```sh
export KUBECONFIG=~/.config/hippius/kubeconfig.yaml
vault kv put secret/hippius-compute/test dummy=hello        # operator
kubectl get clustersecretstore hippius-vault -o jsonpath='{.status.conditions}'
kubectl apply -f test-external-secret.yaml                  # → SecretSynced
kubectl get secret hippius-test-secret -o jsonpath='{.data.dummy}' | base64 -d
```

[eso]: https://external-secrets.io/
