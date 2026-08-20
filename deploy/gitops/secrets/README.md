# `secrets/` — how secrets reach the cluster (they never live in Git)

**Invariant, non-negotiable:** no secret value is ever committed to this
repository — not in plaintext, not "encrypted at rest", not in any form.

This directory holds **no secret material and no `kind: Secret`
manifests**. It exists to document the one supported path and to be the
obvious place a reviewer looks to confirm the rule is being followed.

## The only supported path: External Secrets Operator + Vault

```
   HashiCorp Vault                  Kubernetes cluster
   ┌─────────────┐                  ┌──────────────────────────────┐
   │ secret/...  │   ClusterSecret  │ External Secrets Operator    │
   │  values     │◄─────Store───────│  (reconciles ExternalSecrets) │
   └─────────────┘                  │            │                  │
                                    │            ▼                  │
   committed to Git ───────────────►│  ExternalSecret CR            │
   (references only)                │  (Vault path + keys, NO value)│
                                    │            │                  │
                                    │            ▼                  │
                                    │  kind: Secret  (materialised  │
                                    │  in-cluster, never in Git)    │
                                    └──────────────────────────────┘
```

- **Vault** is the source of truth for every secret value.
- The **External Secrets Operator** (ESO) and a **`ClusterSecretStore`**
  pointing at Vault are installed as a cluster addon — **PR-K11**
  (`../addons/external-secrets/`).
- Each app that needs a secret commits an **`ExternalSecret`** custom
  resource. That CR contains only a Vault **path** and the **key names**
  to project — never a value. ESO reads Vault and materialises a normal
  `kind: Secret` *inside the cluster*. That materialised Secret is never
  written back to Git.

## Explicitly NOT used

- ❌ **Sealed Secrets** — the ciphertext still lives in Git; key
  rotation / disaster recovery is awkward; Vault is already the fleet
  secret store.
- ❌ **SOPS / age / git-crypt** — same objection: encrypted secrets in
  Git are still secrets in Git.
- ❌ **Plaintext `kind: Secret` manifests** — obviously.
- ❌ `kubectl create secret` by hand — breaks GitOps reproducibility
  (the secret would exist only in someone's shell history).

## Naming convention for `ExternalSecret` CRs

Name the files `*-external-secret.yaml` (e.g.
`kbs-vault-external-secret.yaml`). Two reasons:

1. It reads clearly in review.
2. `deploy/.gitignore` blocks `*-secret.yaml` as a safety net against
   committing a raw `Secret`; the `!*-external-secret.yaml` negation in
   that file keeps these reference-only CRs trackable. Stay inside the
   convention and the safety net never fights you.

## Defence in depth

Two independent backstops catch a mistake before it reaches `main`:

1. **`deploy/.gitignore`** — blocks `*.pem`, `*.key`, raw `*-secret.yaml`,
   `kubeconfig*`, `.env*`, `*.tfstate`, …
2. **gitleaks pre-commit hook** — `.pre-commit-config.yaml` at the repo
   root scans every staged file for secret patterns. Enable it once per
   clone with `pre-commit install` (see `../README.md`).

Neither is a substitute for the rule. They are there for the day
someone forgets it.

See [issue #54](https://github.com/thenervelab/hippius-compute/issues/54)
(PR-K11) for the ESO + Vault wiring.
