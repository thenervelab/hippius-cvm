# `deploy/gitops/` — Argo CD app-of-apps

GitOps deployment for the hippius-compute control plane. **Git is the
source of truth for the cluster.** A change reaches production by being
merged to `main`, not by anyone running `kubectl`.

> **No manifest in this tree is ever `kubectl apply`-ed by hand.**
> Everything is reconciled by Argo CD. The only two exceptions are the
> one-time bootstrap steps below — and after PR-K12 even Argo CD manages
> itself.

This is **PR-K0**: the scaffold. The directories below are structured
and documented but mostly empty; PR-K1..K15 fill them in. See
[issue #54](https://github.com/thenervelab/hippius-compute/issues/54)
for the full §K plan and the locked infrastructure topology
([decision](https://github.com/thenervelab/hippius-compute/issues/1#issuecomment-4505904116)).

## The workflow

```
  edit YAML  ──►  PR  ──►  review + merge to main  ──►  Argo CD
  (locally)                                            detects the
                                                       commit, syncs
                                                       the cluster
                                                            │
                                                            ▼
                                               cluster converges to
                                               match Git (prune +
                                               self-heal, automated)
```

1. Edit a chart's `values.yaml` or an `application.yaml` on a branch.
2. Open a PR. CI + review run.
3. Merge to `main`.
4. Argo CD polls `main`, sees the commit, and syncs — `prune: true`
   removes what you deleted, `selfHeal: true` reverts any manual drift.

There is no step where a human applies a manifest to the cluster.

## Directory layout

| Path | What | Filled by |
|---|---|---|
| `bootstrap/argo-cd-install.yaml` | Helm **values** for the one-time `helm install` of Argo CD itself | PR-K0 |
| `bootstrap/root-app.yaml` | The app-of-apps **root** `Application` | PR-K0 |
| `addons/` | Cluster infrastructure — CNI, LB, ingress, storage, runtimes, secrets, observability | PR-K3..K14 |
| `apps/` | hippius-compute workloads — KBS, vali, Edge, sentinel, packer | PR-K4, K6..K10 |
| `secrets/` | Docs only — how secrets reach the cluster (External Secrets + Vault). **Never any secret value.** | PR-K11 |

`addons/` and `apps/` each carry their own `README.md` with the
per-child conventions and the expected contents.

## App-of-apps, concretely

`bootstrap/root-app.yaml` is a single Argo CD `Application` with two
directory sources — `addons/` and `apps/` — each recursed with an
include glob of `*/application.yaml`.

```
root-app.yaml
   ├── recurses addons/  ── picks up addons/<addon>/application.yaml
   └── recurses apps/    ── picks up apps/<app>/application.yaml
```

Each `application.yaml` is itself an Argo CD `Application` that points
at an upstream Helm chart (or local manifests) plus a sibling
`values.yaml`. The glob matches exactly one directory deep (`*` does
not cross `/`), so only `<name>/application.yaml` files become
Applications — `values.yaml`, `Chart.yaml`, `.gitkeep` and READMEs
sitting next to them are not matched.

**Ordering** is by sync wave: `addons/` children use low/negative waves,
`apps/` children use higher waves, so cluster infrastructure is healthy
before any workload schedules. The root app itself is sync wave 0.

## Naming conventions

- **Argo CD Application:** `hippius-compute-<name>` —
  `hippius-compute-cilium`, `hippius-compute-kbs`, …
- **Subdirectory:** one per addon/app, named for the addon/app, holding
  exactly one `application.yaml`.
- **ExternalSecret files:** `*-external-secret.yaml` (see
  [`secrets/README.md`](./secrets/README.md)).
- **Every Kubernetes resource** carries
  `app.kubernetes.io/part-of: hippius-compute` and
  `app.kubernetes.io/managed-by: argocd` — the one exception is the
  bootstrap Argo CD install itself, which is Helm-managed until PR-K12
  hands it to Argo CD self-management (see `bootstrap/argo-cd-install.yaml`).

## Adding a new app

1. `mkdir deploy/gitops/apps/<app>/`.
2. Add `values.yaml` — Helm values, **no secret values** (use an
   `ExternalSecret` instead).
3. Add `application.yaml` — an Argo CD `Application` named
   `hippius-compute-<app>`, following the conventions in
   [`apps/README.md`](./apps/README.md): automated sync policy,
   part-of/managed-by labels, a sync wave above every addon, the right
   `nodeSelector`.
4. Open a PR. On merge, the root app discovers the new `application.yaml`
   automatically — nothing else to wire.

Adding an addon is the same under `addons/`, with a low/negative sync
wave.

## Invariants (locked — see #1, #54)

- **No secret values in Git, ever** — External Secrets Operator + Vault
  only ([`secrets/README.md`](./secrets/README.md)).
- **No hard-coded IPs** — DNS / Kubernetes service names only.
- **No `hostPath`** — persistent storage is always a PVC via
  `local-path-provisioner` (PR-K4).
- **No `NodePort`** for internal services — `ClusterIP` + Ingress.
- **No manual `kubectl apply`** — Argo CD from day one.
- **Sync policy** `automated: { prune: true, selfHeal: true }` on every
  Application.
- **No `replicas: 1`** without a `PodDisruptionBudget`.
- **Container images** — non-confidential (runc) workloads pull a
  PRIVATE `ghcr.io/thenervelab` image via an `ExternalSecret`
  image-pull credential (Edge, vali, sentinel, packer). **Confidential
  (`kata-qemu-snp`) workloads publish a PUBLIC image** + cosign keyless
  attestation: a confidential pod *guest-pulls* its image inside the
  SEV-SNP CVM and cannot use `imagePullSecrets`, and the image carries
  no secrets (those arrive at runtime via Vault), so a public image is
  sound — security rests on SEV-SNP attestation + the §22 signature +
  Vault, not image privacy. Affects KBS now; the Audit-VM agent later.

## Bootstrap (run once, by an operator)

Chicken-and-egg: Argo CD cannot install itself before it exists. Two
imperative steps, once, then never again:

```sh
# 1. Install Argo CD via Helm (pinned chart version — see the values file).
helm repo add argo https://argoproj.github.io/argo-helm
helm repo update
helm install argocd argo/argo-cd \
  --namespace argocd --create-namespace \
  --version 9.5.15 \
  -f deploy/gitops/bootstrap/argo-cd-install.yaml

# 2. Register this (private) repo with Argo CD so it can read manifests.
#    Use a deploy key or a fine-grained read-only token; in steady state
#    PR-K11/K12 manage the repo credential via External Secrets.
argocd repo add git@github.com:thenervelab/hippius-compute-internal.git \
  --ssh-private-key-path <deploy-key>

# 3. Apply the app-of-apps root — the LAST manual apply.
kubectl apply -f deploy/gitops/bootstrap/root-app.yaml
```

From here Argo CD owns the cluster. PR-K12 converts Argo CD's own
lifecycle to self-management, closing the loop.

## Secret-scanning hygiene

Two backstops guard against a secret ever landing in Git:

- **`deploy/.gitignore`** — blocks `*.pem`, `*.key`, raw `*-secret.yaml`,
  `kubeconfig*`, `.env*`, `*.tfstate`, … across the whole `deploy/` tree.
- **gitleaks pre-commit hook** — `.pre-commit-config.yaml` at the repo
  root scans every staged file. Enable it once per clone:

  ```sh
  pip install pre-commit   # or: brew install pre-commit
  pre-commit install       # run from the repo root
  ```

  After that, `git commit` runs gitleaks + a private-key detector on
  staged files and refuses the commit if either fires.

Neither replaces the rule — they catch the day someone forgets it.
