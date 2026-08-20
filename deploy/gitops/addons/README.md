# `addons/` — cluster infrastructure (Argo CD app-of-apps children)

Cluster-level building blocks: CNI, load balancing, ingress, storage,
the confidential-compute runtime, the secrets operator, and
observability. Everything here is infrastructure that the
hippius-compute **applications** (`../apps/`) depend on.

PR-K3 filled in the network / ingress stack — `cilium`, `metallb`,
`cert-manager`, `ingress-nginx`. Later §K PRs add the rest (see the
table below).

## Layout convention

One subdirectory per addon. Each subdirectory is a thin **wrapper Helm
chart**:

```
addons/<addon>/
  Chart.yaml         # wrapper chart — pins the upstream chart as an
                     #   exact-version dependency
  Chart.lock         # the resolved dependency, committed
  values.yaml        # values for the upstream chart (no secrets)
  templates/         # cluster-specific extras the addon adds — config
                     #   CRs, PodDisruptionBudgets (optional)
  application.yaml   # the Argo CD Application — discovered by the root
```

The app-of-apps root (`../bootstrap/root-app.yaml`) recurses this tree
with an include glob of `*/application.yaml` — matched exactly one
directory deep — so **only** the `<addon>/application.yaml` files become
Argo CD Applications; everything else in the addon directory is not
matched. The `application.yaml` points its `source.path` at the wrapper
chart directory; Argo CD's repo-server runs `helm dependency build` from
the committed `Chart.lock` to fetch the pinned upstream chart, then
renders it. The fetched `charts/*.tgz` are build artifacts — git-ignored.

**Why a wrapper chart** (not a bare upstream `targetRevision`): pinning
the upstream chart as a `Chart.yaml` dependency lets `helm lint` / `helm
template` work locally, and lets the addon carry its own extra manifests
in `templates/` — the MetalLB `IPAddressPool`, the cert-manager
`ClusterIssuer`, a `PodDisruptionBudget` for a single-replica Deployment
the upstream chart provides none for.

`Chart.yaml` + `Chart.lock` pin the EXACT upstream version. Note this is
version-pinning, not content-pinning: a classic (non-OCI) Helm HTTP repo
can in principle re-publish a tarball at the same version — `Chart.lock`'s
`digest` covers the dependency *list*, not the tarball *bytes*. That is a
known property of the standard GitOps-Helm dependency model and is
accepted here; a future hardening could add a CI step that re-downloads
each pinned chart and asserts its SHA-256, or move to OCI digest pins.

Bump a chart: change the exact `version` in the addon's `Chart.yaml`,
run `helm dependency update <addon>/` to refresh `Chart.lock`, and bump
the wrapper chart's own `version`.

## Image pinning — grep this tree and you will be misled

**Every image an addon renders must be pinned by digest.** The pin lives
in the addon's `values.yaml`, in the form `<tag>@sha256:…` so the tag
survives as a human-readable hint while the kubelet pulls by digest.

The trap: pinning the *chart* does not pin the *images*. A chart version
pin is a pin on a tarball of templates; the image references inside come
from the upstream subchart's own defaults, and those are overwhelmingly
tag-only. Nothing about them appears in this repository. Grepping
`addons/` for `image:` therefore reports a near-clean tree while the
cluster runs a majority of mutable tags — which is exactly what the
2026-07-28 `apps/` sweep concluded before this was audited.

So do not audit by grep. Audit by render:

```sh
helm dependency build <addon>/
helm template <addon> <addon>/ --include-crds \
  | grep -oE '(quay|ghcr|docker|gcr)\.io/[^" ]+|registry\.k8s\.io/[^" ]+'
```

Every line that comes back without an `@sha256:` is unpinned.

To resolve a digest, read what the cluster is ACTUALLY running rather
than trusting the tag in a spec — `k3s crictl inspecti <ref>` and take
`repoDigests` (the multi-arch index digest). A pin resolved that way is
a no-op on the day it lands. For an image that is not resident on the
node (hook Jobs, on-demand pulls) use
`docker buildx imagetools inspect <ref>` and say so in the comment.

Charts disagree on how to express a digest — `image.digest`,
`image.sha` (sometimes bare hex, sometimes `sha256:`-prefixed), or no
field at all, in which case fold the digest into `tag`. Each addon's
`values.yaml` records which convention its chart uses. Two more things
worth knowing before writing one:

- **A digest pin is still a rollout.** Kubernetes diffs the image
  *string*, not the resolved digest, so appending `@sha256:…` changes
  the pod-template hash and restarts the workload even though the bytes
  are identical. For most addons that is a shrug. For `kata` it is not —
  see the warning in `kata/values.yaml`.
- **Some charts put the tag in a label.** If a chart derives
  `app.kubernetes.io/version` from `.Values.image.tag`, a `@` in the tag
  produces an invalid label value. Check before folding a digest into a
  tag; upstream charts that support it strip the digest themselves.

## Conventions every `application.yaml` here MUST follow

- **Name:** `hippius-compute-<addon>` (e.g. `hippius-compute-cilium`).
- **Namespace:** the Application CR lives in `argocd`; its
  `destination.namespace` is the addon's own namespace, created with
  the `CreateNamespace=true` sync option.
- **Sync policy:** `automated: { prune: true, selfHeal: true }` —
  non-negotiable, fleet-wide. The root app applies this only to itself;
  it is **not** inherited, so every child must set it explicitly. Add a
  `retry` backoff and a small `revisionHistoryLimit` too, matching
  `../bootstrap/root-app.yaml`.
- **Labels:** `app.kubernetes.io/part-of: hippius-compute` and
  `app.kubernetes.io/managed-by: argocd` on every resource.
- **Sync waves:** addons use small positive waves (`1`, `2`, `3`, …)
  set on the Application's `argocd.argoproj.io/sync-wave` annotation, so
  they converge in dependency order and well before any workload in
  `../apps/` (which uses much higher waves, `≥100`). Ordering below.
- **Pinned chart versions** — the upstream chart is an EXACT-pinned
  `Chart.yaml` dependency (no `^`, `~`, `*`, or moving tag).
- **PodDisruptionBudget** for every single-replica `Deployment` (locked
  rule #1) — via the upstream chart's PDB value where it has one, else
  a `templates/` PDB in the wrapper chart.
- No hard-coded IPs for service discovery (DNS only), no `NodePort`, no
  `hostPath`. (A MetalLB `IPAddressPool` range is address-plan config,
  not a hard-coded service IP.)

## Expected addons (filled by later §K PRs)

| Sync wave | Addon | PR | Role |
|---|---|---|---|
| 1 | `cilium` | PR-K3 | CNI — eBPF, `kubeProxyReplacement: true` |
| 2 | `metallb` | PR-K3 | Bare-metal `LoadBalancer` (L2, single-node) |
| 3 | `cert-manager` | PR-K3 | Automatic TLS (Let's Encrypt) |
| 3 | `ingress-nginx` | PR-K3 | HTTP(S) ingress; Cloudflare in front |
| 4 | `local-path-provisioner` | PR-K4 | Default `StorageClass` on the RAID1 NVMe data volume (`/var/lib/hippius-data`) |
| 5 | `external-secrets` | PR-K11 | External Secrets Operator + `ClusterSecretStore` → Vault |
| 6 | `kata` | PR-K5 | Kata Containers operator + `kata-qemu-snp` RuntimeClass (SEV-SNP) |
| 7 | `argo-cd` | PR-K12 | Argo CD self-management (RBAC + GitHub OAuth SSO) |
| 8 | `kube-prometheus-stack` | PR-K14 | Prometheus + Alertmanager + Grafana — Phase 1 slice 1 of tracking issue #128 |

Waves are a starting point — adjust as real inter-addon dependencies
surface. Two rules that hold: **every addon wave < every app wave**, and
**`external-secrets` syncs before `argo-cd` self-management** — once the
Argo CD repo credential is delivered as an `ExternalSecret` (PR-K11/K12),
ESO must be running first, hence the earlier wave above.

See [issue #54](https://github.com/thenervelab/hippius-compute/issues/54)
for the full §K plan and the locked infrastructure topology.
