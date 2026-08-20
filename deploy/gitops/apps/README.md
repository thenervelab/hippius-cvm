# `apps/` — hippius-compute workloads (Argo CD app-of-apps children)

The actual control-plane applications: the KBS, vali, the Edge gateway,
the sentinel, the Packer factory, and supporting jobs. Everything here
depends on the cluster infrastructure in `../addons/`.

This directory is **empty of charts today** — PR-K0 is scaffold only.
PR-K4 + PR-K6 onward fill it in. `.gitkeep` keeps the directory tracked
until then.

## Layout convention

One subdirectory per app, identical in shape to `../addons/`:

```
apps/<app>/
  application.yaml   # the Argo CD Application — discovered by the root
  values.yaml        # Helm values (no secrets — see ../secrets/)
  ...                # chart / extra manifests
```

The app-of-apps root (`../bootstrap/root-app.yaml`) recurses this tree
with an include glob of `*/application.yaml` — matched exactly one
directory deep; only those `<app>/application.yaml` files become Argo CD
Applications.

## Conventions every `application.yaml` here MUST follow

- **Name:** `hippius-compute-<app>` (e.g. `hippius-compute-kbs`).
- **Namespace:** the Application CR lives in `argocd`; its
  `destination.namespace` is the app's own namespace, created with the
  `CreateNamespace=true` sync option.
- **Sync policy:** `automated: { prune: true, selfHeal: true }` — set
  explicitly on every child (the root app does not pass it down); add a
  `retry` backoff and a small `revisionHistoryLimit` too.
- **Labels:** `app.kubernetes.io/part-of: hippius-compute` and
  `app.kubernetes.io/managed-by: argocd` on every resource.
- **Sync waves:** apps use **higher** waves than every addon, so they
  schedule only after CNI / storage / ingress / runtimes / secrets are
  healthy.
- **Secrets:** never inline. Declare an `ExternalSecret` CR that
  references Vault — see [`../secrets/README.md`](../secrets/README.md).
- **Node placement** (locked, #1): KBS and the Audit-VM agent pin
  `nodeSelector: node-role.hippius.network/confidential-compute: "true"`
  (they must land on a SEV-SNP node with `runtimeClassName:
  kata-qemu-snp`); every other app pins
  `nodeSelector: node-role.hippius.network/general-workloads: "true"`.
- No hard-coded IPs (DNS only), no `NodePort` (ClusterIP + Ingress), no
  `hostPath` (PVC via `local-path-provisioner`), no `replicas: 1`
  without a `PodDisruptionBudget`.

## Expected apps (filled by later §K PRs)

| App | PR | Notes |
|---|---|---|
| `postgres-backup` | PR-K4 | CronJob: `pg_dump` → Hippius S3 bucket |
| `kbs` | PR-K6 | First confidential pod — `kata-qemu-snp`, depends on PR-I1/I2 |
| `postgres` | PR-K7 | StatefulSet on a `local-path` PVC |
| `vali` | PR-K7 | Django orchestration service |
| `edge-gateway` | PR-K8 | HA pair — KubeVirt VMs or runc pods (decided in PR-K8) |
| `sentinel` | PR-K9 | LLM observer — wraps the existing Kustomize base (see note) |
| `packer-factory` | PR-K10 | Ephemeral Jobs that build measured UKIs |

> **Note on the layout convention.** The `values.yaml` shape above is
> the Helm default. Argo CD also drives Kustomize and plain-manifest
> sources — `sentinel` already has a Kustomize base at
> `deploy/kustomize/base/sentinel/`, so its `application.yaml` will use
> a Kustomize `source` instead of a Helm `values.yaml`. PR-K9 reconciles
> that. The hard requirements (name, sync policy, labels, sync wave,
> node placement) hold regardless of the source type.

See [issue #54](https://github.com/thenervelab/hippius-compute/issues/54)
for the full §K plan, dependencies, and the locked topology.
