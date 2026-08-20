# `hippius-runner-k8s` — self-hosted GitHub Actions runner image

Image: `ghcr.io/thenervelab/hippius-runner-k8s` (canonical build target,
cosign-signed) mirrored to `registry.hippius.com/hip-team-private/hippius-runner-k8s`
(what the k8s cluster pulls — GHCR packages default to private and the
arc-runners pull secret is for `registry.hippius.com`). Built by
`.github/workflows/runner-image.yml` on every push to `main` that
touches `runner/` or the workspace's `rust-toolchain.toml`. The mirror
to `registry.hippius.com` is currently a manual step (`docker pull` +
`docker tag` + `docker push`) — to be automated when the image-build
workflows migrate off `ubuntu-latest`.

Used by the `mon-runner-k8s` AutoscalingRunnerSet in the operator's k8s
cluster (`arc-runners` namespace). Live values: `runner/values.yaml`.

## What's baked in (vs the bare `ghcr.io/actions/actions-runner` base)

| Tool | Version | Why |
|---|---|---|
| Rust toolchain | `rust-toolchain.toml` channel (1.93.0) + rustfmt + clippy | Workspace pin; saves a ~15 s `dtolnay/rust-toolchain` install per run. |
| `build-essential` | apt-pinned | C toolchain for Rust build scripts (openssl-sys, getrandom, sev). |
| `pkg-config`, `libssl-dev`, `libcryptsetup-dev`, `clang`, `libclang-dev` | apt-pinned | `agent-initramfs::libcryptsetup-rs` bindgen + openssl-sys + sev. |
| `squashfs-tools`, `cryptsetup-bin` | apt-pinned | dm-verity rootfs reproducibility KAT. |
| `docker-ce-cli`, `docker-buildx-plugin` | docker.com apt repo | Image-build workflows talk to ARC's `containerMode: dind` sidecar via `DOCKER_HOST`. NOT a daemon. |
| `cosign` | v3.0.6, sha256-pinned | Keyless image signing on the image-build workflows. |
| `gh`, `jq`, `curl`, `git`, `xz-utils` | apt-pinned | Workflow auxiliaries. |

The image stays as close to ARC's expected runtime contract as
possible: same base, same `runner` user, same entrypoint. The Helm
chart only needs an image override.

## How to roll this out (operator)

The runnerset is managed by the
`actions-runner-controller/gha-runner-scale-set` Helm chart (currently
chart version `0.14.2`). Values live in `runner/values.yaml`. Apply
with:

```sh
helm upgrade --install mon-runner-k8s \
  oci://ghcr.io/actions/actions-runner-controller-charts/gha-runner-scale-set \
  --version 0.14.2 \
  -n arc-runners --create-namespace \
  -f runner/values.yaml
```

The values file pins the image by digest (NOT by `sha-<commit>` tag)
so a registry retag cannot silently swap the runner the workflows
execute on. To roll a new image: rebuild via `runner-image.yml`,
mirror to `registry.hippius.com`, then edit the digest in
`runner/values.yaml` and re-apply.

For workflows that need a docker daemon (`kbs-image`, `vali-image`,
`edge-image`, `ovmf-build`, `*-uki-build`): enable ARC's
docker-in-docker sidecar by adding to `runner/values.yaml`:

```yaml
containerMode:
  type: dind
```

The custom image ships only the docker CLI; the dind sidecar provides
the daemon and ARC wires `DOCKER_HOST` into the runner container
automatically. Those workflows currently still run on `ubuntu-latest`
— migrate after enabling dind.

## Trust chain

- Base image pinned by SHA-256.
- Cosign pinned by version + sha256.
- Rust toolchain pinned by `rust-toolchain.toml`.
- The pushed image is cosign-signed (keyless, GitHub OIDC →
  Sigstore Rekor entry) by `runner-image.yml`. Operators MAY verify
  before deploy:

  ```sh
  cosign verify ghcr.io/thenervelab/hippius-runner-k8s@<digest> \
    --certificate-identity-regexp='^https://github.com/thenervelab/hippius-compute/' \
    --certificate-oidc-issuer='https://token.actions.githubusercontent.com'
  ```

## Bump procedure

1. Update `BASE_IMAGE_DIGEST` in `Dockerfile` to the latest
   `ghcr.io/actions/actions-runner` release digest (verify in GHCR
   web UI).
2. Bump `COSIGN_VERSION` + `COSIGN_SHA256` if a new cosign release
   carries a security fix (verify the sha against the release
   `checksums.txt`).
3. PR. The `runner-image.yml` workflow runs on the PR and produces a
   `sha-<commit>` image you can pin in a `kubectl` sanity check.
4. Merge. Argo or the operator updates the runnerset values to the
   new digest.
