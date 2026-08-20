# Vendoring provenance — `local-path-provisioner`

The chart under [`charts/local-path-provisioner/`](charts/local-path-provisioner)
is **vendored** from the upstream Rancher project. Rancher publishes no
official Helm repository for it (the only OCI chart, SUSE Application
Collection, requires authentication and is not GitOps-viable), so the
chart is committed in-tree — content-pinned via Git, and the Git review
of this PR *is* the provenance check.

## Pin

| Field | Value |
| --- | --- |
| Upstream repo | <https://github.com/rancher/local-path-provisioner> |
| Pinned tag | `v0.0.36` |
| Pinned commit | `5d4bfc84b32cd9c5f56ed3aba921b1a3924ea2f0` |
| Upstream chart path | `deploy/chart/local-path-provisioner/` |
| Chart `version` | `0.0.36` |
| Chart `appVersion` | `v0.0.36` |
| Vendored on | 2026-05-22 |
| Vendored by | Dubs — PR-K4 |

**Why this version.** `v0.0.36` is the latest stable release. It carries
the fix for the HelperPod template-injection vulnerability — added
validation of security-sensitive fields in the helper-pod spec — so it
is the minimum acceptable version to vendor.

## Image digests

The chart's images are digest-pinned in [`values.yaml`](values.yaml)
(the digest is carried in the `tag` field as `<tag>@sha256:…`). Digests
captured at vendoring time:

| Image | Tag | Digest |
| --- | --- | --- |
| `docker.io/rancher/local-path-provisioner` | `v0.0.36` | `sha256:1eba82e9c386038b4af6d69cca7519fac738c28c42735ed48ce70c882ad0d80f` |
| `docker.io/library/busybox` (helper pod) | `1.37.0` | `sha256:1487d0af5f52b4ba31c7e465126ee2123fe3f2305d638e7827681e7cf6c83d5e` |

The upstream chart defaults the helper image to `busybox:latest` — a
moving tag; `values.yaml` overrides it to the exact version + digest
above.

## Re-vendoring procedure (run on every version bump)

Run from the repo root. Bump `NEW_TAG` and update this file's **Pin**
table + image digests in the same commit.

```sh
NEW_TAG=v0.0.36                               # ← bump deliberately
DEST=deploy/gitops/addons/local-path-provisioner/charts/local-path-provisioner

TMP=$(mktemp -d)
git clone --depth=1 --branch "$NEW_TAG" \
  https://github.com/rancher/local-path-provisioner.git "$TMP"

# Record the exact commit the tag resolves to — paste it into the Pin table.
git -C "$TMP" rev-parse HEAD

# Replace the vendored chart wholesale.
git rm -r --quiet "$DEST"
cp -R "$TMP/deploy/chart/local-path-provisioner" "$DEST"
git add "$DEST"

# Confirm what changed is exactly upstream, nothing else.
diff -rq "$TMP/deploy/chart/local-path-provisioner" "$DEST"   # → no output
rm -rf "$TMP"

# Refresh the image digests:
docker buildx imagetools inspect docker.io/rancher/local-path-provisioner:"$NEW_TAG"
```

## Verifying this pin (reviewers)

```sh
TMP=$(mktemp -d)
git clone --depth=1 --branch v0.0.36 \
  https://github.com/rancher/local-path-provisioner.git "$TMP"
test "$(git -C "$TMP" rev-parse HEAD)" = 5d4bfc84b32cd9c5f56ed3aba921b1a3924ea2f0
diff -rq "$TMP/deploy/chart/local-path-provisioner" \
  deploy/gitops/addons/local-path-provisioner/charts/local-path-provisioner
# both commands silent + zero-exit ⇒ the vendored chart is upstream v0.0.36, unmodified
rm -rf "$TMP"
```
