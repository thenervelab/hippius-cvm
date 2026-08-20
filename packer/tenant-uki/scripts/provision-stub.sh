#!/usr/bin/env bash
# `packer/tenant-uki/scripts/provision-stub.sh` — PR-F1 placeholder.
#
# build.pkr.hcl currently inlines a one-liner `shell-local`
# provisioner so the build block is non-empty without needing this
# script on the build host. This file exists to document the slot
# PR-F2 will fill: the real provisioner will be a `shell` (in-guest)
# step driven by a preseed-installed apt system, NOT `shell-local`,
# NOT this stub.
#
# Keep the script tracked in git as a reminder; do NOT make it
# executable until PR-F2 actually wires it in.

set -euo pipefail

echo "tenant-uki provision-stub: PR-F2 will replace this with the real UKI assembly chain."
exit 0
