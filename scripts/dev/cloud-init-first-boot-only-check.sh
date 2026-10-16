#!/usr/bin/env bash
#
# H5b (customer-held keys): prove with the distro's REAL cloud-init that
# a later boot with the stable instance-id and an EMPTY user-data runs
# nothing and keeps the first boot's user, authorized_keys and ssh host
# key — and that a non-empty user-data under the same instance-id would
# still run its bootcmd / boothooks every boot (why the golden initramfs
# must hand cloud-init an empty one).
#
# Runs the checks in a throwaway container (cloud-init writes users,
# ssh keys and /etc — never on the host). Needs docker.
#
#   scripts/dev/cloud-init-first-boot-only-check.sh [IMAGE ...]
#
# Default image: ubuntu:24.04 (the Ubuntu golden base), from mirror.gcr.io pinned by digest.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
GUEST="${HERE}/cloud-init-first-boot-only-guest.sh"
[ -r "${GUEST}" ] || { echo "cloud-init-first-boot-only-check: ${GUEST} missing" >&2; exit 1; }
command -v docker >/dev/null 2>&1 || { echo "cloud-init-first-boot-only-check: docker is required" >&2; exit 1; }

[ "$#" -gt 0 ] || set -- mirror.gcr.io/library/ubuntu:24.04@sha256:534baea6a22c03a63003dbc8dbe78fe34bc0d7e595d9a9dc9834884ff530eb55
for image in "$@"; do
    echo "== ${image}"
    docker run --rm -v "${GUEST}:/h5b-guest.sh:ro" "${image}" bash /h5b-guest.sh
done
